// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.jboss.logging.Logger;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Résout la clé racine Ed25519 qui signe les Biscuits, selon {@code BISCUIT_KEY_STRATEGY} :
 *
 * <ul>
 *   <li>{@code realm} : clé de signature EdDSA/Ed25519 active du realm (via le KeyManager
 *       Keycloak), avec vérification croisée de la clé publique dérivée ;</li>
 *   <li>{@code generated} : paire générée au premier usage et persistée comme attribut de
 *       realm ({@value #REALM_ATTRIBUTE}), seed hex en clair ou chiffrée AES-GCM si
 *       {@code BISCUIT_KEY_ENCRYPTION_KEY} est définie ;</li>
 *   <li>{@code auto} (défaut) : realm si exploitable, sinon generated.</li>
 * </ul>
 *
 * La génération au premier usage est verrouillée par realm sur ce nœud ; en cluster
 * multi-nœuds une course reste possible au tout premier échange (documenté dans le README).
 */
final class BiscuitKeyManager {

    static final String REALM_ATTRIBUTE = "biscuit.root.key";

    private static final Logger LOG = Logger.getLogger(BiscuitKeyManager.class);
    private static final ConcurrentHashMap<String, Object> GENERATION_LOCKS = new ConcurrentHashMap<>();

    static final class KeyResolutionException extends RuntimeException {
        KeyResolutionException(String message) {
            super(message);
        }

        KeyResolutionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Clé racine résolue + son identifiant ({@code keyId}). Le {@code keyId} est émis comme fait
     * {@code key_id(...)} dans chaque Biscuit et exposé en {@code kid} par {@code /public-key},
     * pour permettre la rotation et la révocation par époque côté vérificateur.
     *
     * <ul>
     *   <li>stratégie {@code realm} : {@code keyId} = kid de la clé EdDSA du realm ;</li>
     *   <li>stratégie {@code generated} : {@code keyId} = empreinte (16 hex) de la clé publique —
     *       stable pour une clé donnée, change à chaque rotation (= nouvelle époque).</li>
     * </ul>
     */
    record RootKey(KeyPair keyPair, String keyId) {
    }

    private BiscuitKeyManager() {
    }

    static KeyPair rootKeyPair(KeycloakSession session, RealmModel realm, BiscuitConfig config) {
        return rootKey(session, realm, config, true).keyPair();
    }

    static KeyPair rootKeyPair(KeycloakSession session, RealmModel realm, BiscuitConfig config, boolean allowGenerate) {
        return rootKey(session, realm, config, allowGenerate).keyPair();
    }

    static RootKey rootKey(KeycloakSession session, RealmModel realm, BiscuitConfig config) {
        return rootKey(session, realm, config, true);
    }

    /**
     * @param allowGenerate si {@code false}, ne génère pas de clé manquante (chemin {@code GET} safe) :
     *                      une clé non encore provisionnée lève {@link KeyResolutionException}.
     */
    static RootKey rootKey(KeycloakSession session, RealmModel realm, BiscuitConfig config, boolean allowGenerate) {
        return switch (config.keyStrategy()) {
            case REALM -> fromRealmKey(session, realm, config).orElseThrow(() -> new KeyResolutionException(
                    "BISCUIT_KEY_STRATEGY=realm but realm '" + realm.getName() + "' has no usable active "
                            + "EdDSA/Ed25519 signing key"
                            + (config.realmKeyKid() != null ? " with kid '" + config.realmKeyKid() + "'" : "")));
            case GENERATED -> generatedKey(realm, config, allowGenerate);
            case AUTO -> fromRealmKey(session, realm, config).orElseGet(() -> generatedKey(realm, config, allowGenerate));
        };
    }

    private static Optional<RootKey> fromRealmKey(KeycloakSession session, RealmModel realm, BiscuitConfig config) {
        String pinnedKid = config.realmKeyKid();
        try {
            Optional<RootKey> resolved = session.keys().getKeysStream(realm)
                    .filter(k -> k.getStatus() != null && k.getStatus().isActive())
                    .filter(k -> KeyUse.SIG.equals(k.getUse()))
                    .filter(k -> Algorithm.EdDSA.equals(k.getAlgorithm()))
                    .filter(k -> Algorithm.Ed25519.equals(k.getCurve()))
                    .filter(k -> pinnedKid == null || pinnedKid.equals(k.getKid()))
                    .filter(k -> k.getPrivateKey() != null && k.getPublicKey() != null)
                    .map(BiscuitKeyManager::toBiscuitKeyPair)
                    .filter(Objects::nonNull)
                    .findFirst();
            if (resolved.isPresent() && pinnedKid == null) {
                LOG.warn("Using an unpinned active EdDSA realm key as the Biscuit root key. Set "
                        + "BISCUIT_REALM_KEY_KID to a key dedicated to Biscuit so the realm's JWT signing "
                        + "key is never reused for Biscuit signing.");
            }
            return resolved;
        } catch (RuntimeException e) {
            LOG.warn("Failed to inspect realm keys, falling back to generated key strategy", e);
            return Optional.empty();
        }
    }

    private static RootKey toBiscuitKeyPair(KeyWrapper wrapper) {
        try {
            byte[] seed = SeedExtractor.extractSeed(wrapper.getPrivateKey());
            KeyPair keyPair = new KeyPair(seed);
            if (!SeedExtractor.publicKeyMatches(keyPair, wrapper.getPublicKey())) {
                LOG.warnf("Realm key %s: public key derived from extracted seed does not match, skipping it",
                        wrapper.getKid());
                return null;
            }
            // Le kid du realm identifie la clé : il sert d'identifiant d'époque pour la révocation.
            String keyId = (wrapper.getKid() != null && !wrapper.getKid().isBlank())
                    ? wrapper.getKid() : fingerprint(keyPair);
            return new RootKey(keyPair, keyId);
        } catch (SeedExtractor.SeedExtractionException e) {
            LOG.warnf("Realm key %s: %s, skipping it", wrapper.getKid(), e.getMessage());
            return null;
        }
    }

    /** Empreinte stable d'une clé : 16 premiers hex de la clé publique. Change à la rotation. */
    private static String fingerprint(KeyPair keyPair) {
        String hex = keyPair.public_key().toHex();
        return hex.length() >= 16 ? hex.substring(0, 16) : hex;
    }

    private static RootKey generatedKey(RealmModel realm, BiscuitConfig config, boolean allowGenerate) {
        String stored = realm.getAttribute(REALM_ATTRIBUTE);
        if (stored != null) {
            KeyPair keyPair = decodeStored(stored, config);
            return new RootKey(keyPair, fingerprint(keyPair));
        }
        if (!allowGenerate) {
            throw new KeyResolutionException("no Biscuit root key has been provisioned yet for realm '"
                    + realm.getName() + "'; trigger an exchange (POST .../biscuit/token) first");
        }
        synchronized (GENERATION_LOCKS.computeIfAbsent(realm.getId(), id -> new Object())) {
            stored = realm.getAttribute(REALM_ATTRIBUTE);
            if (stored != null) {
                KeyPair keyPair = decodeStored(stored, config);
                return new RootKey(keyPair, fingerprint(keyPair));
            }
            if (config.encryptionKeyInvalid()) {
                throw new KeyResolutionException(
                        "BISCUIT_KEY_ENCRYPTION_KEY is malformed: refusing to persist a new root key");
            }
            KeyPair keyPair = new KeyPair(new SecureRandom());
            boolean encrypted = config.encryptionKey() != null;
            String value = encrypted
                    ? KeyEncryption.encrypt(keyPair.toBytes(), config.encryptionKey())
                    : keyPair.toHex();
            realm.setAttribute(REALM_ATTRIBUTE, value);
            if (encrypted) {
                LOG.infof("Generated new Biscuit root key for realm '%s' (stored AES-GCM encrypted)",
                        realm.getName());
            } else {
                LOG.warnf("Generated new Biscuit root key for realm '%s' and stored its seed IN PLAINTEXT in "
                        + "realm attribute '%s'. Set BISCUIT_KEY_ENCRYPTION_KEY (AES-256) to encrypt it at rest "
                        + "in production.", realm.getName(), REALM_ATTRIBUTE);
            }
            return new RootKey(keyPair, fingerprint(keyPair));
        }
    }

    static KeyPair decodeStored(String stored, BiscuitConfig config) {
        if (stored.startsWith(KeyEncryption.PREFIX)) {
            if (config.encryptionKey() == null) {
                throw new KeyResolutionException(
                        "stored root key is encrypted but BISCUIT_KEY_ENCRYPTION_KEY is unset");
            }
            try {
                return new KeyPair(KeyEncryption.decrypt(stored, config.encryptionKey()));
            } catch (KeyEncryption.DecryptionException e) {
                throw new KeyResolutionException(e.getMessage(), e);
            }
        }
        try {
            return new KeyPair(stored);
        } catch (RuntimeException e) {
            throw new KeyResolutionException("stored root key attribute is malformed", e);
        }
    }
}
