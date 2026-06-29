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
 * Resolves the Ed25519 root key that signs Biscuits, according to {@code BISCUIT_KEY_STRATEGY}:
 *
 * <ul>
 *   <li>{@code realm}: the realm's active EdDSA/Ed25519 signing key (via the Keycloak
 *       KeyManager), with a cross-check of the derived public key;</li>
 *   <li>{@code generated} (default): dedicated key pair persisted as a realm attribute
 *       ({@value #REALM_ATTRIBUTE}), hex seed in plaintext or AES-GCM encrypted if
 *       {@code BISCUIT_KEY_ENCRYPTION_KEY} is set; it is generated on first use only when
 *       {@code BISCUIT_ALLOW_KEY_BOOTSTRAP} is enabled;</li>
 *   <li>{@code auto}: alias of {@code generated} (never switches to the realm's JWT signing key).</li>
 * </ul>
 *
 * First-use generation is locked per realm on this node; in a multi-node cluster a race
 * remains possible on the very first exchange (documented in the README).
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
     * Resolved root key and its identifier ({@code keyId}). The {@code keyId} is issued as an
     * informational {@code key_id(...)} fact in every Biscuit and exposed as {@code kid} by
     * {@code /public-key}, for audit and rotation bookkeeping. Authorizers select the root key through
     * the envelope's {@code root_key_id} ({@link #rootKeyId()}), not through this fact.
     *
     * <ul>
     *   <li>{@code realm} strategy: {@code keyId} = kid of the realm's EdDSA key;</li>
     *   <li>{@code generated} strategy: {@code keyId} = public key prefix (first 16 hex characters) —
     *       stable for a given key, changes on every rotation (= new epoch).</li>
     * </ul>
     */
    record RootKey(KeyPair keyPair, String keyId) {
        /** Envelope {@code root_key_id} of this key; see {@link BiscuitMinter#rootKeyId}. */
        int rootKeyId() {
            return BiscuitMinter.rootKeyId(keyPair.public_key());
        }
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
     * @param allowGenerate if {@code false}, does not generate a missing key (safe {@code GET} path):
     *                      a key not yet provisioned throws {@link KeyResolutionException}.
     */
    static RootKey rootKey(KeycloakSession session, RealmModel realm, BiscuitConfig config, boolean allowGenerate) {
        return switch (config.keyStrategy()) {
            case REALM -> fromRealmKey(session, realm, config).orElseThrow(() -> new KeyResolutionException(
                    "BISCUIT_KEY_STRATEGY=realm but realm '" + realm.getName() + "' has no usable active "
                            + "EdDSA/Ed25519 signing key"
                            + (config.realmKeyKid() != null ? " with kid '" + config.realmKeyKid() + "'" : "")));
            case GENERATED -> generatedKey(realm, config, allowGenerate);
            // alias of GENERATED: stable dedicated root key, no opportunistic switch to the JWT signing key
            case AUTO -> generatedKey(realm, config, allowGenerate);
        };
    }

    private static Optional<RootKey> fromRealmKey(KeycloakSession session, RealmModel realm, BiscuitConfig config) {
        String pinnedKid = config.realmKeyKid();
        if (pinnedKid == null) throw new KeyResolutionException("realm strategy requires a dedicated BISCUIT_REALM_KEY_KID");
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
            throw new KeyResolutionException("failed to inspect pinned realm key", e);
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
            // The realm kid identifies the key: it serves as the epoch identifier for revocation.
            String keyId = (wrapper.getKid() != null && !wrapper.getKid().isBlank())
                    ? wrapper.getKid() : publicKeyPrefix(keyPair);
            return new RootKey(keyPair, keyId);
        } catch (SeedExtractor.SeedExtractionException e) {
            LOG.warnf("Realm key %s: %s, skipping it", wrapper.getKid(), e.getMessage());
            return null;
        }
    }

    /**
     * Public key prefix used as {@code key_id}: first 16 hex characters of the raw public key (not a
     * hash). Stable for a given key, changes on rotation.
     */
    private static String publicKeyPrefix(KeyPair keyPair) {
        String hex = keyPair.public_key().toHex();
        return hex.length() >= 16 ? hex.substring(0, 16) : hex;
    }

    private static RootKey generatedKey(RealmModel realm, BiscuitConfig config, boolean allowGenerate) {
        String stored = realm.getAttribute(REALM_ATTRIBUTE);
        if (stored != null) {
            KeyPair keyPair = readAndMigrate(stored, realm, config, allowGenerate);
            return new RootKey(keyPair, publicKeyPrefix(keyPair));
        }
        if (!allowGenerate) {
            throw new KeyResolutionException("no Biscuit root key has been provisioned yet for realm '"
                    + realm.getName() + "'; provision it, or (with BISCUIT_ALLOW_KEY_BOOTSTRAP=true) "
                    + "trigger an exchange (POST .../biscuit/token) first");
        }
        if (!config.bootstrap()) throw new KeyResolutionException("provision a dedicated root key before serving; development bootstrap requires BISCUIT_ALLOW_KEY_BOOTSTRAP=true on a single node");
        synchronized (GENERATION_LOCKS.computeIfAbsent(realm.getId(), id -> new Object())) {
            stored = realm.getAttribute(REALM_ATTRIBUTE);
            if (stored != null) {
                KeyPair keyPair = readAndMigrate(stored, realm, config, allowGenerate);
                return new RootKey(keyPair, publicKeyPrefix(keyPair));
            }
            if (config.encryptionKeyInvalid()) {
                throw new KeyResolutionException(
                        "BISCUIT_KEY_ENCRYPTION_KEY is malformed: refusing to persist a new root key");
            }
            KeyPair keyPair = new KeyPair(new SecureRandom());
            boolean encrypted = config.encryptionKey() != null;
            String value = encrypted
                    ? KeyEncryption.encrypt(keyPair.toBytes(), config.encryptionKey(), realm.getId())
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
            return new RootKey(keyPair, publicKeyPrefix(keyPair));
        }
    }

    private static KeyPair readAndMigrate(String stored, RealmModel realm, BiscuitConfig config, boolean mayWrite) {
        KeyPair key = decodeStored(stored, config, realm.getId());
        if (config.encryptionKey() != null && !stored.startsWith(KeyEncryption.PREFIX)) {
            if (!mayWrite) {
                throw new KeyResolutionException(
                        "stored root key must first be migrated to enc:v2 by an authenticated exchange");
            }
            realm.setAttribute(REALM_ATTRIBUTE, KeyEncryption.encrypt(key.toBytes(), config.encryptionKey(), realm.getId()));
        }
        return key;
    }

    static KeyPair decodeStored(String stored, BiscuitConfig config) { return decodeStored(stored, config, "test"); }
    private static KeyPair decodeStored(String stored, BiscuitConfig config, String context) {
        if (stored.startsWith(KeyEncryption.PREFIX) || stored.startsWith(KeyEncryption.LEGACY_PREFIX)) {
            if (config.encryptionKey() == null) {
                throw new KeyResolutionException(
                        "stored root key is encrypted but BISCUIT_KEY_ENCRYPTION_KEY is unset");
            }
            try {
                return new KeyPair(KeyEncryption.decrypt(stored, config.encryptionKey(), context));
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
