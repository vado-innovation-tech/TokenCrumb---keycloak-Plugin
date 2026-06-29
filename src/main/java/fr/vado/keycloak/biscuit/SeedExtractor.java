// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;

import java.security.Key;
import java.security.interfaces.EdECPrivateKey;
import java.util.Arrays;

/**
 * Extraction de la seed brute (32 octets) d'une clé privée Ed25519 {@code java.security}.
 * Utilisé pour réutiliser une clé EdDSA du realm Keycloak comme clé racine Biscuit.
 */
final class SeedExtractor {

    private SeedExtractor() {
    }

    /** Longueur (octets) d'une seed comme d'une clé publique Ed25519. */
    private static final int ED25519_KEY_LENGTH = 32;
    /** Tags DER du repli PKCS#8 v1 : OCTET STRING (0x04) de longueur 32 (0x20). */
    private static final byte ASN1_OCTET_STRING = 0x04;
    private static final byte ASN1_OCTET_STRING_LEN_32 = 0x20;
    /** Position, depuis la fin, du tag de l'octet-string interne ({@code 04 20} + 32 octets de seed). */
    private static final int PKCS8_SEED_TAIL = ED25519_KEY_LENGTH + 2;

    static final class SeedExtractionException extends RuntimeException {
        SeedExtractionException(String message) {
            super(message);
        }
    }

    /**
     * Essaie d'abord l'interface JDK {@link EdECPrivateKey}, puis l'encodage PKCS#8 :
     * pour Ed25519 minimal, la seed est l'OCTET STRING interne ({@code 04 20} + 32 octets)
     * en fin de structure. La garde d'octets évite de lire n'importe quoi sur des encodages
     * étendus (attributs, clé publique incluse) ; {@link #publicKeyMatches} reste la
     * vérification finale obligatoire côté appelant.
     *
     * <p><b>Repli PKCS#8 :</b> seul le format <b>v1</b> minimal ({@code PrivateKeyInfo} sans clé
     * publique) est géré ici ; le v2 (RFC 5958, clé publique incluse) n'est pas parsé. En pratique
     * Keycloak expose un {@link EdECPrivateKey} (branche primaire), donc ce repli est rarement
     * emprunté, et {@link #publicKeyMatches} rejette de toute façon toute seed incorrecte.</p>
     */
    static byte[] extractSeed(Key privateKey) {
        if (privateKey instanceof EdECPrivateKey edec) {
            return edec.getBytes().orElseThrow(() ->
                    new SeedExtractionException("EdECPrivateKey does not expose raw bytes"));
        }
        byte[] pkcs8 = privateKey.getEncoded();
        if (pkcs8 != null && pkcs8.length >= PKCS8_SEED_TAIL
                && pkcs8[pkcs8.length - PKCS8_SEED_TAIL] == ASN1_OCTET_STRING
                && pkcs8[pkcs8.length - (PKCS8_SEED_TAIL - 1)] == ASN1_OCTET_STRING_LEN_32) {
            return Arrays.copyOfRange(pkcs8, pkcs8.length - ED25519_KEY_LENGTH, pkcs8.length);
        }
        throw new SeedExtractionException(
                "unsupported Ed25519 private key encoding: " + privateKey.getClass().getName());
    }

    /** Préfixe DER (12 octets) du SubjectPublicKeyInfo X.509 d'une clé Ed25519, suivi des 32 octets de clé. */
    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /**
     * Vérifie que la clé publique dérivée de la seed correspond à la clé publique du realm.
     * Le SPKI X.509 d'une clé Ed25519 fait exactement 44 octets : un préfixe DER constant de 12 octets
     * (algo OID {@code 1.3.101.112}) puis les 32 octets de clé. On valide longueur + préfixe avant le
     * slice, pour que la comparaison soit sûre indépendamment de l'encodage fourni par l'appelant.
     */
    static boolean publicKeyMatches(KeyPair derived, Key realmPublicKey) {
        byte[] spki = realmPublicKey.getEncoded();
        if (spki == null || spki.length != ED25519_SPKI_PREFIX.length + ED25519_KEY_LENGTH) {
            return false;
        }
        for (int i = 0; i < ED25519_SPKI_PREFIX.length; i++) {
            if (spki[i] != ED25519_SPKI_PREFIX[i]) {
                return false;
            }
        }
        byte[] expected = Arrays.copyOfRange(spki, ED25519_SPKI_PREFIX.length, spki.length);
        return Arrays.equals(derived.public_key().toBytes(), expected);
    }
}
