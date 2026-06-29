// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;

import java.security.Key;
import java.security.interfaces.EdECPrivateKey;
import java.util.Arrays;

/**
 * Extracts the raw seed (32 bytes) from a {@code java.security} Ed25519 private key.
 * Used when reusing a Keycloak realm EdDSA key as the Biscuit root key.
 */
final class SeedExtractor {

    private SeedExtractor() {
    }

    /** Length (bytes) of an Ed25519 seed, as well as of an Ed25519 public key. */
    private static final int ED25519_KEY_LENGTH = 32;
    /** DER tags for the PKCS#8 v1 fallback: OCTET STRING (0x04) of length 32 (0x20). */
    private static final byte ASN1_OCTET_STRING = 0x04;
    private static final byte ASN1_OCTET_STRING_LEN_32 = 0x20;
    /** Position, from the end, of the inner octet-string tag ({@code 04 20} + 32 seed bytes). */
    private static final int PKCS8_SEED_TAIL = ED25519_KEY_LENGTH + 2;

    static final class SeedExtractionException extends RuntimeException {
        SeedExtractionException(String message) {
            super(message);
        }
    }

    /**
     * Tries the JDK {@link EdECPrivateKey} interface first, then the PKCS#8 encoding:
     * for minimal Ed25519, the seed is the inner OCTET STRING ({@code 04 20} + 32 bytes)
     * at the end of the structure. The byte guard prevents reading garbage from extended
     * encodings (attributes, embedded public key); {@link #publicKeyMatches} remains the
     * mandatory final check by the caller.
     *
     * <p><b>PKCS#8 fallback:</b> only the minimal <b>v1</b> format ({@code PrivateKeyInfo} without a
     * public key) is handled here; v2 (RFC 5958, public key included) is not parsed. In practice
     * Keycloak exposes an {@link EdECPrivateKey} (primary branch), so this fallback is rarely
     * taken, and {@link #publicKeyMatches} rejects any incorrect seed anyway.</p>
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

    /** DER prefix (12 bytes) of the X.509 SubjectPublicKeyInfo of an Ed25519 key, followed by the 32 key bytes. */
    private static final byte[] ED25519_SPKI_PREFIX = {
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
    };

    /**
     * Checks that the public key derived from the seed matches the realm public key.
     * The X.509 SPKI of an Ed25519 key is exactly 44 bytes: a constant 12-byte DER prefix
     * (algorithm OID {@code 1.3.101.112}) followed by the 32 key bytes. Length and prefix are validated
     * before slicing, so the comparison is safe regardless of the encoding supplied by the caller.
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
