// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Chiffrement optionnel de la seed persistée : AES-256-GCM, format {@code enc:v2:<base64(iv||ciphertext)>}, AAD liée au realm et à l’usage.
 * La clé (KEK) vient de {@code BISCUIT_KEY_ENCRYPTION_KEY}.
 */
final class KeyEncryption {

    static final String PREFIX = "enc:v2:";
    static final String LEGACY_PREFIX = "enc:v1:";

    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    /** SecureRandom partagé (thread-safe) pour la génération d'IV. */
    private static final SecureRandom RNG = new SecureRandom();

    private KeyEncryption() {
    }

    static final class DecryptionException extends RuntimeException {
        DecryptionException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    static String encrypt(byte[] plaintext, byte[] kek) { return encrypt(plaintext, kek, "test"); }
    static String encrypt(byte[] plaintext, byte[] kek, String context) {
        try {
            byte[] iv = new byte[IV_LENGTH];
            RNG.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(("keycloak-biscuit/root/v2/" + context).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] out = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ciphertext, 0, out, iv.length, ciphertext.length);
            return PREFIX + Base64.getEncoder().encodeToString(out);
        } catch (GeneralSecurityException e) {
            // AES-GCM est garanti par la plateforme Java ; une erreur ici est un bug, pas un cas métier
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    static byte[] decrypt(String stored, byte[] kek) { return decrypt(stored, kek, "test"); }
    static byte[] decrypt(String stored, byte[] kek, String context) {
        try {
            boolean legacy = stored.startsWith(LEGACY_PREFIX);
            if (!legacy && !stored.startsWith(PREFIX)) throw new IllegalArgumentException("unknown encrypted key version");
            byte[] raw = Base64.getDecoder().decode(stored.substring(PREFIX.length()));
            if (raw.length != IV_LENGTH + 32 + TAG_BITS / 8) throw new IllegalArgumentException("invalid encrypted seed size");
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"),
                    new GCMParameterSpec(TAG_BITS, raw, 0, IV_LENGTH));
            if (!legacy) cipher.updateAAD(("keycloak-biscuit/root/v2/" + context).getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return cipher.doFinal(raw, IV_LENGTH, raw.length - IV_LENGTH);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new DecryptionException(
                    "cannot decrypt stored root key (wrong BISCUIT_KEY_ENCRYPTION_KEY?)", e);
        }
    }
}
