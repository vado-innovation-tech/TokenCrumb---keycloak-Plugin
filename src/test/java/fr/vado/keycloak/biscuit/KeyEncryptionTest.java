package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KeyEncryptionTest {

    @Test
    void roundTrip() {
        byte[] kek = new byte[32];
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(kek);
        new SecureRandom().nextBytes(seed);

        String stored = KeyEncryption.encrypt(seed, kek);
        assertTrue(stored.startsWith(KeyEncryption.PREFIX));
        assertArrayEquals(seed, KeyEncryption.decrypt(stored, kek));
    }

    @Test
    void wrongKeyFailsCleanly() {
        byte[] kek = new byte[32];
        byte[] wrong = new byte[32];
        new SecureRandom().nextBytes(kek);
        new SecureRandom().nextBytes(wrong);

        String stored = KeyEncryption.encrypt(new byte[32], kek);
        assertThrows(KeyEncryption.DecryptionException.class, () -> KeyEncryption.decrypt(stored, wrong));
    }
}
