// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Validates the "realm key" path with real JDK Ed25519 keys: seed extraction
 * + cross-check of the public key derived by biscuit-java.
 */
class SeedExtractorTest {

    @Test
    void extractsSeedFromJdkEd25519KeyAndDerivedPublicKeyMatches() throws Exception {
        java.security.KeyPair jdk = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        byte[] seed = SeedExtractor.extractSeed(jdk.getPrivate());
        assertEquals(32, seed.length);

        org.biscuitsec.biscuit.crypto.KeyPair derived = new org.biscuitsec.biscuit.crypto.KeyPair(seed);
        assertTrue(SeedExtractor.publicKeyMatches(derived, jdk.getPublic()));
    }

    @Test
    void mismatchedPublicKeyIsDetected() throws Exception {
        java.security.KeyPair jdk = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        java.security.KeyPair other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();

        byte[] seed = SeedExtractor.extractSeed(jdk.getPrivate());
        org.biscuitsec.biscuit.crypto.KeyPair derived = new org.biscuitsec.biscuit.crypto.KeyPair(seed);

        assertTrue(!SeedExtractor.publicKeyMatches(derived, other.getPublic()));
    }
}
