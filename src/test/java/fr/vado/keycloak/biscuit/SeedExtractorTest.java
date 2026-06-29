package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Valide la voie « clé realm » avec de vraies clés Ed25519 JDK : extraction de seed
 * + vérification croisée de la clé publique dérivée par biscuit-java.
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
