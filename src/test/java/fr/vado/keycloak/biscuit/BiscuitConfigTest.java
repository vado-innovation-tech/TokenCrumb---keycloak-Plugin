package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Couvre tout le parsing de configuration (env + Config.Scope) sans aucun container. */
class BiscuitConfigTest {

    private static final String HEX32 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    private static BiscuitConfig from(Map<String, String> env) {
        return BiscuitConfig.from(env);
    }

    @Test
    void defaultsWhenEnvEmpty() {
        BiscuitConfig c = from(Map.of());
        assertTrue(c.enabled());
        assertEquals(BiscuitConfig.DEFAULT_TTL_SECONDS, c.ttlSeconds());
        assertEquals(BiscuitConfig.KeyStrategy.GENERATED, c.keyStrategy());
        assertNull(c.realmKeyKid());
        assertNull(c.encryptionKey());
        assertFalse(c.encryptionKeyInvalid());
    }

    @Test
    void enabledFalseyAliases() {
        for (String v : new String[]{"false", "FALSE", "0", "no", "off", " Off "}) {
            assertFalse(from(Map.of("BISCUIT_ENABLED", v)).enabled(), v);
        }
        for (String v : new String[]{"true", "1", "yes", "on"}) {
            assertTrue(from(Map.of("BISCUIT_ENABLED", v)).enabled(), v);
        }
    }

    @Test
    void ttlParsingAndBounds() {
        assertEquals(600L, from(Map.of("BISCUIT_TOKEN_TTL", "600")).ttlSeconds());
        for (String bad : List.of("abc", "0", "-5", "", String.valueOf(Long.MAX_VALUE)))
            assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_TOKEN_TTL", bad)));
    }

    @Test
    void strategyParsing() {
        assertEquals(BiscuitConfig.KeyStrategy.REALM, from(Map.of("BISCUIT_KEY_STRATEGY", "realm")).keyStrategy());
        assertEquals(BiscuitConfig.KeyStrategy.GENERATED, from(Map.of("BISCUIT_KEY_STRATEGY", "GENERATED")).keyStrategy());
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_KEY_STRATEGY", "bogus")));
    }

    @Test
    void realmKeyKidTrimmedOrNull() {
        assertNull(from(Map.of("BISCUIT_REALM_KEY_KID", "   ")).realmKeyKid());
        assertEquals("kid-123", from(Map.of("BISCUIT_REALM_KEY_KID", "  kid-123 ")).realmKeyKid());
    }

    @Test
    void kekHex64Accepted() {
        BiscuitConfig c = from(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", HEX32));
        assertNotNull(c.encryptionKey());
        assertEquals(32, c.encryptionKey().length);
        assertFalse(c.encryptionKeyInvalid());
    }

    @Test
    void kekBase64Of32BytesAccepted() {
        String b64 = Base64.getEncoder().encodeToString(new byte[32]);
        BiscuitConfig c = from(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", b64));
        assertNotNull(c.encryptionKey());
        assertEquals(32, c.encryptionKey().length);
        assertFalse(c.encryptionKeyInvalid());
    }

    @Test
    void malformedKekFlagsInvalidAndNullKey() {
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", "too-short")));
    }

    @Test
    void encryptionKeyGetterIsDefensiveCopy() {
        BiscuitConfig c = from(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", HEX32));
        byte[] first = c.encryptionKey();
        first[0] ^= 0xFF; // muter la copie ne doit pas affecter l'état interne
        assertNotEquals(first[0], c.encryptionKey()[0]);
    }

    @Test
    void extraFactsDefaultEmpty() {
        assertTrue(from(Map.of()).extraFacts().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_EXTRA_FACTS", "   ")));
    }

    @Test
    void extraFactsParsedFromJson() {
        BiscuitConfig c = from(Map.of("BISCUIT_EXTRA_FACTS",
                "[{\"name\":\"audience\",\"values\":[\"biscuitmcp://exado\"]},"
                        + "{\"name\":\"required_profile\",\"values\":[\"native\"]}]"));
        assertEquals(2, c.extraFacts().size());
        assertEquals("audience", c.extraFacts().get(0).name());
        assertEquals(List.of("biscuitmcp://exado"), c.extraFacts().get(0).values());
        assertEquals("required_profile", c.extraFacts().get(1).name());
    }

    @Test
    void extraFactsInvalidJsonYieldsEmpty() {
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_EXTRA_FACTS", "not json")));
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_EXTRA_FACTS", "{}")));
    }

    @Test
    void extraFactsSkipInvalidAndReservedNames() {
        for (String name : List.of("1bad", "user", "operation", "time", "key_id"))
            assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_EXTRA_FACTS",
                    "[{\"name\":\"" + name + "\",\"values\":[\"x\"]}]")));
    }

    @Test
    void extraFactsAllowGovernedButRejectCore() {
        assertThrows(IllegalArgumentException.class, () -> from(Map.of("BISCUIT_EXTRA_FACTS",
                "[{\"name\":\"key_id\",\"values\":[\"forged\"]}]")));
    }

    @Test
    void scopeTakesPriorityOverEnvFallback() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.get("enabled")).thenReturn("false");
        when(scope.get("token-ttl")).thenReturn("600");
        when(scope.get("key-strategy")).thenReturn("generated");
        when(scope.get("realm-key-kid")).thenReturn("kid-xyz");
        when(scope.get("key-encryption-key")).thenReturn(null);

        BiscuitConfig c = BiscuitConfig.fromScope(scope);
        assertFalse(c.enabled());
        assertEquals(600L, c.ttlSeconds());
        assertEquals(BiscuitConfig.KeyStrategy.GENERATED, c.keyStrategy());
        assertEquals("kid-xyz", c.realmKeyKid());
    }
}
