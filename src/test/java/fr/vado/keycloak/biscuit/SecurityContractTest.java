package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.token.Biscuit;
import java.util.*;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SecurityContractTest {
    @Test void malformedGovernedFactsCannotDisappear() {
        for (String bad : List.of("null", "[{}]", "[{\"name\":\"required_profile\",\"values\":[\"natvie\"]}]",
                "[{\"name\":\"budget_cap\",\"values\":[\"10\"]}]", "[{\"name\":\"budget_cap\",\"values\":[-1]}]",
                "[{\"name\":\"audience\",\"values\":[null]}]", "[{\"name\":\"audience\",\"values\":[\"a\",\"b\"]}]",
                "[{\"name\":\"audience\",\"name\":\"tenant\",\"values\":[\"a\"]}]"))
            assertThrows(IllegalArgumentException.class, () -> BiscuitConfig.parseExtraFacts(bad), bad);
        assertThrows(IllegalArgumentException.class, () -> BiscuitConfig.from(Map.of("BISCUIT_ENABLED", "treu")));
    }
    @Test void bodyDuplicatesAndNullCannotUnbindAnAgent() {
        for (String bad : List.of("{\"agent_pubkey\":null}", "{\"agent_pubkey\":null,\"agent_pubkey\":\"x\"}", "{agent_pubkey:'x'}"))
            assertThrows(BiscuitResource.InvalidRequestException.class, () -> BiscuitResource.factsFor(bad, List.of()));
    }
    @Test void rolesProduceOnlyExplicitMatchingRights() {
        var cfg = BiscuitConfig.from(Map.of("BISCUIT_ROLE_RIGHTS", "[{\"role\":\"reader\",\"tool\":\"read_file\",\"operation\":\"read\"},{\"role\":\"writer\",\"client\":\"app\",\"tool\":\"write_file\",\"operation\":\"write\"}]"));
        AccessToken token = new AccessToken();
        var staticGrant = new BiscuitMinter.FactSpec("right", List.of("delete_all", "write"));
        assertTrue(cfg.authorizedFacts(token, List.of(staticGrant)).stream().noneMatch(f -> f.name().equals("right")));
        token.setRealmAccess(new AccessToken.Access().addRole("reader").addRole("writer"));
        var rights = cfg.authorizedFacts(token, List.of(staticGrant)).stream().filter(f -> f.name().equals("right")).toList();
        assertEquals(List.of(new BiscuitMinter.FactSpec("right", List.of("read_file", "read"))), rights);
        token.addAccess("app").addRole("writer");
        assertEquals(2, cfg.authorizedFacts(token, List.of()).stream().filter(f -> f.name().equals("right")).count());
        var staticCfg = BiscuitConfig.from(Map.of("BISCUIT_RIGHTS_MODE", "static"));
        assertTrue(staticCfg.authorizedFacts(token, List.of(staticGrant)).contains(staticGrant));
    }
    @Test void encryptedSeedIsBoundToItsRealmAndMalformedInputsFailCleanly() {
        byte[] kek = new byte[32], seed = new byte[32];
        var encrypted = KeyEncryption.encrypt(seed, kek, "realm-a");
        assertArrayEquals(seed, KeyEncryption.decrypt(encrypted, kek, "realm-a"));
        assertThrows(KeyEncryption.DecryptionException.class, () -> KeyEncryption.decrypt(encrypted, kek, "realm-b"));
        for (String bad : List.of("", "enc:v2:", "enc:v2:AA==", "bogus"))
            assertThrows(KeyEncryption.DecryptionException.class, () -> KeyEncryption.decrypt(bad, kek));
    }
    @Test void defaultStartupCannotRaceToCreateIndependentRootKeys() {
        var realm = mock(org.keycloak.models.RealmModel.class);
        when(realm.getId()).thenReturn("r");
        assertThrows(BiscuitKeyManager.KeyResolutionException.class, () -> BiscuitKeyManager.rootKey(mock(org.keycloak.models.KeycloakSession.class), realm, BiscuitConfig.from(Map.of())));
        verify(realm, never()).setAttribute(anyString(), anyString());
    }
    @Test void plaintextRootMigratesWithoutChangingThePublicKey() {
        var realm = mock(org.keycloak.models.RealmModel.class);
        var root = new KeyPair(new java.security.SecureRandom());
        when(realm.getId()).thenReturn("r");
        when(realm.getAttribute(BiscuitKeyManager.REALM_ATTRIBUTE)).thenReturn(root.toHex());
        var cfg = BiscuitConfig.from(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", "00".repeat(32)));
        var loaded = BiscuitKeyManager.rootKey(mock(org.keycloak.models.KeycloakSession.class), realm, cfg);
        assertEquals(root.public_key().toHex(), loaded.keyPair().public_key().toHex());
        var value = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(realm).setAttribute(eq(BiscuitKeyManager.REALM_ATTRIBUTE), value.capture());
        assertArrayEquals(root.toBytes(), KeyEncryption.decrypt(value.getValue(), new byte[32], "r"));
    }
    @Test void auditUserValuesCannotCreateAdditionalLogLines() {
        var audit = new BiscuitMinter.Audit("id", "key", "a\nevent=forged", "iss", "aud", "native", 1);
        String json = BiscuitAudit.issuedJson("rest", "r", audit);
        assertFalse(json.contains("\n"));
        assertEquals(audit.subject(), StrictJson.parse(json).getAsJsonObject().get("sub").getAsString());
    }
    @Test void excessiveRolesAreRefusedBeforeMinting() {
        var token = new AccessToken(); token.setSubject("u");
        var roles = new AccessToken.Access();
        for (int i=0;i<129;i++) roles.addRole("r"+i);
        token.setRealmAccess(roles);
        assertThrows(IllegalArgumentException.class, () -> BiscuitMinter.mint(token, new KeyPair(new java.security.SecureRandom()), 300, Instant.now()));
    }
    @Test void realmKeySelectionRequiresAnExplicitPinAndNeverFallsBack() {
        var realm = mock(org.keycloak.models.RealmModel.class);
        var session = mock(org.keycloak.models.KeycloakSession.class, RETURNS_DEEP_STUBS);
        var unpinned = BiscuitConfig.from(Map.of("BISCUIT_KEY_STRATEGY", "realm"));
        assertThrows(BiscuitKeyManager.KeyResolutionException.class, () -> BiscuitKeyManager.rootKey(session, realm, unpinned));
        var pinned = BiscuitConfig.from(Map.of("BISCUIT_KEY_STRATEGY", "realm", "BISCUIT_REALM_KEY_KID", "dedicated"));
        when(session.keys().getKeysStream(realm)).thenThrow(new IllegalStateException("unavailable"));
        assertThrows(BiscuitKeyManager.KeyResolutionException.class, () -> BiscuitKeyManager.rootKey(session, realm, pinned));
        verify(realm, never()).setAttribute(anyString(), anyString());
    }
    @Test void aValidPinnedRealmKeyIsChosenWithoutUsingAnotherActiveKey() throws Exception {
        var realm = mock(org.keycloak.models.RealmModel.class);
        var session = mock(org.keycloak.models.KeycloakSession.class, RETURNS_DEEP_STUBS);
        var jdk = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        var wrapper = new org.keycloak.crypto.KeyWrapper();
        wrapper.setKid("dedicated"); wrapper.setAlgorithm(org.keycloak.crypto.Algorithm.EdDSA);
        wrapper.setCurve(org.keycloak.crypto.Algorithm.Ed25519); wrapper.setUse(org.keycloak.crypto.KeyUse.SIG);
        wrapper.setStatus(org.keycloak.crypto.KeyStatus.ACTIVE); wrapper.setPrivateKey(jdk.getPrivate()); wrapper.setPublicKey(jdk.getPublic());
        when(session.keys().getKeysStream(realm)).thenReturn(java.util.stream.Stream.of(wrapper));
        var cfg = BiscuitConfig.from(Map.of("BISCUIT_KEY_STRATEGY","realm","BISCUIT_REALM_KEY_KID","dedicated"));
        var resolved = BiscuitKeyManager.rootKey(session,realm,cfg);
        assertEquals("dedicated",resolved.keyId());
        assertTrue(SeedExtractor.publicKeyMatches(resolved.keyPair(),jdk.getPublic()));
        verify(realm,never()).setAttribute(anyString(),anyString());
    }
    @Test void mintedContractUsesDatesAndIntegerBudgetAndExportsInteropFixture() throws Exception {
        var root = new KeyPair(new java.security.SecureRandom());
        var token = new AccessToken(); token.setSubject("interop-user"); token.issuer("test-issuer");
        var now = Instant.parse("2030-01-01T00:00:00Z"); token.exp(now.getEpochSecond()+600);
        var facts = BiscuitConfig.parseExtraFacts("[{\"name\":\"budget_cap\",\"values\":[2]},{\"name\":\"audience\",\"values\":[\"biscuitmcp://interop\"]},{\"name\":\"right\",\"values\":[\"read_file\",\"read\"]}]");
        var result = BiscuitMinter.mint(token, root, 300, now, facts);
        var printed = Biscuit.from_b64url(result.biscuitB64(), root.public_key()).print();
        assertTrue(printed.contains("budget_cap(2)"), printed);
        assertTrue(printed.contains("expires_at(2030-01-01T00:05:00Z)"), printed);
        var fixture = Map.of("token",result.biscuitB64(),"authority_pub","ed25519/"+root.public_key().toHex(),"now",now.toString());
        java.nio.file.Files.writeString(java.nio.file.Path.of("target/python-interop.json"), new com.google.gson.Gson().toJson(fixture));
    }
}
