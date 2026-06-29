package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Couvre decodeStored (crypto) + la résolution de clé générée/AUTO avec un RealmModel mocké. */
class BiscuitKeyManagerTest {

    private static final String HEX32 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    private static BiscuitConfig config(Map<String, String> env) {
        return BiscuitConfig.from(env);
    }

    /** RealmModel mocké dont getAttribute/setAttribute sont adossés à une Map. */
    private static RealmModel realmBackedBy(Map<String, String> store) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("realm-id");
        when(realm.getName()).thenReturn("realm-name");
        when(realm.getAttribute(anyString())).thenAnswer(i -> store.get(i.<String>getArgument(0)));
        doAnswer(i -> {
            store.put(i.getArgument(0), i.getArgument(1));
            return null;
        }).when(realm).setAttribute(anyString(), anyString());
        return realm;
    }

    // ---- decodeStored ----

    @Test
    void decodesPlaintextHexSeed() {
        KeyPair kp = new KeyPair(new SecureRandom());
        KeyPair decoded = BiscuitKeyManager.decodeStored(kp.toHex(), config(Map.of()));
        assertEquals(kp.public_key().toHex(), decoded.public_key().toHex());
    }

    @Test
    void decodesEncryptedSeedRoundTrip() {
        BiscuitConfig cfg = config(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", HEX32));
        KeyPair kp = new KeyPair(new SecureRandom());
        String stored = KeyEncryption.encrypt(kp.toBytes(), cfg.encryptionKey());
        KeyPair decoded = BiscuitKeyManager.decodeStored(stored, cfg);
        assertEquals(kp.public_key().toHex(), decoded.public_key().toHex());
    }

    @Test
    void encryptedSeedWithoutKekFails() {
        BiscuitConfig withKek = config(Map.of("BISCUIT_KEY_ENCRYPTION_KEY", HEX32));
        String stored = KeyEncryption.encrypt(new KeyPair(new SecureRandom()).toBytes(), withKek.encryptionKey());
        assertThrows(BiscuitKeyManager.KeyResolutionException.class,
                () -> BiscuitKeyManager.decodeStored(stored, config(Map.of())));
    }

    @Test
    void malformedStoredSeedFails() {
        assertThrows(BiscuitKeyManager.KeyResolutionException.class,
                () -> BiscuitKeyManager.decodeStored("not-a-valid-seed", config(Map.of())));
    }

    // ---- generated / auto ----

    @Test
    void generatedStrategyPersistsThenReloadsSameKey() {
        Map<String, String> store = new HashMap<>();
        RealmModel realm = realmBackedBy(store);
        KeycloakSession session = mock(KeycloakSession.class);
        BiscuitConfig cfg = config(Map.of("BISCUIT_KEY_STRATEGY", "generated"));

        KeyPair first = BiscuitKeyManager.rootKeyPair(session, realm, cfg);
        assertTrue(store.containsKey(BiscuitKeyManager.REALM_ATTRIBUTE));
        KeyPair second = BiscuitKeyManager.rootKeyPair(session, realm, cfg);
        assertEquals(first.public_key().toHex(), second.public_key().toHex());
    }

    @Test
    void getPathDoesNotGenerateWhenAbsent() {
        Map<String, String> store = new HashMap<>();
        RealmModel realm = realmBackedBy(store);
        KeycloakSession session = mock(KeycloakSession.class);
        BiscuitConfig cfg = config(Map.of("BISCUIT_KEY_STRATEGY", "generated"));

        assertThrows(BiscuitKeyManager.KeyResolutionException.class,
                () -> BiscuitKeyManager.rootKeyPair(session, realm, cfg, false));
        assertFalse(store.containsKey(BiscuitKeyManager.REALM_ATTRIBUTE));
    }

    @Test
    void malformedKekRefusesToGenerate() {
        Map<String, String> store = new HashMap<>();
        RealmModel realm = realmBackedBy(store);
        KeycloakSession session = mock(KeycloakSession.class);
        BiscuitConfig cfg = config(Map.of(
                "BISCUIT_KEY_STRATEGY", "generated",
                "BISCUIT_KEY_ENCRYPTION_KEY", "too-short"));

        assertThrows(BiscuitKeyManager.KeyResolutionException.class,
                () -> BiscuitKeyManager.rootKeyPair(session, realm, cfg));
        assertFalse(store.containsKey(BiscuitKeyManager.REALM_ATTRIBUTE));
    }

    @Test
    void rootKeyExposesStableNonBlankKeyIdForGenerated() {
        Map<String, String> store = new HashMap<>();
        RealmModel realm = realmBackedBy(store);
        KeycloakSession session = mock(KeycloakSession.class);
        BiscuitConfig cfg = config(Map.of("BISCUIT_KEY_STRATEGY", "generated"));

        BiscuitKeyManager.RootKey rk = BiscuitKeyManager.rootKey(session, realm, cfg);
        assertNotNull(rk.keyId());
        assertFalse(rk.keyId().isBlank());
        // empreinte stable : la même clé rechargée donne le même keyId (= même époque)
        assertEquals(rk.keyId(), BiscuitKeyManager.rootKey(session, realm, cfg).keyId());
    }

    @Test
    void autoFallsBackToGeneratedWhenNoRealmKey() {
        Map<String, String> store = new HashMap<>();
        RealmModel realm = realmBackedBy(store);
        KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        when(session.keys().getKeysStream(realm)).thenReturn(Stream.empty());
        BiscuitConfig cfg = config(Map.of()); // AUTO par défaut

        KeyPair kp = BiscuitKeyManager.rootKeyPair(session, realm, cfg);
        assertNotNull(kp);
        assertTrue(store.containsKey(BiscuitKeyManager.REALM_ATTRIBUTE));
    }
}
