package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verrouille la syntaxe datalog et l'API biscuit-java 4.0.1 sans aucun container :
 * si ces tests passent, l'IT ne peut plus échouer sur la construction du Biscuit.
 */
class BiscuitMinterTest {

    // These are logic tests: allow for shared-runner scheduling without changing production limits.
    private static final RunLimits TEST_LIMITS = new RunLimits(1000, 100, Duration.ofSeconds(1));

    private static final KeyPair ROOT = new KeyPair(new SecureRandom());
    private static final Instant NOW = Instant.parse("2026-06-11T10:00:00Z");
    /** Fait time(...) au temps de frappe : vérification déterministe, indépendante de l'horloge réelle. */
    private static final String NOW_TIME_FACT = "time(" + DateTimeFormatter.ISO_INSTANT.format(NOW) + ")";

    private static AccessToken token(String sub, String azp, Long exp) {
        AccessToken t = new AccessToken();
        t.subject(sub);
        t.issuedFor(azp);
        t.exp(exp);
        return t;
    }

    @Test
    void mintsVerifiableBiscuitWithAllFacts() throws Exception {
        AccessToken t = token("user-123", "demo-cli", NOW.getEpochSecond() + 3600);
        t.issuer("https://kc/realms/demo");
        AccessToken.Access realm = new AccessToken.Access();
        realm.roles(Set.of("admin", "user"));
        t.setRealmAccess(realm);
        t.addAccess("demo-cli").roles(Set.of("orders:read"));

        BiscuitMinter.MintResult result = BiscuitMinter.mint(t, ROOT, 300, NOW);

        // round-trip : parsing + vérification de signature avec la clé publique seule
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());
        String printed = parsed.print();
        assertTrue(printed.contains("user(\"user-123\")"), printed);
        assertTrue(printed.contains("client(\"demo-cli\")"), printed);
        assertTrue(printed.contains("issuer(\"https://kc/realms/demo\")"), printed);
        assertTrue(printed.contains("realm_role(\"admin\")"), printed);
        assertTrue(printed.contains("realm_role(\"user\")"), printed);
        assertTrue(printed.contains("client_role(\"demo-cli\", \"orders:read\")"), printed);
        assertTrue(printed.contains("jti(\""), printed);
        assertTrue(printed.contains("check if time($t)"), printed);

        // l'authorizer passe au temps de frappe (déterministe, antérieur à l'expiration)
        parsed.authorizer().add_fact(NOW_TIME_FACT).allow().authorize(TEST_LIMITS);
    }

    @Test
    void expiredTimeFailsAuthorization() throws Exception {
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());

        assertThrows(Error.FailedLogic.class, () ->
                parsed.authorizer().add_fact("time(2999-01-01T00:00:00Z)").allow().authorize(TEST_LIMITS));
    }

    @Test
    void expiryIsCappedByTtlWhenJwtExpIsLater() throws Exception {
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        assertEquals(NOW.getEpochSecond() + 300, result.expiresAt());
    }

    @Test
    void expiryIsCappedByJwtExpWhenSooner() throws Exception {
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 120), ROOT, 300, NOW);
        assertEquals(NOW.getEpochSecond() + 120, result.expiresAt());
    }

    @Test
    void hugeTtlDoesNotOverflowAndExpiryStaysFormattable() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> BiscuitMinter.mint(token("u", "c", null), ROOT, Long.MAX_VALUE, NOW));
    }

    @Test
    void missingRealmAndResourceAccessYieldsNoRoleFacts() throws Exception {
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", null, NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());
        String printed = parsed.print();
        assertFalse(printed.contains("role("), printed);
        assertFalse(printed.contains("client("), printed);
        assertTrue(printed.contains("user(\"u\")"), printed);
    }

    @Test
    void missingSubjectIsRejected() {
        assertThrows(BiscuitMinter.MissingSubjectException.class, () ->
                BiscuitMinter.mint(token(null, "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW));
    }

    @Test
    void injectsConfiguredExtraFacts() throws Exception {
        BiscuitMinter.MintResult result = BiscuitMinter.mint(
                token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW,
                List.of(new BiscuitMinter.FactSpec("audience", List.of("biscuitmcp://exado")),
                        new BiscuitMinter.FactSpec("required_profile", List.of("native"))));
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());
        String printed = parsed.print();
        assertTrue(printed.contains("audience(\"biscuitmcp://exado\")"), printed);
        assertTrue(printed.contains("required_profile(\"native\")"), printed);
        // les faits cœur restent émis : l'extension n'écrase rien
        assertTrue(printed.contains("user(\"u\")"), printed);
        assertTrue(printed.contains("jti(\""), printed);
    }

    @Test
    void extraFactValuesCannotInjectDatalog() throws Exception {
        // une valeur piégée reste un littéral string, jamais une source datalog
        BiscuitMinter.MintResult result = BiscuitMinter.mint(
                token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW,
                List.of(new BiscuitMinter.FactSpec("audience", List.of("x\"); role(\"hacker"))));
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());
        assertThrows(Error.FailedLogic.class, () -> parsed.authorizer()
                .add_fact(NOW_TIME_FACT).add_check("check if role(\"hacker\")").allow().authorize(TEST_LIMITS));
    }

    @Test
    void emitsKeyIdFactAndPopulatesAuditWhenKeyIdProvided() throws Exception {
        BiscuitMinter.MintResult result = BiscuitMinter.mint(
                token("u", "c", NOW.getEpochSecond() + 3600), ROOT, "kid-epoch-1", 300, NOW,
                List.of(new BiscuitMinter.FactSpec("audience", List.of("biscuitmcp://exado")),
                        new BiscuitMinter.FactSpec("required_profile", List.of("native"))));

        String printed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key()).print();
        assertTrue(printed.contains("key_id(\"kid-epoch-1\")"), printed);

        BiscuitMinter.Audit audit = result.audit();
        assertNotNull(audit);
        assertEquals("kid-epoch-1", audit.keyId());
        assertEquals("u", audit.subject());
        assertEquals("biscuitmcp://exado", audit.audience());
        assertEquals("native", audit.requiredProfile());
        assertFalse(audit.capabilityId().isBlank(), "capability_id (jti) doit être renseigné");
        assertEquals(result.expiresAt(), audit.expiresAt());
    }

    @Test
    void noKeyIdFactWhenKeyIdAbsent() throws Exception {
        // surcharge sans keyId : aucun fait key_id, mais l'audit reste disponible
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        assertFalse(Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key()).print().contains("key_id("));
        assertNotNull(result.audit());
        assertEquals("u", result.audit().subject());
    }

    @Test
    void claimValuesCannotInjectDatalog() throws Exception {
        // un sub piégé doit finir comme simple littéral string, pas comme source datalog
        String evil = "x\"); role(\"hacker";
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token(evil, null, NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());

        // le token reste vérifiable normalement…
        parsed.authorizer().add_fact(NOW_TIME_FACT).allow().authorize(TEST_LIMITS);
        // …mais aucun fact role("hacker") n'a été créé : l'exiger doit échouer
        assertThrows(Error.FailedLogic.class, () -> parsed.authorizer()
                .add_fact(NOW_TIME_FACT).add_check("check if role(\"hacker\")").allow().authorize(TEST_LIMITS));
    }
}
