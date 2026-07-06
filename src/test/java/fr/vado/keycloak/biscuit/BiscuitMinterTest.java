// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import io.vavr.control.Option;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.RunLimits;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.RevocationIdentifier;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.AccessToken;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Locks down the Datalog syntax and the biscuit-java 4.0.1 API without any container:
 * if these tests pass, the ITs cannot fail because of Biscuit construction.
 */
class BiscuitMinterTest {

    // These are logic tests: allow for shared-runner scheduling without changing production limits.
    private static final RunLimits TEST_LIMITS = new RunLimits(1000, 100, Duration.ofSeconds(1));

    private static final KeyPair ROOT = new KeyPair(new SecureRandom());
    private static final Instant NOW = Instant.parse("2026-06-11T10:00:00Z");
    /** time(...) fact at minting time: deterministic verification, independent of the real clock. */
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

        // round-trip: parsing + signature verification with the public key alone
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

        // the authorizer passes at minting time (deterministic, before expiry)
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
                List.of(new BiscuitMinter.FactSpec("audience", List.of("https://gateway.example")),
                        new BiscuitMinter.FactSpec("required_profile", List.of("native"))));
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());
        String printed = parsed.print();
        assertTrue(printed.contains("audience(\"https://gateway.example\")"), printed);
        assertTrue(printed.contains("required_profile(\"native\")"), printed);
        // core facts are still issued: the extension overrides nothing
        assertTrue(printed.contains("user(\"u\")"), printed);
        assertTrue(printed.contains("jti(\""), printed);
    }

    @Test
    void extraFactValuesCannotInjectDatalog() throws Exception {
        // a malicious value stays a string literal, never Datalog source
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
                List.of(new BiscuitMinter.FactSpec("audience", List.of("https://gateway.example")),
                        new BiscuitMinter.FactSpec("required_profile", List.of("native"))));

        String printed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key()).print();
        assertTrue(printed.contains("key_id(\"kid-epoch-1\")"), printed);

        BiscuitMinter.Audit audit = result.audit();
        assertNotNull(audit);
        assertEquals("kid-epoch-1", audit.keyId());
        assertEquals("u", audit.subject());
        assertEquals("https://gateway.example", audit.audience());
        assertEquals("native", audit.requiredProfile());
        assertFalse(audit.capabilityId().isBlank(), "capability_id (jti) must be set");
        assertEquals(result.expiresAt(), audit.expiresAt());
    }

    @Test
    void noKeyIdFactWhenKeyIdAbsent() throws Exception {
        // overload without keyId: no key_id fact, but the audit is still available
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        assertFalse(Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key()).print().contains("key_id("));
        assertNotNull(result.audit());
        assertEquals("u", result.audit().subject());
    }

    @Test
    void claimValuesCannotInjectDatalog() throws Exception {
        // a malicious sub must end up as a plain string literal, not as Datalog source
        String evil = "x\"); role(\"hacker";
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token(evil, null, NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());

        // the token remains verifiable as usual…
        parsed.authorizer().add_fact(NOW_TIME_FACT).allow().authorize(TEST_LIMITS);
        // …but no role("hacker") fact was created: requiring it must fail
        assertThrows(Error.FailedLogic.class, () -> parsed.authorizer()
                .add_fact(NOW_TIME_FACT).add_check("check if role(\"hacker\")").allow().authorize(TEST_LIMITS));
    }

    // ---- root_key_id and revocation identifiers ----

    @Test
    void rootKeyIdMatchesTheKnownAnswerVector() {
        // RFC 8032 test vector 1: SHA-256(public key) starts with 21fe31df → 0x21fe31df & 0x7fffffff
        KeyPair rfc8032 = new KeyPair("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        assertEquals("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                rfc8032.public_key().toHex().toLowerCase(Locale.ROOT));
        assertEquals(570307039, BiscuitMinter.rootKeyId(rfc8032.public_key()));
    }

    @Test
    void rootKeyIdIsStableNonNegativeAndChangesWithTheKey() {
        // same key reloaded from its seed (restart) → same id
        assertEquals(BiscuitMinter.rootKeyId(ROOT.public_key()),
                BiscuitMinter.rootKeyId(new KeyPair(ROOT.toHex()).public_key()));
        for (int i = 0; i < 64; i++) {
            assertTrue(BiscuitMinter.rootKeyId(new KeyPair(new SecureRandom()).public_key()) >= 0);
        }
        assertNotEquals(BiscuitMinter.rootKeyId(ROOT.public_key()),
                BiscuitMinter.rootKeyId(new KeyPair(new SecureRandom()).public_key()));
    }

    @Test
    void envelopeCarriesTheRootKeyIdForKeySelection() throws Exception {
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token("u", "c", NOW.getEpochSecond() + 3600), ROOT, 300, NOW);
        int expected = BiscuitMinter.rootKeyId(ROOT.public_key());

        // the way an authorizer selects the root key: a key provider keyed on root_key_id
        AtomicReference<Option<Integer>> seen = new AtomicReference<>();
        Biscuit.from_b64url(result.biscuitB64(), (Option<Integer> id) -> {
            seen.set(id);
            return id.contains(expected) ? Option.some(ROOT.public_key()) : Option.<PublicKey>none();
        });
        assertEquals(Option.some(expected), seen.get());
    }

    @Test
    void revocationIdsMatchTheMintedTokenAndFeedTheAudit() throws Exception {
        BiscuitMinter.MintResult result = BiscuitMinter.mint(
                token("u", "c", NOW.getEpochSecond() + 3600), ROOT, "kid-epoch-1", 300, NOW, List.of());
        Biscuit parsed = Biscuit.from_b64url(result.biscuitB64(), ROOT.public_key());

        List<String> expected = parsed.revocation_identifiers().stream()
                .map(RevocationIdentifier::toHex).map(h -> h.toLowerCase(Locale.ROOT)).toList();
        assertEquals(1, result.revocationIds().size(), "a freshly minted token has only its authority block");
        assertEquals(expected, result.revocationIds());
        assertTrue(result.revocationIds().get(0).matches("[0-9a-f]+"), result.revocationIds().toString());
        assertEquals(result.revocationIds().get(0), result.audit().revocationId());

        String json = BiscuitAudit.issuedJson("rest", "r", result.audit());
        assertEquals(result.revocationIds().get(0),
                StrictJson.parse(json).getAsJsonObject().get("revocation_id").getAsString());
    }
}
