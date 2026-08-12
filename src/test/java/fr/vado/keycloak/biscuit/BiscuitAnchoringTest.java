// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Anchoring of an agent key supplied by the requester.
 *
 * <p>The point is not just that anchoring works, but that it is never half-done: a mandate that carries
 * a key while leaving the native profile open would give the caller a way around attestation, and a
 * mandate believed to be anchored when it is not is worse than a refusal.</p>
 */
class BiscuitAnchoringTest {

    private static final String KEY = "ed25519/" + "ab".repeat(32);
    private static final List<BiscuitMinter.FactSpec> NO_CONFIG = List.of();

    private static String profileOf(List<BiscuitMinter.FactSpec> facts) {
        return facts.stream()
                .filter(f -> "required_profile".equals(f.name()))
                .map(f -> f.values().get(0))
                .reduce((a, b) -> {
                    throw new AssertionError("required_profile emitted twice: " + a + " / " + b);
                })
                .orElse(null);
    }

    private static String pubkeyOf(List<BiscuitMinter.FactSpec> facts) {
        return facts.stream()
                .filter(f -> "agent_pubkey".equals(f.name()))
                .map(f -> f.values().get(0))
                .findFirst().orElse(null);
    }

    // ------------------------------------------------------------------ //
    // BiscuitFacts.requested: the only path that accepts agent_pubkey
    // ------------------------------------------------------------------ //
    @Test
    void requestedAcceptsAWellFormedKey() {
        Optional<BiscuitMinter.FactSpec> fact = BiscuitFacts.requested(KEY);
        assertTrue(fact.isPresent());
        assertEquals("agent_pubkey", fact.get().name());
        assertEquals(List.of(KEY), fact.get().values());
    }

    @Test
    void requestedNormalisesTheHexToLowercase() {
        // Two spellings of the same key must not produce two different mandates.
        assertEquals(List.of(KEY),
                BiscuitFacts.requested("ed25519/" + "AB".repeat(32)).orElseThrow().values());
    }

    @Test
    void requestedRejectsAnythingElse() {
        for (String bad : List.of(
                "", "   ", "ed25519/", "ed25519/short", "ed25519/" + "zz".repeat(32),
                "ed25519/" + "ab".repeat(33), "ed25519/" + "ab".repeat(31),
                "ED25519/" + "ab".repeat(32), "rsa/" + "ab".repeat(32), "ab".repeat(32))) {
            assertTrue(BiscuitFacts.requested(bad).isEmpty(), "should have been rejected: " + bad);
        }
        assertTrue(BiscuitFacts.requested(null).isEmpty());
    }

    @Test
    void configurationPathsStillRefuseAgentPubkey() {
        // The reservation targets configuration: it remains intact. Only the per-request path opens it.
        assertTrue(BiscuitFacts.validated("agent_pubkey", List.of(KEY)).isEmpty());
        assertTrue(BiscuitFacts.governed("agent_pubkey", List.of(KEY)).isEmpty());
    }

    // ------------------------------------------------------------------ //
    // BiscuitFacts.anchored: the enforced profile
    // ------------------------------------------------------------------ //
    @Test
    void anchoringForcesTheHardenedProfile() {
        List<BiscuitMinter.FactSpec> facts =
                BiscuitFacts.anchored(NO_CONFIG, BiscuitFacts.requested(KEY).orElseThrow());
        assertEquals(KEY, pubkeyOf(facts));
        assertEquals("hardened_biscuit_anchored", profileOf(facts));
    }

    @Test
    void aConfiguredProfileCannotSurviveAnchoring() {
        // The bypass: anchor a key, then present the mandate under the native profile. If a configured
        // required_profile("native") survived, the extension would create a bypass instead of closing one.
        List<BiscuitMinter.FactSpec> configured =
                List.of(new BiscuitMinter.FactSpec("required_profile", List.of("native")));
        List<BiscuitMinter.FactSpec> facts =
                BiscuitFacts.anchored(configured, BiscuitFacts.requested(KEY).orElseThrow());
        assertEquals("hardened_biscuit_anchored", profileOf(facts));
    }

    @Test
    void otherConfiguredFactsAreKept() {
        List<BiscuitMinter.FactSpec> configured = List.of(
                new BiscuitMinter.FactSpec("audience", List.of("gw-paris")),
                new BiscuitMinter.FactSpec("agent_id", List.of("agent-1")));
        List<BiscuitMinter.FactSpec> facts =
                BiscuitFacts.anchored(configured, BiscuitFacts.requested(KEY).orElseThrow());
        assertTrue(facts.containsAll(configured), facts.toString());
        assertEquals("hardened_biscuit_anchored", profileOf(facts));
    }

    // ------------------------------------------------------------------ //
    // BiscuitResource.factsFor: the request body
    // ------------------------------------------------------------------ //
    @Test
    void noBodyKeepsTheConfiguredFactsUntouched() {
        List<BiscuitMinter.FactSpec> configured =
                List.of(new BiscuitMinter.FactSpec("audience", List.of("gw-paris")));
        assertSame(configured, BiscuitResource.factsFor(null, configured));
        assertSame(configured, BiscuitResource.factsFor("", configured));
        assertSame(configured, BiscuitResource.factsFor("   ", configured));
    }

    @Test
    void aNullAgentPubkeyIsRefused() {
        List<BiscuitMinter.FactSpec> configured = List.of();
        assertThrows(BiscuitResource.InvalidRequestException.class, () -> BiscuitResource.factsFor("{\"agent_pubkey\": null}", configured));
    }

    @Test
    void aWellFormedBodyAnchors() {
        List<BiscuitMinter.FactSpec> facts =
                BiscuitResource.factsFor("{\"agent_pubkey\": \"" + KEY + "\"}", NO_CONFIG);
        assertEquals(KEY, pubkeyOf(facts));
        assertEquals("hardened_biscuit_anchored", profileOf(facts));
    }

    @Test
    void aMalformedKeyIsRefusedRatherThanSilentlyDropped() {
        BiscuitResource.InvalidRequestException e = assertThrows(
                BiscuitResource.InvalidRequestException.class,
                () -> BiscuitResource.factsFor("{\"agent_pubkey\": \"nope\"}", NO_CONFIG));
        assertEquals("invalid_agent_pubkey", e.code());
    }

    @Test
    void aNonStringKeyIsRefused() {
        BiscuitResource.InvalidRequestException e = assertThrows(
                BiscuitResource.InvalidRequestException.class,
                () -> BiscuitResource.factsFor("{\"agent_pubkey\": 42}", NO_CONFIG));
        assertEquals("invalid_agent_pubkey", e.code());
    }

    @Test
    void anUnknownFieldIsRefused() {
        // A caller who believes they asked for something and gets a 200 without receiving it is
        // the worst of both worlds.
        BiscuitResource.InvalidRequestException e = assertThrows(
                BiscuitResource.InvalidRequestException.class,
                () -> BiscuitResource.factsFor("{\"required_profile\": \"native\"}", NO_CONFIG));
        assertEquals("invalid_request", e.code());
    }

    @Test
    void anUnparseableOrNonObjectBodyIsRefused() {
        for (String bad : List.of("{", "[]", "\"x\"", "42")) {
            BiscuitResource.InvalidRequestException e = assertThrows(
                    BiscuitResource.InvalidRequestException.class,
                    () -> BiscuitResource.factsFor(bad, NO_CONFIG), "should have been rejected: " + bad);
            assertEquals("invalid_request", e.code());
        }
    }
}
