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
 * Ancrage d'une clé d'agent fournie par le demandeur (ADR-0003 du dépôt {@code MCPproxy}).
 *
 * <p>L'enjeu n'est pas de savoir ancrer, c'est de ne jamais ancrer à moitié : un mandat qui porte
 * une clé et laisse le profil 1 ouvert offrirait à l'appelant un contournement de l'attestation,
 * et un mandat qu'on croit ancré alors qu'il ne l'est pas est pire qu'un refus.</p>
 */
class BiscuitAnchoringTest {

    private static final String KEY = "ed25519/" + "ab".repeat(32);
    private static final List<BiscuitMinter.FactSpec> NO_CONFIG = List.of();

    private static String profileOf(List<BiscuitMinter.FactSpec> facts) {
        return facts.stream()
                .filter(f -> "required_profile".equals(f.name()))
                .map(f -> f.values().get(0))
                .reduce((a, b) -> {
                    throw new AssertionError("required_profile émis deux fois : " + a + " / " + b);
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
    // BiscuitFacts.requested : la seule voie qui accepte agent_pubkey
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
        // Deux orthographes de la même clé ne doivent pas produire deux mandats différents.
        assertEquals(List.of(KEY),
                BiscuitFacts.requested("ed25519/" + "AB".repeat(32)).orElseThrow().values());
    }

    @Test
    void requestedRejectsAnythingElse() {
        for (String bad : List.of(
                "", "   ", "ed25519/", "ed25519/short", "ed25519/" + "zz".repeat(32),
                "ed25519/" + "ab".repeat(33), "ed25519/" + "ab".repeat(31),
                "ED25519/" + "ab".repeat(32), "rsa/" + "ab".repeat(32), "ab".repeat(32))) {
            assertTrue(BiscuitFacts.requested(bad).isEmpty(), "devait être refusé : " + bad);
        }
        assertTrue(BiscuitFacts.requested(null).isEmpty());
    }

    @Test
    void configurationPathsStillRefuseAgentPubkey() {
        // La réserve visait la configuration : elle reste entière. Seule la voie par requête ouvre.
        assertTrue(BiscuitFacts.validated("agent_pubkey", List.of(KEY)).isEmpty());
        assertTrue(BiscuitFacts.governed("agent_pubkey", List.of(KEY)).isEmpty());
    }

    // ------------------------------------------------------------------ //
    // BiscuitFacts.anchored : le profil imposé
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
        // Le contournement : ancrer une clé, puis présenter le mandat en profil 1. Si un
        // required_profile("native") de configuration subsistait, l'extension ouvrirait un trou.
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
    // BiscuitResource.factsFor : le corps de requête
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
        // Un appelant qui croit avoir demandé quelque chose et reçoit 200 sans l'avoir obtenu est
        // le pire des deux mondes.
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
                    () -> BiscuitResource.factsFor(bad, NO_CONFIG), "devait être refusé : " + bad);
            assertEquals("invalid_request", e.code());
        }
    }
}
