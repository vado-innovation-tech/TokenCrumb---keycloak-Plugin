// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validation and conversion of the extra facts that can be injected into a Biscuit.
 * Single source of truth for the rules, shared by both issuance paths:
 * the global REST config ({@link BiscuitConfig}) and the protocol mapper
 * ({@link BiscuitProtocolMapper}).
 *
 * <p>Three sets of reserved names protect the security semantics:</p>
 * <ul>
 *   <li>{@link #RESERVED_CORE}: facts issued by the engine itself (or reserved for future use,
 *       read from the Keycloak model — never supplied by the requester). Forbidden on
 *       <strong>every</strong> config path, so the base semantics cannot be blurred or forged
 *       ({@code user}, {@code jti}, {@code key_id}, {@code agent_pubkey}…).</li>
 *   <li>{@link #RESERVED_GOVERNED}: security-sensitive facts (anti-downgrade, scoping, agent
 *       identity). They are only accepted through a <strong>dedicated, validated</strong> path
 *       ({@link #governed} — named UI fields, or trusted deployer config), never through the
 *       free-form per-client map ({@link #validated}). This prevents a free-form fact from forging
 *       or duplicating a {@code required_profile}/{@code audience}.</li>
 *   <li>{@link #DEPLOYER_ONLY}: {@code right}, accepted only from the deployer configuration
 *       ({@code BISCUIT_EXTRA_FACTS}, static rights mode), never from the free-form per-client map.</li>
 * </ul>
 *
 * <p>In every case: name = valid Datalog predicate, values as string literals (injection safety
 * is guaranteed downstream by {@code Utils.string} in {@link BiscuitMinter}), and a rejected fact
 * invalidates the issuance configuration on both the REST and mapper paths.</p>
 */
public final class BiscuitFacts {

    private static final Logger LOG = Logger.getLogger(BiscuitFacts.class);

    /** Valid Datalog predicate: a lowercase letter, then lowercase letters, digits or underscores. */
    static final Pattern FACT_NAME = Pattern.compile("^[a-z][a-z0-9_]{0,63}$");

    /**
     * Facts issued by the engine (or reserved for future use, derived from the Keycloak model): forbidden
     * on every config path, free-form or dedicated. {@code key_id} is issued by the minter;
     * {@code agent_pubkey}/{@code max_delegation_depth} are reserved for anchoring and future
     * delegation support and must never come from a value supplied in configuration.
     */
    static final Set<String> RESERVED_CORE = Set.of(
            "user", "client", "issuer", "realm_role", "client_role", "jti", "time",
            "key_id", "agent_pubkey", "max_delegation_depth", "expires_at", "operation", "upstream",
            "resource", "budget", "delegation_depth", "arg", "call_signature_valid", "nonce_fresh", "arguments_bound", "capability_bound");

    /**
     * Security-sensitive facts, settable only through their dedicated field ({@link #governed}),
     * never through the free-form per-client map ({@link #validated}). Guarantees that a
     * {@code required_profile} (anti-downgrade) or an {@code audience} (scoping) can be neither
     * forged nor duplicated by a free-form fact.
     */
    static final Set<String> RESERVED_GOVERNED = Set.of(
            "audience", "required_profile", "agent_id", "principal_id", "rights_source", "spiffe_id", "budget_cap");

    /**
     * Rights granted by the deployer: in static rights mode, {@code right(tool, operation)} facts come
     * only from the deployer configuration ({@code BISCUIT_EXTRA_FACTS}). Like {@link #RESERVED_GOVERNED}
     * (which already holds {@code rights_source}), rejected on the free-form per-client path, so a client
     * admin cannot grant tool rights through the mapper's "Extra facts" map.
     */
    static final Set<String> DEPLOYER_ONLY = Set.of("right");

    /** Agent public key: {@code ed25519/} followed by 64 hexadecimal characters. */
    static final Pattern AGENT_PUBKEY = Pattern.compile("^ed25519/[0-9a-fA-F]{64}$");

    /**
     * Profile enforced as soon as an agent key is anchored: anchoring is only meaningful if the
     * authorizer then requires proof of possession of the key.
     */
    static final String ANCHORED_PROFILE = "hardened_biscuit_anchored";

    private BiscuitFacts() {
    }

    /**
     * <strong>Per-request</strong> path: the only one that accepts {@code agent_pubkey}, and it
     * accepts nothing else.
     *
     * <p>The reservation in {@link #RESERVED_CORE} targets <em>configuration</em>: an agent key
     * hard-coded by a deployer would apply to every exchange in the realm, which would be
     * dangerous. A key supplied by an already-authenticated requester is a different channel, and
     * anchoring it only <strong>restricts</strong> the mandate to the holder of the matching private
     * key: tool rights come from the configured role mapping (or the explicitly chosen static mode). This is the
     * <em>proof-of-possession</em> reasoning of RFC 7800.</p>
     *
     * <p>An invalid value is rejected, never skipped: the requester explicitly asked for anchoring,
     * and handing back an unanchored mandate they would believe to be anchored would be worse than
     * a refusal. The caller maps {@link Optional#empty()} to {@code 400}.</p>
     */
    public static Optional<BiscuitMinter.FactSpec> requested(String agentPubkey) {
        if (agentPubkey == null || !AGENT_PUBKEY.matcher(agentPubkey).matches()) {
            return Optional.empty();
        }
        // Lowercase normalization: two spellings of the same key must not produce two different
        // mandates, and this is the form downstream verifiers expect.
        return Optional.of(new BiscuitMinter.FactSpec("agent_pubkey",
                List.of(agentPubkey.toLowerCase(java.util.Locale.ROOT))));
    }

    /**
     * Builds the facts of an anchored exchange: the configured facts, minus any
     * {@code required_profile} they declared, plus the anchored key and the enforced profile.
     *
     * <p>The removal is not cosmetic. Without it, a deployer who configured
     * {@code required_profile("native")} would produce a mandate carrying both an anchored key and
     * permission to skip it: the caller would anchor a key and then present the mandate under
     * the {@code native} profile, skipping proof of possession. The extension would create a bypass instead of closing
     * one.</p>
     */
    public static List<BiscuitMinter.FactSpec> anchored(List<BiscuitMinter.FactSpec> configured,
                                                        BiscuitMinter.FactSpec agentPubkey) {
        List<BiscuitMinter.FactSpec> out = new java.util.ArrayList<>();
        for (BiscuitMinter.FactSpec fact : configured == null ? List.<BiscuitMinter.FactSpec>of() : configured) {
            if ("required_profile".equals(fact.name())) {
                LOG.debugf("Biscuit exchange: overriding configured required_profile '%s' "
                        + "because an agent key is anchored", fact.values());
                continue;
            }
            out.add(fact);
        }
        out.add(agentPubkey);
        out.add(new BiscuitMinter.FactSpec("required_profile", List.of(ANCHORED_PROFILE)));
        return List.copyOf(out);
    }

    static void checkUnique(List<BiscuitMinter.FactSpec> facts) {
        var seen = new java.util.HashSet<String>();
        for (var f : facts) if ((RESERVED_GOVERNED.contains(f.name()) || f.name().equals("agent_pubkey"))
                && !seen.add(f.name())) throw new IllegalArgumentException("duplicate governed fact: " + f.name());
    }

    /**
     * <strong>Free-form</strong> path (per-client fact map):
     * rejects core, governed and deployer-only ({@code right}) names. Use it for any arbitrary
     * business fact.
     */
    public static Optional<BiscuitMinter.FactSpec> validated(String name, List<String> values) {
        return validate(name, values, true);
    }

    /**
     * <strong>Dedicated, trusted</strong> path (named mapper UI fields, deployer config):
     * rejects only core names. Allows governed facts ({@code audience},
     * {@code required_profile}, agent identity) because they come from a named, validated input.
     */
    public static Optional<BiscuitMinter.FactSpec> governed(String name, List<String> values) {
        return validate(name, values, false);
    }

    /**
     * Validates a fact and converts it into a {@link BiscuitMinter.FactSpec}. Returns
     * {@link Optional#empty()} (with a {@code WARN}) if the name is invalid, core, or — when
     * {@code rejectGoverned} — governed; the caller must refuse issuance when a validation fails.
     */
    private static Optional<BiscuitMinter.FactSpec> validate(String name, List<String> values,
                                                             boolean rejectGoverned) {
        if (name == null || !FACT_NAME.matcher(name).matches()) {
            LOG.warnf("Biscuit extra fact: rejecting invalid Datalog name '%s'", name);
            return Optional.empty();
        }
        if (RESERVED_CORE.contains(name)) {
            LOG.warnf("Biscuit extra fact: rejecting reserved core fact name '%s'", name);
            return Optional.empty();
        }
        if (rejectGoverned && RESERVED_GOVERNED.contains(name)) {
            LOG.warnf("Biscuit extra fact: rejecting security-governed fact '%s' on a free-form path; "
                    + "set it through its dedicated field instead", name);
            return Optional.empty();
        }
        if (rejectGoverned && DEPLOYER_ONLY.contains(name)) {
            LOG.warnf("Biscuit extra fact: rejecting '%s' on a free-form path; rights come from the role "
                    + "mapping or, in static mode, from the deployer configuration", name);
            return Optional.empty();
        }
        if (values == null || values.isEmpty() || values.size() > 16 || values.stream().anyMatch(v ->
                v == null || v.isBlank() || !v.equals(v.trim()) || v.length() > 4096 || v.chars().anyMatch(c -> c < 32)))
            return Optional.empty();
        if (RESERVED_GOVERNED.contains(name) && values.size() != 1) return Optional.empty();
        if (name.equals("right") && values.size() != 2) return Optional.empty();
        if (name.equals("required_profile") && !Set.of("native", "registry_backed", ANCHORED_PROFILE).contains(values.get(0)))
            return Optional.empty();
        if (name.equals("budget_cap")) {
            try { if (!values.get(0).matches("[0-9]+") || Long.parseLong(values.get(0)) > 9007199254740991L) return Optional.empty(); }
            catch (NumberFormatException e) { return Optional.empty(); }
        }
        return Optional.of(new BiscuitMinter.FactSpec(name, values));
    }
}
