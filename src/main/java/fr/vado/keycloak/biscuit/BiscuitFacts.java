// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Validation et conversion des faits supplémentaires injectables dans un Biscuit.
 * Source de vérité unique des règles, partagée par les deux voies d'émission :
 * la config globale REST ({@link BiscuitConfig}) et le mapper de protocole
 * ({@link BiscuitProtocolMapper}).
 *
 * <p>Deux niveaux de réservation protègent la sémantique de sécurité :</p>
 * <ul>
 *   <li>{@link #RESERVED_CORE} : faits frappés par le moteur lui-même (ou réservés pour un lot
 *       ultérieur, lus depuis le modèle Keycloak — jamais fournis par le demandeur). Interdits sur
 *       <strong>toutes</strong> les voies de config, pour ne pas brouiller ni forger la sémantique
 *       de base ({@code user}, {@code jti}, {@code key_id}, {@code agent_pubkey}…).</li>
 *   <li>{@link #RESERVED_GOVERNED} : faits sensibles à la sécurité (anti-downgrade, scoping,
 *       identité agent). Ils ne sont acceptés que via une voie <strong>dédiée et validée</strong>
 *       ({@link #governed} — champs UI nommés, ou config déployeur de confiance), jamais via la map
 *       libre per-client ({@link #validated}). Cela empêche un fait libre de forger ou de dupliquer
 *       un {@code required_profile}/{@code audience} (note §A3).</li>
 * </ul>
 *
 * <p>Dans tous les cas : nom = prédicat Datalog valide, valeurs en littéraux string (l'insensibilité
 * à l'injection est garantie en aval par {@code Utils.string} dans {@link BiscuitMinter}), et un fait
 * refusé invalide la configuration d'émission dans les voies REST et mapper.</p>
 */
public final class BiscuitFacts {

    private static final Logger LOG = Logger.getLogger(BiscuitFacts.class);

    /** Prédicat Datalog valide : minuscule initiale, puis alphanumérique/underscore. */
    static final Pattern FACT_NAME = Pattern.compile("^[a-z][a-z0-9_]{0,63}$");

    /**
     * Faits frappés par le moteur (ou réservés Lot 3, dérivés du modèle Keycloak) : interdits sur
     * toute voie de config, qu'elle soit libre ou dédiée. {@code key_id} est émis par le minter ;
     * {@code agent_pubkey}/{@code max_delegation_depth} sont réservés pour le profil 3b / la chaîne
     * de cautions et ne devront jamais provenir d'une valeur fournie en configuration.
     */
    static final Set<String> RESERVED_CORE = Set.of(
            "user", "client", "issuer", "realm_role", "client_role", "jti", "time",
            "key_id", "agent_pubkey", "max_delegation_depth", "expires_at", "operation", "upstream",
            "resource", "budget", "delegation_depth", "arg", "call_signature_valid", "nonce_fresh", "arguments_bound", "capability_bound");

    /**
     * Faits sensibles à la sécurité, settables uniquement via leur champ dédié ({@link #governed}),
     * jamais via la map libre per-client ({@link #validated}). Garantit qu'un {@code required_profile}
     * (anti-downgrade) ou une {@code audience} (scoping) ne peut être ni forgé ni dupliqué par un
     * fait libre.
     */
    static final Set<String> RESERVED_GOVERNED = Set.of(
            "audience", "required_profile", "agent_id", "principal_id", "rights_source", "spiffe_id", "budget_cap");

    /** Clé publique d'agent : {@code ed25519/} suivi de 64 caractères hexadécimaux. */
    static final Pattern AGENT_PUBKEY = Pattern.compile("^ed25519/[0-9a-fA-F]{64}$");

    /**
     * Profil imposé dès qu'une clé d'agent est ancrée (ADR-0003 du dépôt {@code MCPproxy},
     * {@code docs/adr/0003-demo-en-profil-3b-via-extension-du-spi-keycloak.md}).
     */
    static final String ANCHORED_PROFILE = "hardened_biscuit_anchored";

    private BiscuitFacts() {
    }

    /**
     * Voie <strong>par requête</strong> : la seule qui accepte {@code agent_pubkey}, et elle
     * n'accepte que lui.
     *
     * <p>La réserve inscrite dans {@link #RESERVED_CORE} visait la <em>configuration</em> : une clé
     * d'agent posée en dur par un déployeur s'appliquerait à tous les échanges du realm, ce qui
     * serait dangereux. Une clé fournie par un demandeur déjà authentifié est un canal différent, et
     * l'ancrer ne fait que <strong>restreindre</strong> le mandat au détenteur de la clé privée
     * correspondante : les droits d'outils viennent de la correspondance de rôles configurée (ou du mode statique explicitement choisi). C'est le
     * raisonnement du <em>proof-of-possession</em> de la RFC 7800.</p>
     *
     * <p>Contrairement à {@link #validated} et {@link #governed}, une valeur invalide n'est pas
     * ignorée avec un {@code WARN} : le demandeur a explicitement demandé un ancrage, et lui rendre
     * un mandat non ancré qu'il croirait de profil 3b serait pire qu'un refus. L'appelant traduit
     * l'{@link Optional#empty()} en {@code 400}.</p>
     */
    public static Optional<BiscuitMinter.FactSpec> requested(String agentPubkey) {
        if (agentPubkey == null || !AGENT_PUBKEY.matcher(agentPubkey).matches()) {
            return Optional.empty();
        }
        // Normalisation en minuscules : deux orthographes de la même clé ne doivent pas produire
        // deux mandats différents, et c'est la forme qu'émet le plan de contrôle côté proxy.
        return Optional.of(new BiscuitMinter.FactSpec("agent_pubkey",
                List.of(agentPubkey.toLowerCase(java.util.Locale.ROOT))));
    }

    /**
     * Compose les faits d'un échange avec ancrage : les faits de configuration, moins tout
     * {@code required_profile} qu'ils déclaraient, plus la clé ancrée et le profil imposé.
     *
     * <p>Le retrait n'est pas cosmétique. Sans lui, un déployeur ayant configuré
     * {@code required_profile("native")} produirait un mandat portant à la fois une clé ancrée et
     * l'autorisation de s'en passer : l'appelant ancrerait une clé puis présenterait le mandat en
     * profil 1, court-circuitant l'attestation. L'extension ouvrirait un contournement au lieu de
     * fermer un trou (ADR-0003 du dépôt {@code MCPproxy}).</p>
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
     * Voie <strong>libre</strong> (map de faits per-client, {@code BISCUIT_EXTRA_FACTS} historique) :
     * rejette les noms cœur <em>et</em> gouvernés. À utiliser pour tout fait métier arbitraire.
     */
    public static Optional<BiscuitMinter.FactSpec> validated(String name, List<String> values) {
        return validate(name, values, true);
    }

    /**
     * Voie <strong>dédiée et de confiance</strong> (champs UI nommés du mapper, config déployeur) :
     * rejette uniquement les noms cœur. Autorise les faits gouvernés ({@code audience},
     * {@code required_profile}, identité agent) car ils proviennent d'une entrée nommée et validée.
     */
    public static Optional<BiscuitMinter.FactSpec> governed(String name, List<String> values) {
        return validate(name, values, false);
    }

    /**
     * Valide un fait et le convertit en {@link BiscuitMinter.FactSpec}. Retourne
     * {@link Optional#empty()} (avec un {@code WARN}) si le nom est invalide, cœur, ou — quand
     * {@code rejectGoverned} — gouverné, l'appelant doit refuser l'émission lorsqu'une validation échoue.
     */
    private static Optional<BiscuitMinter.FactSpec> validate(String name, List<String> values,
                                                             boolean rejectGoverned) {
        if (name == null || !FACT_NAME.matcher(name).matches()) {
            LOG.warnf("Biscuit extra fact: skipping invalid Datalog name '%s'", name);
            return Optional.empty();
        }
        if (RESERVED_CORE.contains(name)) {
            LOG.warnf("Biscuit extra fact: skipping reserved core fact name '%s'", name);
            return Optional.empty();
        }
        if (rejectGoverned && RESERVED_GOVERNED.contains(name)) {
            LOG.warnf("Biscuit extra fact: skipping security-governed fact '%s' on a free-form path; "
                    + "set it through its dedicated field instead", name);
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
