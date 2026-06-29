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
 * refusé est simplement ignoré avec un {@code WARN} (l'émission n'échoue jamais).</p>
 */
public final class BiscuitFacts {

    private static final Logger LOG = Logger.getLogger(BiscuitFacts.class);

    /** Prédicat Datalog valide : minuscule initiale, puis alphanumérique/underscore. */
    static final Pattern FACT_NAME = Pattern.compile("^[a-z][a-zA-Z0-9_]*$");

    /**
     * Faits frappés par le moteur (ou réservés Lot 3, dérivés du modèle Keycloak) : interdits sur
     * toute voie de config, qu'elle soit libre ou dédiée. {@code key_id} est émis par le minter ;
     * {@code agent_pubkey}/{@code max_delegation_depth} sont réservés pour le profil 3b / la chaîne
     * de cautions et ne devront jamais provenir d'une valeur fournie en configuration.
     */
    static final Set<String> RESERVED_CORE = Set.of(
            "user", "client", "issuer", "realm_role", "client_role", "jti", "time",
            "key_id", "agent_pubkey", "max_delegation_depth");

    /**
     * Faits sensibles à la sécurité, settables uniquement via leur champ dédié ({@link #governed}),
     * jamais via la map libre per-client ({@link #validated}). Garantit qu'un {@code required_profile}
     * (anti-downgrade) ou une {@code audience} (scoping) ne peut être ni forgé ni dupliqué par un
     * fait libre.
     */
    static final Set<String> RESERVED_GOVERNED = Set.of(
            "audience", "required_profile", "agent_id", "principal_id", "rights_source", "spiffe_id");

    private BiscuitFacts() {
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
     * {@code rejectGoverned} — gouverné, afin que l'émission n'échoue jamais à cause d'un fait mal
     * déclaré.
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
        return Optional.of(new BiscuitMinter.FactSpec(name, values == null ? List.of() : values));
    }
}
