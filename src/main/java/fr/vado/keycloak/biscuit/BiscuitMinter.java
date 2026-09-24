// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.keycloak.representations.AccessToken;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Logique pure de frappe d'un Biscuit à partir des claims d'un access token Keycloak.
 * Aucune dépendance à KeycloakSession : testable unitairement.
 *
 * Bloc authority produit :
 * <pre>
 *   user("&lt;sub&gt;");
 *   client("&lt;azp&gt;");                       // si présent dans le JWT
 *   issuer("&lt;iss&gt;");                       // claim iss du JWT (si présent)
 *   realm_role("&lt;r&gt;");                     // un par rôle realm
 *   client_role("&lt;clientId&gt;", "&lt;r&gt;");      // un par rôle client, qualifié par le client
 *   &lt;extra facts&gt;;                           // faits déclarés en config (ex. audience, required_profile)
 *   key_id("&lt;kid&gt;");                       // identifiant de la clé racine (si fourni) : rotation/révocation par époque
 *   jti("&lt;uuid&gt;");                         // identifiant unique du Biscuit (denylist applicative)
 *   check if time($t), $t &lt; &lt;exp&gt;;         // exp = min(exp du JWT, now + ttl)
 * </pre>
 *
 * L'émetteur reste générique : il ne connaît aucune sémantique applicative (agent, MCP…).
 * Les faits supplémentaires sont de simples {@link FactSpec} fournis par la configuration
 * ({@code BISCUIT_EXTRA_FACTS}) ; un déploiement qui n'en déclare aucun produit exactement
 * les faits JWT ci-dessus.
 *
 * Sécurité : les valeurs issues des claims (sub, azp, rôles) comme celles des faits
 * supplémentaires passent par l'API programmatique de facts (jamais de concaténation dans
 * du source datalog), ce qui neutralise toute injection. Seul le timestamp — calculé
 * localement — est interpolé.
 */
public final class BiscuitMinter {

    /** 9999-12-31T23:59:59Z : borne max formatable par {@link DateTimeFormatter#ISO_INSTANT}. */
    private static final long MAX_EXP_EPOCH_SECONDS = 253_402_300_799L;

    /** SecureRandom partagé (thread-safe) : évite un reseeding coûteux à chaque frappe. */
    private static final SecureRandom RNG = new SecureRandom();

    private BiscuitMinter() {
    }

    /** Addition qui sature à {@link Long#MAX_VALUE} au lieu de déborder en négatif. */
    private static long saturatedAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }

    public record MintResult(String biscuitB64, long expiresAt, Audit audit) {
    }

    /**
     * Résumé d'émission destiné à l'audit {@code capability_issued} (note §A6). Données pures :
     * les appelants ({@link BiscuitResource}, {@link BiscuitProtocolMapper}) en émettent une ligne
     * de journal. Les champs absents sont {@code null}. {@code capabilityId} = {@code jti} émis.
     */
    public record Audit(String capabilityId, String keyId, String subject, String issuer,
                        String audience, String requiredProfile, long expiresAt) {
    }

    /**
     * Fait supplémentaire à injecter dans le bloc authority, déclaré en configuration.
     * Le nom est un prédicat Datalog ; chaque valeur devient un littéral string.
     * La liste des valeurs est copiée pour garantir l'immuabilité.
     */
    public record FactSpec(String name, List<String> values) {
        public FactSpec {
            values = List.copyOf(values);
        }
    }

    /** Le JWT ne porte pas de claim {@code sub} : l'échange est impossible (fact user obligatoire). */
    public static final class MissingSubjectException extends RuntimeException {
        public MissingSubjectException() {
            super("access token has no 'sub' claim");
        }
    }

    public static MintResult mint(AccessToken token, KeyPair rootKey, long ttlSeconds, Instant now)
            throws Error {
        return mint(token, rootKey, null, ttlSeconds, now, List.of());
    }

    public static MintResult mint(AccessToken token, KeyPair rootKey, long ttlSeconds, Instant now,
                                  List<FactSpec> extraFacts) throws Error {
        return mint(token, rootKey, null, ttlSeconds, now, extraFacts);
    }

    /**
     * Surcharge canonique : {@code keyId} (l'identifiant de la clé racine) est émis comme fait
     * {@code key_id(...)} dans le bloc authority (sauf s'il est {@code null}/blanc) et repris dans
     * l'{@link Audit}, pour permettre la rotation et la révocation par époque côté vérificateur.
     */
    public static MintResult mint(AccessToken token, KeyPair rootKey, String keyId, long ttlSeconds,
                                  Instant now, List<FactSpec> extraFacts) throws Error {
        if (ttlSeconds <= 0 || ttlSeconds > BiscuitConfig.MAX_TTL_SECONDS) throw new IllegalArgumentException("invalid TTL");
        extraFacts = new java.util.ArrayList<>(extraFacts == null ? List.of() : extraFacts);
        BiscuitFacts.checkUnique(extraFacts);
        for (var f : extraFacts) {
            boolean valid = f.name().equals("agent_pubkey") ? (f.values().size() == 1 && BiscuitFacts.requested(f.values().get(0)).isPresent())
                    : BiscuitFacts.governed(f.name(), f.values()).isPresent();
            if (!valid) throw new IllegalArgumentException("invalid authority fact");
        }
        if (extraFacts.stream().noneMatch(f -> f.name().equals("required_profile")))
            extraFacts.add(new FactSpec("required_profile", List.of("native")));
        if (extraFacts.stream().anyMatch(f -> f.name().equals("agent_pubkey"))
                && !BiscuitFacts.ANCHORED_PROFILE.equals(firstValue(extraFacts, "required_profile")))
            throw new IllegalArgumentException("anchored key requires anchored profile");
        String sub = token.getSubject();
        if (sub == null || sub.isBlank()) {
            throw new MissingSubjectException();
        }

        if (sub.length() > 256 || !sub.equals(sub.trim()) || sub.chars().anyMatch(c -> c < 32))
            throw new IllegalArgumentException("invalid subject");
        long roleCount = realmRoles(token).size();
        if (token.getResourceAccess() != null) for (var access : token.getResourceAccess().values())
            if (access != null && access.getRoles() != null) roleCount += access.getRoles().size();
        if (roleCount > 128 || extraFacts.size() > 128) throw new IllegalArgumentException("authority fact limit exceeded");
        long jwtExp = (token.getExp() != null && token.getExp() > 0) ? token.getExp() : Long.MAX_VALUE;
        long ttlExp = saturatedAdd(now.getEpochSecond(), ttlSeconds);
        long exp = Math.min(Math.min(jwtExp, ttlExp), MAX_EXP_EPOCH_SECONDS);

        if (exp <= now.getEpochSecond()) throw new IllegalArgumentException("expired access token");
        org.biscuitsec.biscuit.token.builder.Biscuit builder =
                Biscuit.builder(RNG, rootKey);

        builder.add_authority_fact(Utils.fact("user", List.of(Utils.string(sub))));

        String azp = token.getIssuedFor();
        if (azp != null && !azp.isBlank()) {
            builder.add_authority_fact(Utils.fact("client", List.of(Utils.string(azp))));
        }

        String issuer = token.getIssuer();
        if (issuer != null && !issuer.isBlank()) {
            builder.add_authority_fact(Utils.fact("issuer", List.of(Utils.string(issuer))));
        }

        for (String role : realmRoles(token)) {
            builder.add_authority_fact(Utils.fact("realm_role", List.of(Utils.string(role))));
        }
        Map<String, AccessToken.Access> resourceAccess = token.getResourceAccess();
        if (resourceAccess != null) {
            for (Map.Entry<String, AccessToken.Access> entry : resourceAccess.entrySet()) {
                AccessToken.Access access = entry.getValue();
                if (access == null || access.getRoles() == null) {
                    continue;
                }
                for (String role : new LinkedHashSet<>(access.getRoles())) {
                    builder.add_authority_fact(Utils.fact("client_role",
                            List.of(Utils.string(entry.getKey()), Utils.string(role))));
                }
            }
        }

        // Faits supplémentaires déclarés en config : injectés via l'API programmatique
        // (Utils.string) comme les faits JWT, donc insensibles à toute injection datalog.
        if (extraFacts != null) {
            for (FactSpec fact : extraFacts) {
                if (fact.name().equals("budget_cap")) builder.add_authority_fact("budget_cap(" + Long.parseLong(fact.values().get(0)) + ")");
                else builder.add_authority_fact(Utils.fact(fact.name(), fact.values().stream().map(Utils::string).toList()));
            }
        }

        // Identifiant de clé : permet la rotation et la révocation par époque côté vérificateur.
        if (keyId != null && !keyId.isBlank()) {
            builder.add_authority_fact(Utils.fact("key_id", List.of(Utils.string(keyId))));
        }

        String jti = UUID.randomUUID().toString();
        builder.add_authority_fact(Utils.fact("jti", List.of(Utils.string(jti))));

        builder.add_authority_fact("expires_at(" + DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(exp)) + ")");
        builder.add_authority_check("check if time($t), $t < "
                + DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(exp)));

        Audit audit = new Audit(jti, keyId, sub, issuer,
                firstValue(extraFacts, "audience"), firstValue(extraFacts, "required_profile"), exp);
        String encoded = builder.build().serialize_b64url();
        if (encoded.length() > 16384) throw new IllegalArgumentException("minted token exceeds gateway size contract");
        return new MintResult(encoded, exp, audit);
    }

    /** Première valeur du fait nommé {@code name} parmi les faits supplémentaires, ou {@code null}. */
    private static String firstValue(List<FactSpec> facts, String name) {
        if (facts == null) {
            return null;
        }
        for (FactSpec fact : facts) {
            if (name.equals(fact.name()) && !fact.values().isEmpty()) {
                return fact.values().get(0);
            }
        }
        return null;
    }

    /** Rôles realm du JWT, dédupliqués, ordre stable. Les rôles client sont émis séparément (qualifiés par client). */
    static Set<String> realmRoles(AccessToken token) {
        Set<String> roles = new LinkedHashSet<>();
        AccessToken.Access realmAccess = token.getRealmAccess();
        if (realmAccess != null && realmAccess.getRoles() != null) {
            roles.addAll(realmAccess.getRoles());
        }
        return roles;
    }
}
