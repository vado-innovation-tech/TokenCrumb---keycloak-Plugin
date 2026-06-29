// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.biscuitsec.biscuit.crypto.KeyPair;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.biscuitsec.biscuit.token.builder.Utils;
import org.keycloak.representations.AccessToken;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Pure logic for minting a Biscuit from the claims of a Keycloak access token.
 * Has no dependency on KeycloakSession, so it can be unit-tested.
 *
 * Authority block produced:
 * <pre>
 *   user("&lt;sub&gt;");
 *   client("&lt;azp&gt;");                       // if present in the JWT
 *   issuer("&lt;iss&gt;");                       // JWT iss claim (if present)
 *   realm_role("&lt;r&gt;");                     // one per realm role
 *   client_role("&lt;clientId&gt;", "&lt;r&gt;");      // one per client role, qualified by the client
 *   audience("&lt;aud&gt;");                     // governed facts, when configured
 *   required_profile("&lt;profile&gt;");         // always present: "native" unless configured or anchored
 *   agent_pubkey("ed25519/&lt;hex&gt;");          // anchored exchanges only
 *   budget_cap(&lt;integer&gt;);                 // when configured
 *   right("&lt;tool&gt;", "&lt;operation&gt;");       // one per granted right (role mapping or static mode)
 *   rights_source("jwt_roles" | "static_deployer");
 *   &lt;extra facts&gt;;                           // other facts declared in config (e.g. tenant_id)
 *   key_id("&lt;kid&gt;");                       // root key identifier (if provided), informational
 *   jti("&lt;uuid&gt;");                         // unique Biscuit identifier (application denylist)
 *   expires_at(&lt;exp&gt;);                     // exp = min(JWT exp, now + ttl), as a Datalog date
 *   check if time($t), $t &lt; &lt;exp&gt;;
 * </pre>
 *
 * The token envelope also carries a {@code root_key_id} ({@link #rootKeyId}), which authorizers use
 * to select the root public key before verifying the signature; the {@code key_id} fact is only
 * readable once the signature has been verified.
 *
 * The issuer stays generic: it has no knowledge of application semantics (agent, MCP…).
 * Extra facts are plain {@link FactSpec}s supplied by configuration
 * ({@code BISCUIT_EXTRA_FACTS}); a deployment that declares none produces exactly
 * the JWT facts above, plus {@code required_profile("native")} and {@code rights_source}.
 *
 * Security: values taken from claims (sub, azp, roles) as well as extra-fact values go
 * through the programmatic fact API (never concatenated into Datalog source), which
 * neutralizes any injection. Only the expiry check — built from a locally computed
 * timestamp — is written as Datalog source.
 */
public final class BiscuitMinter {

    /** 9999-12-31T23:59:59Z: maximum value formattable by {@link DateTimeFormatter#ISO_INSTANT}. */
    private static final long MAX_EXP_EPOCH_SECONDS = 253_402_300_799L;

    /** Shared (thread-safe) SecureRandom: avoids costly reseeding on every mint. */
    private static final SecureRandom RNG = new SecureRandom();

    private BiscuitMinter() {
    }

    /** Addition that saturates at {@link Long#MAX_VALUE} instead of overflowing into negatives. */
    private static long saturatedAdd(long a, long b) {
        long r = a + b;
        return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
    }

    /**
     * @param revocationIds revocation identifiers of the minted token (lowercase hex), authority
     *                      block first
     */
    public record MintResult(String biscuitB64, long expiresAt, List<String> revocationIds, Audit audit) {
        public MintResult {
            revocationIds = List.copyOf(revocationIds);
        }
    }

    /**
     * Issuance summary for the {@code capability_issued} audit. Pure data:
     * callers ({@link BiscuitResource}, {@link BiscuitProtocolMapper}) emit a log line from it.
     * Absent fields are {@code null}. {@code capabilityId} = the issued {@code jti};
     * {@code revocationId} = the authority block's revocation identifier (lowercase hex).
     */
    public record Audit(String capabilityId, String keyId, String revocationId, String subject, String issuer,
                        String audience, String requiredProfile, long expiresAt) {
    }

    /**
     * Extra fact to inject into the authority block, declared in configuration.
     * The name is a Datalog predicate; each value becomes a string literal.
     * The value list is copied to guarantee immutability.
     */
    public record FactSpec(String name, List<String> values) {
        public FactSpec {
            values = List.copyOf(values);
        }
    }

    /** The JWT carries no {@code sub} claim: the exchange cannot proceed because the user fact is mandatory. */
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
     * Root key identifier carried in the token envelope ({@code root_key_id}): the first 4 bytes of
     * SHA-256 over the raw 32-byte Ed25519 public key, read big-endian and masked to 31 bits so the
     * value is a non-negative {@code int}. Deterministic, stable across restarts, and changes with the key.
     */
    public static int rootKeyId(PublicKey publicKey) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.toBytes());
            return ByteBuffer.wrap(digest, 0, 4).getInt() & 0x7fffffff;
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed by the Java platform
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Canonical overload: {@code keyId} (the root key identifier) is issued as an informational
     * {@code key_id(...)} fact in the authority block (unless {@code null}/blank) and included in
     * the {@link Audit}. The envelope's {@code root_key_id} ({@link #rootKeyId}) is always set.
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
        builder.set_root_key_id(rootKeyId(rootKey.public_key()));

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

        // Extra facts declared in config: injected through the programmatic API
        // (Utils.string) like the JWT facts, hence immune to any Datalog injection.
        if (extraFacts != null) {
            for (FactSpec fact : extraFacts) {
                if (fact.name().equals("budget_cap")) {
                    builder.add_authority_fact(Utils.fact("budget_cap",
                            List.of(Utils.integer(Long.parseLong(fact.values().get(0))))));
                } else {
                    builder.add_authority_fact(Utils.fact(fact.name(),
                            fact.values().stream().map(Utils::string).toList()));
                }
            }
        }

        // Key identifier (informational: authorizers select the root key through the envelope's
        // root_key_id, since a fact is only readable after signature verification).
        if (keyId != null && !keyId.isBlank()) {
            builder.add_authority_fact(Utils.fact("key_id", List.of(Utils.string(keyId))));
        }

        String jti = UUID.randomUUID().toString();
        builder.add_authority_fact(Utils.fact("jti", List.of(Utils.string(jti))));

        builder.add_authority_fact(Utils.fact("expires_at",
                List.of(Utils.date(Date.from(Instant.ofEpochSecond(exp))))));
        builder.add_authority_check("check if time($t), $t < "
                + DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(exp)));

        Biscuit biscuit = builder.build();
        String encoded = biscuit.serialize_b64url();
        if (encoded.length() > 16384) throw new IllegalArgumentException("minted token exceeds the gateway size limit");
        List<String> revocationIds = biscuit.revocation_identifiers().stream()
                .map(id -> id.toHex().toLowerCase(Locale.ROOT)).toList();
        Audit audit = new Audit(jti, keyId, revocationIds.get(0), sub, issuer,
                firstValue(extraFacts, "audience"), firstValue(extraFacts, "required_profile"), exp);
        return new MintResult(encoded, exp, revocationIds, audit);
    }

    /** First value of the fact named {@code name} among the extra facts, or {@code null}. */
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

    /**
     * Realm roles from the JWT, deduplicated, stable order. Client roles are issued separately
     * (qualified by client).
     */
    static Set<String> realmRoles(AccessToken token) {
        Set<String> roles = new LinkedHashSet<>();
        AccessToken.Access realmAccess = token.getRealmAccess();
        if (realmAccess != null && realmAccess.getRoles() != null) {
            roles.addAll(realmAccess.getRoles());
        }
        return roles;
    }
}
