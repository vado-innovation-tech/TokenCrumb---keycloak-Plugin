// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.keycloak.Config;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Extension configuration, read from the Keycloak {@code Config.Scope}, falling back to environment
 * variables.
 *
 * <ul>
 *   <li>{@code BISCUIT_ENABLED} (default {@code true})</li>
 *   <li>{@code BISCUIT_TOKEN_TTL} in seconds (default {@code 300})</li>
 *   <li>{@code BISCUIT_KEY_STRATEGY}: {@code generated} (default) | {@code realm} | {@code auto} (alias for {@code generated})</li>
 *   <li>{@code BISCUIT_KEY_ENCRYPTION_KEY}: AES-256 key (64 hex or base64 of 32 bytes), optional</li>
 * </ul>
 */
public final class BiscuitConfig {

    public static final long DEFAULT_TTL_SECONDS = 300L;

    /** Upper bound of the accepted TTL (~10 years): the TTL must be between 1 and this value; other values are rejected. */
    public static final long MAX_TTL_SECONDS = 315_360_000L;

    public enum KeyStrategy { AUTO, REALM, GENERATED }

    private final boolean enabled;
    private final long ttlSeconds;
    private final KeyStrategy keyStrategy;
    private final String realmKeyKid;
    private final byte[] encryptionKey;
    private final boolean encryptionKeyInvalid;
    private final List<BiscuitMinter.FactSpec> extraFacts;
    private List<RoleRights.Grant> roleRights = List.of();
    private boolean staticRights;
    private boolean bootstrap;
    public boolean bootstrap() { return bootstrap; }
    public List<BiscuitMinter.FactSpec> authorizedFacts(org.keycloak.representations.AccessToken token,
                                                      List<BiscuitMinter.FactSpec> configured) {
        return RoleRights.apply(token, configured, roleRights, staticRights);
    }

    private BiscuitConfig(boolean enabled, long ttlSeconds, KeyStrategy keyStrategy, String realmKeyKid,
                          byte[] encryptionKey, boolean encryptionKeyInvalid,
                          List<BiscuitMinter.FactSpec> extraFacts) {
        this.enabled = enabled;
        this.ttlSeconds = ttlSeconds;
        this.keyStrategy = keyStrategy;
        this.realmKeyKid = realmKeyKid;
        this.encryptionKey = encryptionKey == null ? null : encryptionKey.clone();
        this.encryptionKeyInvalid = encryptionKeyInvalid;
        this.extraFacts = List.copyOf(extraFacts);
    }

    public static BiscuitConfig fromEnv() {
        return from(System.getenv());
    }

    /**
     * Resolves the configuration from the calling provider's Keycloak {@link Config.Scope}, falling back
     * to the {@code BISCUIT_*} environment variables. Each provider has its own scope
     * ({@code --spi-realm-restapi-extension--biscuit--*} for the REST endpoint,
     * {@code --spi-protocol-mapper--oidc-biscuit-mapper--*} for the mapper), so only the environment
     * variables are shared by both issuance paths.
     */
    public static BiscuitConfig fromScope(Config.Scope scope) {
        Map<String, String> env = System.getenv();
        Map<String, String> merged = new HashMap<>();
        merged.put("BISCUIT_ENABLED", resolve(scope, "enabled", env, "BISCUIT_ENABLED"));
        merged.put("BISCUIT_TOKEN_TTL", resolve(scope, "token-ttl", env, "BISCUIT_TOKEN_TTL"));
        merged.put("BISCUIT_KEY_STRATEGY", resolve(scope, "key-strategy", env, "BISCUIT_KEY_STRATEGY"));
        merged.put("BISCUIT_REALM_KEY_KID", resolve(scope, "realm-key-kid", env, "BISCUIT_REALM_KEY_KID"));
        merged.put("BISCUIT_KEY_ENCRYPTION_KEY", resolve(scope, "key-encryption-key", env, "BISCUIT_KEY_ENCRYPTION_KEY"));
        merged.put("BISCUIT_EXTRA_FACTS", resolve(scope, "extra-facts", env, "BISCUIT_EXTRA_FACTS"));
        merged.put("BISCUIT_ROLE_RIGHTS", resolve(scope, "role-rights", env, "BISCUIT_ROLE_RIGHTS"));
        merged.put("BISCUIT_RIGHTS_MODE", resolve(scope, "rights-mode", env, "BISCUIT_RIGHTS_MODE"));
        merged.put("BISCUIT_ALLOW_KEY_BOOTSTRAP", resolve(scope, "allow-key-bootstrap", env, "BISCUIT_ALLOW_KEY_BOOTSTRAP"));
        return from(merged);
    }

    /** Config.Scope value if present and non-blank, otherwise the environment variable. */
    private static String resolve(Config.Scope scope, String scopeKey, Map<String, String> env, String envVar) {
        String v = scope != null ? scope.get(scopeKey) : null;
        return v != null ? v : env.get(envVar);
    }

    static BiscuitConfig from(Map<String, String> env) {
        boolean enabled = parseEnabled(env.get("BISCUIT_ENABLED"));
        long ttl = parseTtl(env.get("BISCUIT_TOKEN_TTL"));
        KeyStrategy strategy = parseStrategy(env.get("BISCUIT_KEY_STRATEGY"));
        String realmKeyKid = parseRealmKeyKid(env.get("BISCUIT_REALM_KEY_KID"));

        byte[] kek = null;
        boolean kekInvalid = false;
        String rawKek = env.get("BISCUIT_KEY_ENCRYPTION_KEY");
        if (rawKek != null) {
            kek = parseKek(rawKek.trim());
            if (kek == null) {
                throw new IllegalArgumentException("BISCUIT_KEY_ENCRYPTION_KEY must encode 32 bytes");
            }
        }
        List<BiscuitMinter.FactSpec> extraFacts = parseExtraFacts(env.get("BISCUIT_EXTRA_FACTS"));
        BiscuitConfig result = new BiscuitConfig(enabled, ttl, strategy, realmKeyKid, kek, kekInvalid, extraFacts);
        result.roleRights = RoleRights.parse(env.get("BISCUIT_ROLE_RIGHTS"));
        String mode = env.getOrDefault("BISCUIT_RIGHTS_MODE", "roles");
        if (mode == null) mode = "roles";
        if (!mode.equals("roles") && !mode.equals("static")) throw new IllegalArgumentException("unknown rights mode");
        result.staticRights = mode.equals("static");
        String bootstrap = env.get("BISCUIT_ALLOW_KEY_BOOTSTRAP");
        result.bootstrap = bootstrap != null && parseEnabled(bootstrap);
        return result;
    }

    private static boolean parseEnabled(String raw) {
        if (raw == null) return true;
        return switch (raw.trim().toLowerCase(Locale.ROOT)) {
            case "true", "1", "yes", "on" -> true;
            case "false", "0", "no", "off" -> false;
            default -> throw new IllegalArgumentException("invalid boolean configuration");
        };
    }
    private static long parseTtl(String raw) {
        if (raw == null) return DEFAULT_TTL_SECONDS;
        long value = Long.parseLong(raw.trim());
        if (value <= 0 || value > MAX_TTL_SECONDS) throw new IllegalArgumentException("TTL outside supported range");
        return value;
    }
    private static KeyStrategy parseStrategy(String raw) {
        return raw == null ? KeyStrategy.GENERATED : KeyStrategy.valueOf(raw.trim().toUpperCase(Locale.ROOT));
    }

    /** kid (trimmed) of the realm EdDSA key dedicated to Biscuit, or null if unset/blank. */
    private static String parseRealmKeyKid(String raw) {
        return (raw == null || raw.isBlank()) ? null : raw.trim();
    }

    /** Accepts 64 hex characters or base64 decoding to exactly 32 bytes; null if malformed. */
    private static byte[] parseKek(String raw) {
        if (raw.matches("[0-9a-fA-F]{64}")) {
            byte[] out = new byte[32];
            for (int i = 0; i < 32; i++) {
                out[i] = (byte) Integer.parseInt(raw.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(raw);
            return decoded.length == 32 ? decoded : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Parses the fact configuration: strict schema, types and uniqueness.
     * Any error rejects the whole configuration, so no constraint is silently dropped. */
    static List<BiscuitMinter.FactSpec> parseExtraFacts(String raw) {
        if (raw == null) return List.of();
        JsonElement root = StrictJson.parse(raw);
        if (!root.isJsonArray()) throw new IllegalArgumentException("extra facts must be an array");
        List<BiscuitMinter.FactSpec> facts = new ArrayList<>();
        for (JsonElement e : root.getAsJsonArray()) {
            if (!e.isJsonObject()) throw new IllegalArgumentException("fact must be an object");
            JsonObject o = e.getAsJsonObject();
            if (!o.keySet().equals(java.util.Set.of("name", "values")) || !o.get("name").isJsonPrimitive()
                    || !o.getAsJsonPrimitive("name").isString() || !o.get("values").isJsonArray())
                throw new IllegalArgumentException("invalid fact schema");
            String name = o.get("name").getAsString();
            List<String> values = new ArrayList<>();
            for (JsonElement value : o.getAsJsonArray("values")) {
                if (!value.isJsonPrimitive() || (!name.equals("budget_cap") && !value.getAsJsonPrimitive().isString())
                        || (name.equals("budget_cap") && !value.getAsJsonPrimitive().isNumber()))
                    throw new IllegalArgumentException("invalid fact value type");
                values.add(value.getAsString());
            }
            facts.add(BiscuitFacts.governed(name, values).orElseThrow(() -> new IllegalArgumentException("invalid fact")));
        }
        BiscuitFacts.checkUnique(facts);
        return List.copyOf(facts);
    }

    public boolean enabled() {
        return enabled;
    }

    public long ttlSeconds() {
        return ttlSeconds;
    }

    public KeyStrategy keyStrategy() {
        return keyStrategy;
    }

    /** kid of the realm EdDSA key dedicated to Biscuit ({@code realm} strategy), or null if not pinned. */
    public String realmKeyKid() {
        return realmKeyKid;
    }

    /** AES-256 key encrypting the persisted seed (defensive copy), or null if not configured. */
    public byte[] encryptionKey() {
        return encryptionKey == null ? null : encryptionKey.clone();
    }

    /** true if the variable is set but unusable: persisting a new key is forbidden. */
    public boolean encryptionKeyInvalid() {
        return encryptionKeyInvalid;
    }

    /** (Validated) extra facts to inject into every issued Biscuit; empty by default. */
    public List<BiscuitMinter.FactSpec> extraFacts() {
        return extraFacts;
    }

    @Override
    public String toString() {
        return "BiscuitConfig{enabled=" + enabled + ", ttlSeconds=" + ttlSeconds
                + ", keyStrategy=" + keyStrategy
                + ", realmKeyKid=" + (realmKeyKid != null ? realmKeyKid : "unset")
                + ", encryptionKey=" + (encryptionKey != null ? "set" : "unset")
                + (encryptionKeyInvalid ? " (INVALID)" : "")
                + ", extraFacts=" + extraFacts.size() + "}";
    }
}
