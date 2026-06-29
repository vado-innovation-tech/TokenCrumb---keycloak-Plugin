// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jboss.logging.Logger;
import org.keycloak.Config;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Configuration de l'extension, lue depuis les variables d'environnement.
 *
 * <ul>
 *   <li>{@code BISCUIT_ENABLED} (défaut {@code true})</li>
 *   <li>{@code BISCUIT_TOKEN_TTL} en secondes (défaut {@code 300})</li>
 *   <li>{@code BISCUIT_KEY_STRATEGY} : {@code auto} | {@code realm} | {@code generated} (défaut {@code auto})</li>
 *   <li>{@code BISCUIT_KEY_ENCRYPTION_KEY} : clé AES-256 (64 hex ou base64 de 32 octets), optionnelle</li>
 * </ul>
 */
public final class BiscuitConfig {

    private static final Logger LOG = Logger.getLogger(BiscuitConfig.class);

    public static final long DEFAULT_TTL_SECONDS = 300L;

    /** Borne anti-débordement (~10 ans) : au-delà, l'expiration dépasserait les dates formatables. */
    public static final long MAX_TTL_SECONDS = 315_360_000L;

    public enum KeyStrategy { AUTO, REALM, GENERATED }

    private final boolean enabled;
    private final long ttlSeconds;
    private final KeyStrategy keyStrategy;
    private final String realmKeyKid;
    private final byte[] encryptionKey;
    private final boolean encryptionKeyInvalid;
    private final List<BiscuitMinter.FactSpec> extraFacts;

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
     * Résout la configuration depuis le {@link Config.Scope} Keycloak
     * (options {@code --spi-realm-restapi-extension-biscuit-*} / {@code KC_SPI_*}) avec repli sur les
     * variables d'environnement {@code BISCUIT_*} historiques.
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
        return from(merged);
    }

    /** Valeur du Config.Scope si présente et non blanche, sinon variable d'environnement. */
    private static String resolve(Config.Scope scope, String scopeKey, Map<String, String> env, String envVar) {
        String v = scope != null ? scope.get(scopeKey) : null;
        return (v != null && !v.isBlank()) ? v : env.get(envVar);
    }

    static BiscuitConfig from(Map<String, String> env) {
        boolean enabled = parseEnabled(env.get("BISCUIT_ENABLED"));
        long ttl = parseTtl(env.get("BISCUIT_TOKEN_TTL"));
        KeyStrategy strategy = parseStrategy(env.get("BISCUIT_KEY_STRATEGY"));
        String realmKeyKid = parseRealmKeyKid(env.get("BISCUIT_REALM_KEY_KID"));

        byte[] kek = null;
        boolean kekInvalid = false;
        String rawKek = env.get("BISCUIT_KEY_ENCRYPTION_KEY");
        if (rawKek != null && !rawKek.isBlank()) {
            kek = parseKek(rawKek.trim());
            if (kek == null) {
                kekInvalid = true;
                LOG.error("BISCUIT_KEY_ENCRYPTION_KEY is set but malformed (expected 64 hex chars or "
                        + "base64 of 32 bytes); refusing to persist any NEW root key until fixed");
            }
        }
        List<BiscuitMinter.FactSpec> extraFacts = parseExtraFacts(env.get("BISCUIT_EXTRA_FACTS"));
        return new BiscuitConfig(enabled, ttl, strategy, realmKeyKid, kek, kekInvalid, extraFacts);
    }

    private static boolean parseEnabled(String raw) {
        if (raw == null || raw.isBlank()) {
            return true;
        }
        String v = raw.trim().toLowerCase(Locale.ROOT);
        return !(v.equals("false") || v.equals("0") || v.equals("no") || v.equals("off"));
    }

    private static long parseTtl(String raw) {
        if (raw == null || raw.isBlank()) {
            return DEFAULT_TTL_SECONDS;
        }
        try {
            long ttl = Long.parseLong(raw.trim());
            if (ttl <= 0) {
                LOG.warnf("BISCUIT_TOKEN_TTL=%s is not a positive number, using default %d", raw, DEFAULT_TTL_SECONDS);
                return DEFAULT_TTL_SECONDS;
            }
            if (ttl > MAX_TTL_SECONDS) {
                LOG.warnf("BISCUIT_TOKEN_TTL=%s exceeds the maximum of %d seconds, clamping", raw, MAX_TTL_SECONDS);
                return MAX_TTL_SECONDS;
            }
            return ttl;
        } catch (NumberFormatException e) {
            LOG.warnf("BISCUIT_TOKEN_TTL=%s is not a number, using default %d", raw, DEFAULT_TTL_SECONDS);
            return DEFAULT_TTL_SECONDS;
        }
    }

    private static KeyStrategy parseStrategy(String raw) {
        if (raw == null || raw.isBlank()) {
            return KeyStrategy.AUTO;
        }
        try {
            return KeyStrategy.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            LOG.warnf("BISCUIT_KEY_STRATEGY=%s is unknown (expected auto|realm|generated), using auto", raw);
            return KeyStrategy.AUTO;
        }
    }

    /** kid (trim) de la clé EdDSA du realm à dédier au Biscuit, ou null si non défini/blanc. */
    private static String parseRealmKeyKid(String raw) {
        return (raw == null || raw.isBlank()) ? null : raw.trim();
    }

    /** Accepte 64 caractères hex ou du base64 décodant exactement 32 octets ; null si malformée. */
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

    /**
     * Parse {@code BISCUIT_EXTRA_FACTS} : un tableau JSON d'objets {@code {"name": ..., "values": [...]}}.
     * Émetteur générique : aucune sémantique n'est imposée, seuls la validité du nom et les noms
     * réservés sont contrôlés. Tout fait invalide est ignoré (WARN) ; un JSON illisible donne une
     * liste vide — l'émission ne doit jamais échouer à cause de la config de faits.
     */
    static List<BiscuitMinter.FactSpec> parseExtraFacts(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<BiscuitMinter.FactSpec> facts = new ArrayList<>();
        try {
            JsonElement root = JsonParser.parseString(raw);
            if (!root.isJsonArray()) {
                LOG.warnf("BISCUIT_EXTRA_FACTS must be a JSON array, ignoring (got: %s)",
                        root.getClass().getSimpleName());
                return List.of();
            }
            for (JsonElement element : root.getAsJsonArray()) {
                BiscuitMinter.FactSpec fact = parseFact(element);
                if (fact != null) {
                    facts.add(fact);
                }
            }
        } catch (RuntimeException e) {
            LOG.warnf("BISCUIT_EXTRA_FACTS is not valid JSON, ignoring all extra facts: %s", e.getMessage());
            return List.of();
        }
        return facts;
    }

    /** Valide et convertit un élément du tableau en fait ; null (avec WARN) si invalide. */
    private static BiscuitMinter.FactSpec parseFact(JsonElement element) {
        if (!element.isJsonObject()) {
            LOG.warnf("BISCUIT_EXTRA_FACTS: skipping non-object entry %s", element);
            return null;
        }
        JsonObject obj = element.getAsJsonObject();
        JsonElement nameEl = obj.get("name");
        if (nameEl == null || !nameEl.isJsonPrimitive()) {
            LOG.warnf("BISCUIT_EXTRA_FACTS: skipping entry without a string 'name': %s", obj);
            return null;
        }
        String name = nameEl.getAsString();
        List<String> values = new ArrayList<>();
        JsonElement valuesEl = obj.get("values");
        if (valuesEl != null) {
            if (!valuesEl.isJsonArray()) {
                LOG.warnf("BISCUIT_EXTRA_FACTS: 'values' must be an array for fact '%s', skipping", name);
                return null;
            }
            for (JsonElement v : valuesEl.getAsJsonArray()) {
                if (!v.isJsonPrimitive()) {
                    LOG.warnf("BISCUIT_EXTRA_FACTS: skipping fact '%s' with non-scalar value %s", name, v);
                    return null;
                }
                values.add(v.getAsString());
            }
        }
        // BISCUIT_EXTRA_FACTS est une config déployeur de confiance (env/SPI lue au démarrage) :
        // voie gouvernée, elle peut poser audience/required_profile mais jamais un fait cœur.
        return BiscuitFacts.governed(name, values).orElse(null);
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

    /** kid de la clé EdDSA du realm à dédier au Biscuit (stratégies {@code realm}/{@code auto}), ou null si non épinglée. */
    public String realmKeyKid() {
        return realmKeyKid;
    }

    /** Clé AES-256 de chiffrement de la seed persistée (copie défensive), ou null si non configurée. */
    public byte[] encryptionKey() {
        return encryptionKey == null ? null : encryptionKey.clone();
    }

    /** true si la variable est définie mais inutilisable : interdit de persister une nouvelle clé. */
    public boolean encryptionKeyInvalid() {
        return encryptionKeyInvalid;
    }

    /** Faits supplémentaires (validés) à injecter dans chaque Biscuit émis ; vide par défaut. */
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
