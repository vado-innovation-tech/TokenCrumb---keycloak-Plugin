// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;
import java.util.*;
import com.google.gson.*;
import org.keycloak.representations.AccessToken;

/** Explicit role-to-right mapping from the authenticated JWT. No user-editable attributes. */
final class RoleRights {
    record Grant(String role, String client, String tool, String operation) {}
    static List<Grant> parse(String raw) {
        if (raw == null) return List.of();
        JsonElement root = StrictJson.parse(raw);
        if (!root.isJsonArray()) throw new IllegalArgumentException("role rights must be an array");
        List<Grant> out = new ArrayList<>();
        for (JsonElement value : root.getAsJsonArray()) {
            if (!value.isJsonObject()) throw new IllegalArgumentException("invalid role right");
            JsonObject o = value.getAsJsonObject();
            if (!Set.of("role", "tool", "operation", "client").containsAll(o.keySet())) throw new IllegalArgumentException("unknown grant field");
            out.add(new Grant(text(o,"role"), o.has("client") ? text(o,"client") : null, text(o,"tool"), text(o,"operation")));
        }
        return List.copyOf(out);
    }
    private static String text(JsonObject o, String field) {
        JsonElement v = o.get(field);
        if (v == null || !v.isJsonPrimitive() || !v.getAsJsonPrimitive().isString()
            || v.getAsString().isBlank() || !v.getAsString().equals(v.getAsString().trim())) throw new IllegalArgumentException("invalid grant field");
        return v.getAsString();
    }
    static List<BiscuitMinter.FactSpec> apply(AccessToken token, List<BiscuitMinter.FactSpec> facts, List<Grant> grants, boolean staticMode) {
        List<BiscuitMinter.FactSpec> out = new ArrayList<>();
        for (var fact : facts) if (!fact.name().equals("rights_source") && (staticMode || !fact.name().equals("right"))) out.add(fact);
        if (!staticMode) for (Grant grant : grants) {
            var access = grant.client() == null ? token.getRealmAccess() : token.getResourceAccess(grant.client());
            if (access != null && access.isUserInRole(grant.role())) out.add(new BiscuitMinter.FactSpec("right", List.of(grant.tool(), grant.operation())));
        }
        out.add(new BiscuitMinter.FactSpec("rights_source", List.of(staticMode ? "static_deployer" : "jwt_roles")));
        return out;
    }
}
