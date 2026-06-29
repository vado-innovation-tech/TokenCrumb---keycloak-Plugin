// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * REST endpoints mounted under {@code /realms/{realm}/biscuit}.
 *
 * <ul>
 *   <li>{@code POST /token}: exchanges a valid Keycloak access token (Bearer header)
 *       for a Biscuit signed by the realm's root key.</li>
 *   <li>{@code GET /public-key}: exposes the Ed25519 root public key (no auth).</li>
 * </ul>
 *
 * <p>Both endpoints are designed to be called from a browser (SPA, demo page) or a
 * gateway: they emit CORS headers and answer the {@code OPTIONS} preflight. Since
 * authentication uses the {@code Authorization: Bearer} header (not a cookie), the origin
 * can be allowed broadly without exposing any session.</p>
 */
public class BiscuitResource {

    private static final Logger LOG = Logger.getLogger(BiscuitResource.class);

    private final KeycloakSession session;
    private final BiscuitConfig config;

    public BiscuitResource(KeycloakSession session, BiscuitConfig config) {
        this.session = session;
        this.config = config;
    }

    /**
     * Exchanges a Keycloak access token for a Biscuit.
     *
     * <p>The body is <strong>optional</strong>: without it, behavior is unchanged, and an existing
     * client that posts an empty body is not broken. If present, it may carry only a single
     * key:</p>
     *
     * <pre>{@code {"agent_pubkey": "ed25519/<64 hex>"}}</pre>
     *
     * <p>Supplying this key requests anchoring: the issued mandate is bound to the holder of the matching
     * private key, and the issuer then enforces {@code required_profile("hardened_biscuit_anchored")}
     * (anchoring must force the profile, otherwise the extension would create a bypass instead of
     * closing one). A malformed key, a malformed JSON body or an unknown key in the object are rejected
     * with {@code 400} — never a silently unanchored exchange that the caller would believe to be
     * anchored.</p>
     *
     * <p>The response carries the token, its expiry (epoch seconds) and its revocation identifiers
     * (lowercase hex, authority block first).</p>
     */
    @POST
    @Path("token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(String body) {
        return guarded("Biscuit minting failed", () -> {
            RealmModel realm = session.getContext().getRealm();

            AuthenticationManager.AuthResult auth;
            try {
                // validates signature, expiry and active session; everything is taken from the request context
                auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
            } catch (NotAuthorizedException e) {
                auth = null;
            }
            if (auth == null) {
                BiscuitAudit.logDenied("rest", "invalid_token");
                return withCors(Response.status(Response.Status.UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer realm=\"" + realm.getName() + "\"")
                        .entity(Map.of("error", "invalid_token")));
            }
            List<BiscuitMinter.FactSpec> facts;
            try {
                facts = config.authorizedFacts(auth.getToken(), factsFor(body));
            } catch (InvalidRequestException e) {
                return error(Response.Status.BAD_REQUEST, e.code());
            }

            try {
                BiscuitKeyManager.RootKey rootKey = BiscuitKeyManager.rootKey(session, realm, config);
                BiscuitMinter.MintResult result =
                        BiscuitMinter.mint(auth.getToken(), rootKey.keyPair(), rootKey.keyId(),
                                config.ttlSeconds(), Instant.now(), facts);
                BiscuitAudit.logIssued("rest", realm.getName(), result.audit());
                return withCors(Response.ok(tokenResponse(result)));
            } catch (BiscuitMinter.MissingSubjectException e) {
                return error(Response.Status.BAD_REQUEST, "invalid_request");
            }
        });
    }

    @GET
    @Path("public-key")
    @Produces(MediaType.APPLICATION_JSON)
    public Response publicKey() {
        return guarded("Biscuit public key retrieval failed", () -> {
            RealmModel realm = session.getContext().getRealm();
            // allowGenerate=false: a GET must not provision a key (safe GET semantics)
            BiscuitKeyManager.RootKey rootKey = BiscuitKeyManager.rootKey(session, realm, config, false);
            return withCors(Response.ok(publicKeyResponse(rootKey)));
        });
    }

    /** Body of a successful {@code POST /token}. Package-private for tests. */
    static Map<String, Object> tokenResponse(BiscuitMinter.MintResult result) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("biscuit", result.biscuitB64());
        body.put("expires_at", result.expiresAt());
        // deny-list handles: the authority block's id also revokes every attenuated copy of the token
        body.put("revocation_ids", result.revocationIds());
        return body;
    }

    /** Body of {@code GET /public-key}. Package-private for tests. */
    static Map<String, Object> publicKeyResponse(BiscuitKeyManager.RootKey rootKey) {
        PublicKey publicKey = rootKey.keyPair().public_key();
        String hex = publicKey.toHex().toLowerCase(Locale.ROOT);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("algorithm", "ed25519");
        // kid: identifies the key/epoch; correlate with the Biscuit's key_id(...) fact
        body.put("kid", rootKey.keyId());
        // root_key_id: matches the token envelope's root_key_id, for root key selection before verification
        body.put("root_key_id", rootKey.rootKeyId());
        // standard text form, accepted as is by biscuit-cli and the other Biscuit libraries
        body.put("public_key", "ed25519/" + hex);
        body.put("public_key_hex", publicKey.toHex());
        body.put("public_key_base64", Base64.getEncoder().encodeToString(publicKey.toBytes()));
        return body;
    }

    /** CORS preflight for {@code POST /token}. */
    @OPTIONS
    @Path("token")
    public Response tokenPreflight() {
        if (!config.enabled()) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        return withCors(Response.noContent());
    }

    /** CORS preflight for {@code GET /public-key}. */
    @OPTIONS
    @Path("public-key")
    public Response publicKeyPreflight() {
        if (!config.enabled()) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        return withCors(Response.noContent());
    }

    /** Thrown when the request body is rejected; carries the error code returned to the client. */
    static final class InvalidRequestException extends RuntimeException {
        private final String code;

        InvalidRequestException(String code, String message) {
            super(message);
            this.code = code;
        }

        String code() {
            return code;
        }
    }

    /** Only key recognized in the body; any other key is rejected, never silently ignored. */
    private static final String AGENT_PUBKEY_KEY = "agent_pubkey";

    /**
     * Facts to inject for this exchange: those from the configuration, plus the anchoring requested
     * in the body, if any.
     *
     * <p>Package-private and static so it can be tested without mounting an endpoint.</p>
     */
    static List<BiscuitMinter.FactSpec> factsFor(String body, List<BiscuitMinter.FactSpec> configured) {
        if (body == null || body.isBlank()) {
            return configured;
        }
        JsonObject obj;
        try {
            JsonElement parsed = StrictJson.parse(body);
            if (!parsed.isJsonObject()) {
                throw new InvalidRequestException("invalid_request", "body is not a JSON object");
            }
            obj = parsed.getAsJsonObject();
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("invalid_request", "body is not valid JSON");
        }

        // An unknown key is refused rather than ignored: a caller who believes they asked for
        // something and gets a 200 without receiving it is the worst of both worlds.
        for (String key : obj.keySet()) {
            if (!AGENT_PUBKEY_KEY.equals(key)) {
                throw new InvalidRequestException("invalid_request", "unknown field: " + key);
            }
        }
        JsonElement value = obj.get(AGENT_PUBKEY_KEY);
        if (value == null) {
            return configured;
        }
        if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            throw new InvalidRequestException("invalid_agent_pubkey", "agent_pubkey must be a string");
        }
        return BiscuitFacts.requested(value.getAsString())
                .map(fact -> BiscuitFacts.anchored(configured, fact))
                .orElseThrow(() -> new InvalidRequestException(
                        "invalid_agent_pubkey", "agent_pubkey must be ed25519/<64 hex>"));
    }

    private List<BiscuitMinter.FactSpec> factsFor(String body) {
        return factsFor(body, config.extraFacts());
    }

    private Response error(Response.Status status, String code) {
        BiscuitAudit.logDenied("rest", code);
        return withCors(Response.status(status).entity(Map.of("error", code)));
    }

    /** Endpoint action that may throw a checked exception (e.g. biscuit-java's {@code Error}). */
    @FunctionalInterface
    private interface ResponseAction {
        Response run() throws Exception;
    }

    /**
     * Guards shared by the endpoints: extension disabled → {@code 404}, root key unavailable →
     * {@code 503}, unexpected error → {@code 500} (details in logs only, never to the client).
     */
    private Response guarded(String errorContext, ResponseAction action) {
        if (!config.enabled()) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        try {
            return action.run();
        } catch (BiscuitKeyManager.KeyResolutionException e) {
            LOG.error("Biscuit root key unavailable", e);
            return error(Response.Status.SERVICE_UNAVAILABLE, "biscuit_unavailable");
        } catch (Exception e) {
            LOG.error(errorContext, e);
            return error(Response.Status.INTERNAL_SERVER_ERROR, "internal_error");
        }
    }

    /**
     * Adds CORS headers to a response. The request origin is reflected if present
     * (otherwise {@code *}). No {@code Allow-Credentials}: auth goes through the Bearer header,
     * never a cookie, so browser calls use {@code credentials:'omit'}.
     */
    private Response withCors(Response.ResponseBuilder rb) {
        HttpHeaders headers = session.getContext().getRequestHeaders();
        String origin = headers != null ? headers.getHeaderString("Origin") : null;
        if (origin != null && !origin.isBlank()) {
            rb.header("Access-Control-Allow-Origin", origin);
            rb.header("Vary", "Origin");
        } else {
            rb.header("Access-Control-Allow-Origin", "*");
        }
        rb.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        rb.header("Access-Control-Allow-Headers", "authorization, content-type");
        rb.header("Access-Control-Max-Age", "3600");
        return rb.build();
    }
}
