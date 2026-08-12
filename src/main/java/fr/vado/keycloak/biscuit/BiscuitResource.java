// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
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
import java.util.List;
import java.util.Map;

/**
 * Endpoints REST montés sous {@code /realms/{realm}/biscuit}.
 *
 * <ul>
 *   <li>{@code POST /token} : échange un access token Keycloak valide (header Bearer)
 *       contre un Biscuit signé par la clé racine du realm.</li>
 *   <li>{@code GET /public-key} : expose la clé publique racine Ed25519 (sans auth).</li>
 * </ul>
 *
 * <p>Les deux endpoints sont pensés pour être appelés depuis un navigateur (SPA, page de
 * démo) ou une gateway : ils émettent les en-têtes CORS et répondent au préflight
 * {@code OPTIONS}. Comme l'authentification se fait par header {@code Authorization: Bearer}
 * (et non par cookie), l'origine peut être autorisée largement sans exposer de session.</p>
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
     * Échange un access token Keycloak contre un Biscuit.
     *
     * <p>Le corps est <strong>facultatif</strong> : sans lui, le comportement est celui d'avant, et
     * un client existant qui poste sans rien n'est pas cassé. S'il est présent, il ne peut porter
     * qu'une seule clé :</p>
     *
     * <pre>{@code {"agent_pubkey": "ed25519/<64 hex>"}}</pre>
     *
     * <p>Fournir cette clé demande un ancrage : le mandat émis est lié au détenteur de la clé privée
     * correspondante, et l'émetteur impose alors {@code required_profile("hardened_biscuit_anchored")}
     * (ADR-0003 du dépôt {@code MCPproxy} : l'ancrage doit forcer le profil, sinon il ouvre un
     * contournement). Une clé mal formée, un corps illisible ou une clé inconnue dans l'objet sont des
     * {@code 400} — jamais un échange silencieusement non ancré, que l'appelant croirait de profil 3b.</p>
     */
    @POST
    @Path("token")
    @Produces(MediaType.APPLICATION_JSON)
    public Response token(String body) {
        return guarded("Biscuit minting failed", () -> {
            RealmModel realm = session.getContext().getRealm();

            AuthenticationManager.AuthResult auth;
            try {
                // valide signature, expiration et session active ; tout est pris du contexte de requête
                auth = new AppAuthManager.BearerTokenAuthenticator(session).authenticate();
            } catch (NotAuthorizedException e) {
                auth = null;
            }
            if (auth == null) {
                return withCors(Response.status(Response.Status.UNAUTHORIZED)
                        .header("WWW-Authenticate", "Bearer realm=\"" + realm.getName() + "\"")
                        .entity(Map.of("error", "invalid_token")));
            }
            List<BiscuitMinter.FactSpec> facts;
            try {
                facts = factsFor(body);
            } catch (InvalidRequestException e) {
                return error(Response.Status.BAD_REQUEST, e.code());
            }

            try {
                BiscuitKeyManager.RootKey rootKey = BiscuitKeyManager.rootKey(session, realm, config);
                BiscuitMinter.MintResult result =
                        BiscuitMinter.mint(auth.getToken(), rootKey.keyPair(), rootKey.keyId(),
                                config.ttlSeconds(), Instant.now(), facts);
                BiscuitAudit.logIssued("rest", realm.getName(), result.audit());
                return withCors(Response.ok(Map.of(
                        "biscuit", result.biscuitB64(),
                        "expires_at", result.expiresAt()
                )));
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
            // allowGenerate=false : un GET ne doit pas provisionner de clé (sémantique GET safe)
            BiscuitKeyManager.RootKey rootKey = BiscuitKeyManager.rootKey(session, realm, config, false);
            PublicKey publicKey = rootKey.keyPair().public_key();
            return withCors(Response.ok(Map.of(
                    "algorithm", "ed25519",
                    // kid : identifie la clé/époque ; à corréler au fait key_id(...) du Biscuit
                    "kid", rootKey.keyId(),
                    "public_key_hex", publicKey.toHex(),
                    "public_key_base64", Base64.getEncoder().encodeToString(publicKey.toBytes())
            )));
        });
    }

    /** Préflight CORS pour {@code POST /token}. */
    @OPTIONS
    @Path("token")
    public Response tokenPreflight() {
        if (!config.enabled()) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        return withCors(Response.noContent());
    }

    /** Préflight CORS pour {@code GET /public-key}. */
    @OPTIONS
    @Path("public-key")
    public Response publicKeyPreflight() {
        if (!config.enabled()) {
            return error(Response.Status.NOT_FOUND, "not_found");
        }
        return withCors(Response.noContent());
    }

    /** Le corps de la requête est refusable : porte le code d'erreur rendu au client. */
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

    /** Seule clé reconnue dans le corps ; toute autre est un refus, pas un silence. */
    private static final String AGENT_PUBKEY_KEY = "agent_pubkey";

    /**
     * Faits à injecter pour cet échange : ceux de la configuration, éventuellement complétés par
     * un ancrage demandé dans le corps.
     *
     * <p>Package-private et statique pour être testable sans monter un endpoint.</p>
     */
    static List<BiscuitMinter.FactSpec> factsFor(String body, List<BiscuitMinter.FactSpec> configured) {
        if (body == null || body.isBlank()) {
            return configured;
        }
        JsonObject obj;
        try {
            JsonElement parsed = JsonParser.parseString(body);
            if (!parsed.isJsonObject()) {
                throw new InvalidRequestException("invalid_request", "body is not a JSON object");
            }
            obj = parsed.getAsJsonObject();
        } catch (JsonSyntaxException e) {
            throw new InvalidRequestException("invalid_request", "body is not valid JSON");
        }

        // Une clé inconnue est refusée plutôt qu'ignorée : un appelant qui croit avoir demandé
        // quelque chose et reçoit 200 sans l'avoir obtenu est le pire des deux mondes.
        for (String key : obj.keySet()) {
            if (!AGENT_PUBKEY_KEY.equals(key)) {
                throw new InvalidRequestException("invalid_request", "unknown field: " + key);
            }
        }
        JsonElement value = obj.get(AGENT_PUBKEY_KEY);
        if (value == null || value.isJsonNull()) {
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
        return withCors(Response.status(status).entity(Map.of("error", code)));
    }

    /** Action d'endpoint pouvant lever une exception vérifiée (ex. {@code Error} de biscuit-java). */
    @FunctionalInterface
    private interface ResponseAction {
        Response run() throws Exception;
    }

    /**
     * Gardes communes aux endpoints : extension désactivée → {@code 404}, clé racine indisponible →
     * {@code 503}, erreur inattendue → {@code 500} (détail en logs uniquement, jamais au client).
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
     * Ajoute les en-têtes CORS à une réponse. L'origine de la requête est reflétée si présente
     * (sinon {@code *}). Pas de {@code Allow-Credentials} : l'auth passe par le header Bearer,
     * jamais par cookie, donc les appels navigateur utilisent {@code credentials:'omit'}.
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
