package fr.vado.keycloak.biscuit;

import biscuit.format.schema.Schema;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.error.Error;
import org.biscuitsec.biscuit.token.Biscuit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Bout en bout contre un vrai Keycloak 26.4.7 (Testcontainers) avec le JAR shadé monté
 * en provider : login password grant → échange JWT→Biscuit → vérification hors-ligne
 * du Biscuit avec la clé publique exposée par l'extension.
 */
class BiscuitExchangeIT {

    private static final String REALM = "biscuit-demo";

    private static KeycloakContainer keycloak;
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final ObjectMapper JSON = new ObjectMapper();

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:26.4.7")
                .withRealmImportFile("/biscuit-demo-realm.json")
                .withProviderLibsFrom(List.of(new File("target/keycloak-biscuit-exchange.jar")));
        keycloak.start();
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    private static String baseUrl() {
        String url = keycloak.getAuthServerUrl();
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    private static String passwordGrant() throws Exception {
        String form = "grant_type=password&client_id=demo-cli"
                + "&username=alice&password=" + URLEncoder.encode("alice-password", StandardCharsets.UTF_8);
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/realms/" + REALM + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "password grant failed: " + response.body());
        return JSON.readTree(response.body()).get("access_token").asText();
    }

    private static HttpResponse<String> exchange(String authorizationHeader) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/realms/" + REALM + "/biscuit/token"))
                .POST(HttpRequest.BodyPublishers.noBody());
        if (authorizationHeader != null) {
            request.header("Authorization", authorizationHeader);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static PublicKey fetchPublicKey() throws Exception {
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/realms/" + REALM + "/biscuit/public-key"))
                .GET()
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        JsonNode body = JSON.readTree(response.body());
        assertEquals("ed25519", body.get("algorithm").asText());
        assertTrue(body.has("kid") && !body.get("kid").asText().isBlank(), "kid attendu sur /public-key");
        String hex = body.get("public_key_hex").asText();
        assertEquals(64, hex.length(), "expected 32-byte hex public key");
        assertEquals(32, Base64.getDecoder().decode(body.get("public_key_base64").asText()).length);
        return new PublicKey(Schema.PublicKey.Algorithm.Ed25519, hex);
    }

    @Test
    void exchangesJwtForBiscuitAndVerifiesOffline() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());

        JsonNode body = JSON.readTree(response.body());
        String biscuitB64 = body.get("biscuit").asText();
        assertNotNull(biscuitB64);
        assertTrue(body.get("expires_at").asLong() > Instant.now().getEpochSecond());

        // vérification hors-ligne : seule la clé publique exposée par l'extension est utilisée
        Biscuit biscuit = Biscuit.from_b64url(biscuitB64, fetchPublicKey());
        biscuit.authorizer().set_time().allow().authorize();

        String printed = biscuit.print();
        assertTrue(printed.contains("user(\""), printed);
        assertTrue(printed.contains("client(\"demo-cli\")"), printed);
        assertTrue(printed.contains("realm_role(\"admin\")"), printed);
        assertTrue(printed.contains("realm_role(\"user\")"), printed);
        assertTrue(printed.contains("client_role(\"demo-cli\", \"orders:read\")"), printed);
        assertTrue(printed.contains("issuer(\""), printed);
        assertTrue(printed.contains("jti(\""), printed);
        assertTrue(printed.contains("key_id(\""), printed);
    }

    @Test
    void publicKeyKidMatchesBiscuitKeyIdFact() throws Exception {
        // l'échange provisionne la clé racine et émet le Biscuit…
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());
        String biscuitB64 = JSON.readTree(response.body()).get("biscuit").asText();

        // …puis /public-key expose le kid de cette clé (GET safe, la clé existe désormais)
        HttpResponse<String> pk = HTTP.send(HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl() + "/realms/" + REALM + "/biscuit/public-key")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, pk.statusCode(), pk.body());
        String kid = JSON.readTree(pk.body()).get("kid").asText();
        assertFalse(kid.isBlank(), "kid doit être exposé par /public-key");

        String printed = Biscuit.from_b64url(biscuitB64, fetchPublicKey()).print();
        // le fait key_id du Biscuit doit correspondre au kid exposé : corrélation rotation/époque
        assertTrue(printed.contains("key_id(\"" + kid + "\")"), printed);
    }

    @Test
    void protocolMapperEmbedsBiscuitClaimInAccessToken() throws Exception {
        // Le mapper "Biscuit Emitter" est configuré sur demo-cli dans le realm de démo :
        // le JWT d'accès doit déjà porter un claim "biscuit" (sans appel REST).
        String jwt = passwordGrant();
        String payloadJson = new String(
                Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        JsonNode payload = JSON.readTree(payloadJson);
        assertTrue(payload.has("biscuit"), "le claim biscuit doit être présent dans l'access token");

        // Le Biscuit du claim se vérifie hors-ligne avec la même clé publique racine.
        Biscuit biscuit = Biscuit.from_b64url(payload.get("biscuit").asText(), fetchPublicKey());
        biscuit.authorizer().set_time().allow().authorize();

        String printed = biscuit.print();
        // faits configurés en UI (realm JSON)
        assertTrue(printed.contains("audience(\"biscuitmcp://exado-gateway\")"), printed);
        assertTrue(printed.contains("required_profile(\"native\")"), printed);
        assertTrue(printed.contains("tenant_id(\"exado\")"), printed);
        // fait gouverné dérivé de l'attribut utilisateur agent_id (jamais settable en littéral)
        assertTrue(printed.contains("agent_id(\"agent-alice-007\")"), printed);
        // faits cœur toujours émis par le minter
        assertTrue(printed.contains("user(\""), printed);
        assertTrue(printed.contains("realm_role(\"admin\")"), printed);
    }

    @Test
    void expiresAtIsCappedByJwtExp() throws Exception {
        // accessTokenLifespan du realm = 120 s < TTL biscuit (300 s) : le JWT borne l'expiration
        long now = Instant.now().getEpochSecond();
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());

        long expiresAt = JSON.readTree(response.body()).get("expires_at").asLong();
        assertTrue(expiresAt <= now + 130, "expires_at=" + expiresAt + " now=" + now);
        assertTrue(expiresAt >= now + 90, "expires_at=" + expiresAt + " now=" + now);
    }

    @Test
    void expiredTimeFailsAuthorization() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());
        String biscuitB64 = JSON.readTree(response.body()).get("biscuit").asText();
        Biscuit biscuit = Biscuit.from_b64url(biscuitB64, fetchPublicKey());

        assertThrows(Error.FailedLogic.class, () ->
                biscuit.authorizer().add_fact("time(2999-01-01T00:00:00Z)").allow().authorize());
    }

    @Test
    void tamperedTokenIsRejected() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());
        String biscuitB64 = JSON.readTree(response.body()).get("biscuit").asText();

        byte[] raw = Base64.getUrlDecoder().decode(biscuitB64);
        raw[raw.length / 2] ^= 0x01;
        String tampered = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);

        PublicKey publicKey = fetchPublicKey();
        assertThrows(Exception.class, () -> Biscuit.from_b64url(tampered, publicKey));
    }

    @Test
    void missingOrInvalidBearerReturns401() throws Exception {
        HttpResponse<String> noHeader = exchange(null);
        assertEquals(401, noHeader.statusCode(), noHeader.body());
        assertTrue(JSON.readTree(noHeader.body()).has("error"));

        HttpResponse<String> garbage = exchange("Bearer garbage");
        assertEquals(401, garbage.statusCode(), garbage.body());
        assertEquals("invalid_token", JSON.readTree(garbage.body()).get("error").asText());
    }
}
