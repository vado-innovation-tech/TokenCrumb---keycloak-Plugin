// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import biscuit.format.schema.Schema;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.RunLimits;
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
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End to end against a real Keycloak 26.4.7 (Testcontainers) with the shaded JAR mounted
 * as a provider: password grant login → JWT→Biscuit exchange → offline verification
 * of the Biscuit with the public key exposed by the extension.
 */
class BiscuitExchangeIT {

    // biscuit-java's default Datalog time limit (1 ms) is too short for a cold JVM in CI.
    private static final RunLimits TEST_LIMITS = new RunLimits(1000, 100, Duration.ofSeconds(1));

    private static final String REALM = "biscuit-demo";

    private static KeycloakContainer keycloak;
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final ObjectMapper JSON = new ObjectMapper();

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer(System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.4.7"))
                .withRealmImportFile("/biscuit-demo-realm.json")
                .withEnv("BISCUIT_ALLOW_KEY_BOOTSTRAP", "true")
                .withEnv("BISCUIT_EXTRA_FACTS", "[{\"name\":\"audience\",\"values\":[\"https://interop.gateway.example\"]},{\"name\":\"budget_cap\",\"values\":[2]}]")
                .withEnv("BISCUIT_ROLE_RIGHTS", "[{\"role\":\"user\",\"tool\":\"read_file\",\"operation\":\"read\"}]")
                .withProviderLibsFrom(List.of(new File("target/tokencrumb-keycloak-plugin.jar")));
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
        return exchange(authorizationHeader, null);
    }

    /** {@code body} null: request without a body, the legacy form, which must remain accepted. */
    private static HttpResponse<String> exchange(String authorizationHeader, String body)
            throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl() + "/realms/" + REALM + "/biscuit/token"))
                .POST(body == null
                        ? HttpRequest.BodyPublishers.noBody()
                        : HttpRequest.BodyPublishers.ofString(body));
        if (body != null) {
            request.header("Content-Type", "application/json");
        }
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
        assertTrue(body.has("kid") && !body.get("kid").asText().isBlank(), "kid expected on /public-key");
        String hex = body.get("public_key_hex").asText();
        assertEquals(64, hex.length(), "expected 32-byte hex public key");
        assertEquals(32, Base64.getDecoder().decode(body.get("public_key_base64").asText()).length);
        // standard text form: "ed25519/" + lowercase hex, same key as public_key_hex
        assertEquals("ed25519/" + hex.toLowerCase(java.util.Locale.ROOT), body.get("public_key").asText());
        PublicKey key = new PublicKey(Schema.PublicKey.Algorithm.Ed25519, hex);
        assertEquals(BiscuitMinter.rootKeyId(key), body.get("root_key_id").asInt());
        return key;
    }

    /**
     * root_key_id read from the token's protobuf envelope (what a key provider receives). Read
     * directly rather than through a KeyDelegate: the ITs run against the shaded JAR, where
     * KeyDelegate's signature uses the relocated vavr Option.
     */
    static Integer envelopeRootKeyId(String biscuitB64) throws Exception {
        Schema.Biscuit envelope = Schema.Biscuit.parseFrom(Base64.getUrlDecoder().decode(biscuitB64));
        return envelope.hasRootKeyId() ? envelope.getRootKeyId() : null;
    }

    @Test
    void exchangesJwtForBiscuitAndVerifiesOffline() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());

        JsonNode body = JSON.readTree(response.body());
        String biscuitB64 = body.get("biscuit").asText();
        assertNotNull(biscuitB64);
        assertTrue(body.get("expires_at").asLong() > Instant.now().getEpochSecond());
        assertEquals(1, body.get("revocation_ids").size(), response.body());

        // offline verification: only the public key exposed by the extension is used
        PublicKey publicKey = fetchPublicKey();
        java.nio.file.Files.writeString(java.nio.file.Path.of("target/keycloak-live-interop.json"), JSON.writeValueAsString(
                java.util.Map.of("token",biscuitB64,"authority_pub","ed25519/"+publicKey.toHex(),"now",Instant.now().toString())));
        Biscuit biscuit = Biscuit.from_b64url(biscuitB64, publicKey);
        biscuit.authorizer().set_time().allow().authorize(TEST_LIMITS);
        assertEquals(biscuit.revocation_identifiers().get(0).toHex().toLowerCase(java.util.Locale.ROOT),
                body.get("revocation_ids").get(0).asText());

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
        // the exchange provisions the root key and issues the Biscuit…
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());
        String biscuitB64 = JSON.readTree(response.body()).get("biscuit").asText();

        // …then /public-key exposes that key's kid (safe GET, the key now exists)
        HttpResponse<String> pk = HTTP.send(HttpRequest.newBuilder()
                        .uri(URI.create(baseUrl() + "/realms/" + REALM + "/biscuit/public-key")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, pk.statusCode(), pk.body());
        JsonNode pkBody = JSON.readTree(pk.body());
        String kid = pkBody.get("kid").asText();
        assertFalse(kid.isBlank(), "kid must be exposed by /public-key");

        PublicKey publicKey = fetchPublicKey();
        String printed = Biscuit.from_b64url(biscuitB64, publicKey).print();
        // the Biscuit's key_id fact must match the exposed kid: rotation/epoch correlation
        assertTrue(printed.contains("key_id(\"" + kid + "\")"), printed);
        // the envelope's root_key_id must match the one /public-key exposes: root key selection
        assertEquals(pkBody.get("root_key_id").asInt(), envelopeRootKeyId(biscuitB64));
    }

    @Test
    void protocolMapperEmbedsBiscuitClaimInAccessToken() throws Exception {
        // The "Biscuit Emitter" mapper is configured on demo-cli in the demo realm:
        // the access JWT must already carry a "biscuit" claim (no REST call).
        String jwt = passwordGrant();
        String payloadJson = new String(
                Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        JsonNode payload = JSON.readTree(payloadJson);
        assertTrue(payload.has("biscuit"), "the biscuit claim must be present in the access token");

        // The Biscuit from the claim verifies offline with the same root public key.
        PublicKey publicKey = fetchPublicKey();
        assertEquals(BiscuitMinter.rootKeyId(publicKey), envelopeRootKeyId(payload.get("biscuit").asText()));
        Biscuit biscuit = Biscuit.from_b64url(payload.get("biscuit").asText(), publicKey);
        biscuit.authorizer().set_time().allow().authorize(TEST_LIMITS);

        String printed = biscuit.print();
        // facts configured in the UI (realm JSON)
        assertTrue(printed.contains("audience(\"https://gateway.example\")"), printed);
        assertTrue(printed.contains("required_profile(\"native\")"), printed);
        assertTrue(printed.contains("tenant_id(\"acme\")"), printed);
        // governed fact derived from the agent_id user attribute (never settable as a literal)
        assertTrue(printed.contains("agent_id(\"agent-alice-007\")"), printed);
        // core facts always issued by the minter
        assertTrue(printed.contains("user(\""), printed);
        assertTrue(printed.contains("realm_role(\"admin\")"), printed);
    }

    @Test
    void expiresAtIsCappedByJwtExp() throws Exception {
        // realm accessTokenLifespan = 120 s < biscuit TTL (300 s): the JWT bounds the expiry
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
                biscuit.authorizer().add_fact("time(2999-01-01T00:00:00Z)").allow().authorize(TEST_LIMITS));
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

    // ------------------------------------------------------------------ //
    // Anchoring of an agent key supplied by the requester
    // ------------------------------------------------------------------ //
    private static final String AGENT_PUBKEY = "ed25519/" + "ab".repeat(32);

    @Test
    void anchorsTheRequestedAgentKeyAndForcesTheHardenedProfile() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant(),
                "{\"agent_pubkey\": \"" + AGENT_PUBKEY + "\"}");
        assertEquals(200, response.statusCode(), response.body());

        Biscuit biscuit = Biscuit.from_b64url(
                JSON.readTree(response.body()).get("biscuit").asText(), fetchPublicKey());
        String printed = biscuit.print();
        assertTrue(printed.contains("agent_pubkey(\"" + AGENT_PUBKEY + "\")"), printed);
        // Without this enforcement, the caller anchors a key then presents the mandate under the native profile
        // and bypasses attestation: the extension would create a bypass instead of closing one.
        assertTrue(printed.contains("required_profile(\"hardened_biscuit_anchored\")"), printed);
        // Rights remain those of the presented JWT: anchoring only restricts.
        assertTrue(printed.contains("realm_role(\"admin\")"), printed);
    }

    @Test
    void exportsARealAnchoredHolderForPythonVerification() throws Exception {
        // Ephemeral test identity only; the private key is held by the requesting client.
        var agent = new org.biscuitsec.biscuit.crypto.KeyPair(new java.security.SecureRandom());
        var response = exchange("Bearer " + passwordGrant(),
                "{\"agent_pubkey\":\"ed25519/" + agent.public_key().toHex() + "\"}");
        assertEquals(200, response.statusCode(), response.body());
        var fixture = java.util.Map.of("token",JSON.readTree(response.body()).get("biscuit").asText(),
                "authority_pub","ed25519/"+fetchPublicKey().toHex(),"now",Instant.now().toString(),
                "agent_private","ed25519-private/"+agent.toHex());
        java.nio.file.Files.writeString(java.nio.file.Path.of("target/keycloak-live-3b-interop.json"),JSON.writeValueAsString(fixture));
    }

    @Test
    void anExchangeWithoutABodyIsStillNotAnchored() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant());
        assertEquals(200, response.statusCode(), response.body());
        String printed = Biscuit.from_b64url(
                JSON.readTree(response.body()).get("biscuit").asText(), fetchPublicKey()).print();
        assertFalse(printed.contains("agent_pubkey("), printed);
    }

    @Test
    void aMalformedAgentKeyIs400() throws Exception {
        HttpResponse<String> response =
                exchange("Bearer " + passwordGrant(), "{\"agent_pubkey\": \"nope\"}");
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_agent_pubkey", JSON.readTree(response.body()).get("error").asText());
    }

    @Test
    void anUnknownBodyFieldIs400() throws Exception {
        HttpResponse<String> response = exchange("Bearer " + passwordGrant(),
                "{\"required_profile\": \"native\"}");
        assertEquals(400, response.statusCode(), response.body());
        assertEquals("invalid_request", JSON.readTree(response.body()).get("error").asText());
    }

    @Test
    void anchoringStillRequiresAValidBearer() throws Exception {
        HttpResponse<String> response =
                exchange(null, "{\"agent_pubkey\": \"" + AGENT_PUBKEY + "\"}");
        assertEquals(401, response.statusCode(), response.body());
    }
}
