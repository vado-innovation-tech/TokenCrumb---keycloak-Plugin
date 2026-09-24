// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import biscuit.format.schema.Schema;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.biscuitsec.biscuit.crypto.PublicKey;
import org.biscuitsec.biscuit.datalog.RunLimits;
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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * "Biscuit Emitter" mapper with the {@code hardened_biscuit_anchored} profile against a real Keycloak
 * 26.4.7: the agent key is the one from the token request's Ed25519 DPoP proof.
 */
class BiscuitMapperDPoPIT {

    // biscuit-java's default Datalog time limit (1 ms) is too short for a cold JVM in CI.
    private static final RunLimits TEST_LIMITS = new RunLimits(1000, 100, Duration.ofSeconds(1));

    private static final String REALM = "biscuit-dpop";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private static KeycloakContainer keycloak;
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final ObjectMapper JSON = new ObjectMapper();

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer(System.getProperty("keycloak.image", "quay.io/keycloak/keycloak:26.4.7"))
                .withRealmImportFile("/biscuit-dpop-realm.json")
                .withEnv("BISCUIT_ALLOW_KEY_BOOTSTRAP", "true")
                // Deliberately different global table: the mapper must replace it with its own.
                .withEnv("BISCUIT_ROLE_RIGHTS", "[{\"role\":\"analyst\",\"tool\":\"read_file\",\"operation\":\"read\"}]")
                .withProviderLibsFrom(List.of(new File("target/tokencrumb-keycloak-plugin.jar")));
        keycloak.start();
    }

    @AfterAll
    static void stopKeycloak() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    private static String tokenUrl() {
        String url = keycloak.getAuthServerUrl();
        return (url.endsWith("/") ? url.substring(0, url.length() - 1) : url)
                + "/realms/" + REALM + "/protocol/openid-connect/token";
    }

    private static KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    private static byte[] rawEd25519(KeyPair key) {
        byte[] spki = key.getPublic().getEncoded();
        return Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    }

    private static String sign(String alg, String jwk, KeyPair key, String algorithm) throws Exception {
        String header = "{\"typ\":\"dpop+jwt\",\"alg\":\"" + alg + "\",\"jwk\":" + jwk + "}";
        String payload = JSON.writeValueAsString(Map.of("jti", UUID.randomUUID().toString(), "htm", "POST",
                "htu", tokenUrl(), "iat", Instant.now().getEpochSecond()));
        String input = B64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + B64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(key.getPrivate());
        signature.update(input.getBytes(StandardCharsets.US_ASCII));
        return input + "." + B64.encodeToString(signature.sign());
    }

    private static String ed25519Proof(KeyPair key) throws Exception {
        String jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + B64.encodeToString(rawEd25519(key)) + "\"}";
        return sign("EdDSA", jwk, key, "Ed25519");
    }

    private static HttpResponse<String> token(String form, String dpopProof) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder().uri(URI.create(tokenUrl()))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        if (dpopProof != null) {
            request.header("DPoP", dpopProof);
        }
        return HTTP.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> passwordGrant(String clientId, String dpopProof) throws Exception {
        return token("grant_type=password&client_id=" + clientId + "&username=alice&password="
                + URLEncoder.encode("alice-password", StandardCharsets.UTF_8), dpopProof);
    }

    private static JsonNode publicKeyDocument() throws Exception {
        String url = tokenUrl().replace("/protocol/openid-connect/token", "/biscuit/public-key");
        HttpResponse<String> response = HTTP.send(HttpRequest.newBuilder().uri(URI.create(url)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), response.body());
        return JSON.readTree(response.body());
    }

    private static Biscuit biscuitClaim(HttpResponse<String> response) throws Exception {
        assertEquals(200, response.statusCode(), response.body());
        JsonNode body = JSON.readTree(response.body());
        assertEquals("DPoP", body.get("token_type").asText(), response.body());
        String jwt = body.get("access_token").asText();
        JsonNode payload = JSON.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
        assertTrue(payload.has("biscuit"), payload.toString());

        // Select the root key the way an authorizer does: by the envelope's root_key_id, matched
        // against the one /public-key advertises, using the standard "ed25519/<hex>" text form.
        JsonNode document = publicKeyDocument();
        String text = document.get("public_key").asText();
        assertTrue(text.startsWith("ed25519/"), text);
        PublicKey root = new PublicKey(Schema.PublicKey.Algorithm.Ed25519, text.substring("ed25519/".length()));
        String token = payload.get("biscuit").asText();
        assertEquals(document.get("root_key_id").asInt(), BiscuitExchangeIT.envelopeRootKeyId(token));
        return Biscuit.from_b64url(token, root);
    }

    @Test
    void theDPoPKeyIsAnchoredWithTheMapperRightsBudgetAndLifetime() throws Exception {
        KeyPair agent = ed25519();
        long now = Instant.now().getEpochSecond();
        Biscuit biscuit = biscuitClaim(passwordGrant("agent-cli", ed25519Proof(agent)));
        biscuit.authorizer().set_time().allow().authorize(TEST_LIMITS);
        String printed = biscuit.print();

        assertTrue(printed.contains("agent_pubkey(\"ed25519/" + HexFormat.of().formatHex(rawEd25519(agent)) + "\")"), printed);
        assertTrue(printed.contains("required_profile(\"hardened_biscuit_anchored\")"), printed);
        assertFalse(printed.contains("required_profile(\"native\")"), printed);
        assertTrue(printed.contains("audience(\"https://demo.gateway.example\")"), printed);
        assertTrue(printed.contains("agent_id(\"agent-alice-007\")"), printed);
        assertTrue(printed.contains("budget_cap(7)"), printed);
        // The mapper's table, not the global table.
        assertTrue(printed.contains("right(\"list_tables\", \"read\")"), printed);
        assertFalse(printed.contains("read_file"), printed);
        assertTrue(printed.contains("rights_source(\"jwt_roles\")"), printed);
        // Mapper TTL (60 s) shorter than the global one (300 s) and the JWT's (300 s).
        java.util.regex.Matcher exp = java.util.regex.Pattern.compile("expires_at\\(([^)]+)\\)").matcher(printed);
        assertTrue(exp.find(), printed);
        long expiresAt = Instant.parse(exp.group(1)).getEpochSecond();
        assertTrue(expiresAt <= now + 70 && expiresAt >= now + 50, "expires_at=" + expiresAt + " now=" + now);
    }

    @Test
    void aRefreshKeepsTheSameAnchoredKey() throws Exception {
        KeyPair agent = ed25519();
        HttpResponse<String> first = passwordGrant("agent-cli", ed25519Proof(agent));
        assertEquals(200, first.statusCode(), first.body());
        String refresh = JSON.readTree(first.body()).get("refresh_token").asText();

        HttpResponse<String> refreshed = token("grant_type=refresh_token&client_id=agent-cli&refresh_token="
                + URLEncoder.encode(refresh, StandardCharsets.UTF_8), ed25519Proof(agent));
        String printed = biscuitClaim(refreshed).print();
        assertTrue(printed.contains("agent_pubkey(\"ed25519/" + HexFormat.of().formatHex(rawEd25519(agent)) + "\")"), printed);
    }

    @Test
    void withoutADPoPProofTheMapperRefusesToIssue() throws Exception {
        // agent-lax does not require DPoP on the Keycloak side: the mapper is the one that must refuse.
        // Control: the same client gets its mandate as soon as an Ed25519 proof is presented.
        KeyPair agent = ed25519();
        assertTrue(biscuitClaim(passwordGrant("agent-lax", ed25519Proof(agent))).print()
                .contains("ed25519/" + HexFormat.of().formatHex(rawEd25519(agent))));

        HttpResponse<String> response = passwordGrant("agent-lax", null);
        assertNotEquals(200, response.statusCode(), response.body());
        assertFalse(response.body().contains("access_token"), response.body());
    }

    @Test
    void aNonEd25519DPoPKeyIsRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair ec = generator.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) ec.getPublic();
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + B64.encodeToString(fixed(pub.getW().getAffineX().toByteArray()))
                + "\",\"y\":\"" + B64.encodeToString(fixed(pub.getW().getAffineY().toByteArray())) + "\"}";
        HttpResponse<String> response = passwordGrant("agent-lax", sign("ES256", jwk, ec, "SHA256withECDSAinP1363Format"));
        assertNotEquals(200, response.statusCode(), response.body());
        assertFalse(response.body().contains("access_token"), response.body());
    }

    /** EC coordinate encoded as exactly 32 bytes (BigInteger may add a sign byte). */
    private static byte[] fixed(byte[] value) {
        byte[] out = new byte[32];
        System.arraycopy(value, Math.max(0, value.length - 32), out, Math.max(0, 32 - value.length), Math.min(32, value.length));
        return out;
    }
}
