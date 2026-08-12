// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.biscuitsec.biscuit.crypto.KeyPair;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Endpoint behavior (404 when disabled, CORS, 503, response bodies) with a mocked KeycloakSession. */
class BiscuitResourceTest {

    private static KeycloakSession session(String origin, RealmModel realm) {
        KeycloakSession session = mock(KeycloakSession.class, RETURNS_DEEP_STUBS);
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.getHeaderString("Origin")).thenReturn(origin);
        when(session.getContext().getRequestHeaders()).thenReturn(headers);
        when(session.getContext().getRealm()).thenReturn(realm);
        return session;
    }

    @Test
    void disabledExtensionReturns404OnAllEndpoints() {
        BiscuitConfig disabled = BiscuitConfig.from(Map.of("BISCUIT_ENABLED", "false"));
        BiscuitResource res = new BiscuitResource(session(null, null), disabled);
        assertEquals(404, res.token(null).getStatus());
        assertEquals(404, res.publicKey().getStatus());
        assertEquals(404, res.tokenPreflight().getStatus());
        assertEquals(404, res.publicKeyPreflight().getStatus());
    }

    @Test
    void preflightReflectsOriginAndEmitsCorsHeaders() {
        BiscuitResource res = new BiscuitResource(session("https://app.example", null), BiscuitConfig.from(Map.of()));
        Response r = res.tokenPreflight();
        assertEquals(204, r.getStatus());
        assertEquals("https://app.example", r.getHeaderString("Access-Control-Allow-Origin"));
        assertEquals("Origin", r.getHeaderString("Vary"));
        assertTrue(r.getHeaderString("Access-Control-Allow-Methods").contains("POST"));
        assertEquals("authorization, content-type", r.getHeaderString("Access-Control-Allow-Headers"));
    }

    @Test
    void corsFallsBackToWildcardWithoutOrigin() {
        BiscuitResource res = new BiscuitResource(session(null, null), BiscuitConfig.from(Map.of()));
        assertEquals("*", res.publicKeyPreflight().getHeaderString("Access-Control-Allow-Origin"));
    }

    @Test
    void publicKeyReturns503WhenNoKeyProvisioned() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("r");
        when(realm.getName()).thenReturn("r");
        when(realm.getAttribute(anyString())).thenReturn(null);
        BiscuitConfig cfg = BiscuitConfig.from(Map.of("BISCUIT_KEY_STRATEGY", "generated"));
        BiscuitResource res = new BiscuitResource(session(null, realm), cfg);
        assertEquals(503, res.publicKey().getStatus());
    }

    @Test
    @SuppressWarnings("unchecked")
    void publicKeyExposesTheStandardTextFormAndRootKeyId() {
        KeyPair root = new KeyPair(new SecureRandom());
        RealmModel realm = mock(RealmModel.class);
        when(realm.getId()).thenReturn("r");
        when(realm.getName()).thenReturn("r");
        when(realm.getAttribute(BiscuitKeyManager.REALM_ATTRIBUTE)).thenReturn(root.toHex());
        BiscuitResource res = new BiscuitResource(session(null, realm), BiscuitConfig.from(Map.of()));

        Response r = res.publicKey();
        assertEquals(200, r.getStatus());
        Map<String, Object> body = (Map<String, Object>) r.getEntity();
        String hex = root.public_key().toHex();
        assertEquals("ed25519/" + hex.toLowerCase(Locale.ROOT), body.get("public_key"));
        assertEquals(BiscuitMinter.rootKeyId(root.public_key()), body.get("root_key_id"));
        // pre-existing fields are unchanged
        assertEquals("ed25519", body.get("algorithm"));
        assertEquals(hex.substring(0, 16), body.get("kid"));
        assertEquals(hex, body.get("public_key_hex"));
        assertEquals(Base64.getEncoder().encodeToString(root.public_key().toBytes()), body.get("public_key_base64"));
    }

    @Test
    void tokenResponseCarriesTheRevocationIds() throws Exception {
        org.keycloak.representations.AccessToken token = new org.keycloak.representations.AccessToken();
        token.subject("u");
        BiscuitMinter.MintResult result =
                BiscuitMinter.mint(token, new KeyPair(new SecureRandom()), 300, Instant.now());

        Map<String, Object> body = BiscuitResource.tokenResponse(result);
        assertEquals(List.of("biscuit", "expires_at", "revocation_ids"), List.copyOf(body.keySet()));
        assertEquals(result.biscuitB64(), body.get("biscuit"));
        assertEquals(result.expiresAt(), body.get("expires_at"));
        assertEquals(result.revocationIds(), body.get("revocation_ids"));
    }
}
