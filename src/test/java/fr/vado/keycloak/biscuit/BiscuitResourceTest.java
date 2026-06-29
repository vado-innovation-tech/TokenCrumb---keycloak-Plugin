package fr.vado.keycloak.biscuit;

import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Comportements des endpoints (404 désactivé, CORS, 503) avec un KeycloakSession mocké. */
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
        assertEquals(404, res.token().getStatus());
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
}
