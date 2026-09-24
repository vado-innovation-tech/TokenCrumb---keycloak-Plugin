package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** Extraction de la clé d'agent depuis une preuve DPoP dont Keycloak a vérifié l'empreinte. */
class DPoPAnchorTest {

    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final byte[] KEY = HexFormat.of().parseHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

    private static String proof(String jwk) {
        String header = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":" + jwk + "}";
        return B64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "."
                + B64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }

    private static String okp(byte[] x) {
        return "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + B64.encodeToString(x) + "\"}";
    }

    /** Empreinte RFC 7638, calculée indépendamment de Keycloak (membres requis, ordre lexical). */
    private static String thumbprint(String canonical) throws Exception {
        return B64.encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical.getBytes(StandardCharsets.UTF_8)));
    }

    private static String okpThumbprint(byte[] x) throws Exception {
        return thumbprint("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + B64.encodeToString(x) + "\"}");
    }

    @Test
    void verifiedEd25519KeyBecomesTheAnchoredAgentKey() throws Exception {
        BiscuitMinter.FactSpec fact = DPoPAnchor.agentPubkey(proof(okp(KEY)), okpThumbprint(KEY));
        assertEquals(new BiscuitMinter.FactSpec("agent_pubkey", List.of("ed25519/" + HexFormat.of().formatHex(KEY))), fact);
    }

    @Test
    void aKeyOtherThanTheVerifiedOneIsRefused() throws Exception {
        byte[] other = KEY.clone();
        other[0] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(proof(okp(other)), okpThumbprint(KEY)));
    }

    @Test
    void missingProofOrUnverifiedProofIsRefused() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(null, okpThumbprint(KEY)));
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(" ", okpThumbprint(KEY)));
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(proof(okp(KEY)), null));
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey("not-a-jws", okpThumbprint(KEY)));
    }

    @Test
    void nonEd25519KeysAreRefused() throws Exception {
        String ec = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
                + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}";
        String ecThumb = thumbprint("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
                + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}");
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(proof(ec), ecThumb));
        byte[] shortKey = new byte[31];
        assertThrows(IllegalArgumentException.class, () -> DPoPAnchor.agentPubkey(proof(okp(shortKey)), okpThumbprint(shortKey)));
    }
}
