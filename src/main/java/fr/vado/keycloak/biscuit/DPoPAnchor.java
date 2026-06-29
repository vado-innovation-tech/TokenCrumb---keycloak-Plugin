// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JWKSUtils;

import java.util.Base64;
import java.util.HexFormat;

/**
 * Agent key taken from the DPoP proof (RFC 9449) of the token request, used to anchor a mandate
 * issued by the mapper under the {@code hardened_biscuit_anchored} profile.
 *
 * <p>Keycloak validates the proof (signature, {@code htm}/{@code htu}, freshness, replay) before the
 * mappers run but only keeps its thumbprint (RFC 7638). We therefore re-read the public key from the
 * {@code DPoP} header and require its thumbprint to be <strong>exactly</strong> the one Keycloak
 * verified: this guarantees the anchored key is the one whose possession was just proven. The signature
 * is not re-verified here; that is Keycloak's job. Without a verified thumbprint, we refuse.</p>
 *
 * <p>Only an Ed25519 key ({@code kty=OKP}, {@code crv=Ed25519}) is accepted: it is the only form the
 * gateway can verify for {@code agent_pubkey}. Any other key causes issuance to be refused — never an
 * unanchored mandate presented as anchored.</p>
 */
final class DPoPAnchor {

    private DPoPAnchor() {
    }

    /**
     * @param dpopHeader         raw value of the request's {@code DPoP} header
     * @param verifiedThumbprint thumbprint of the key Keycloak verified for this same request
     * @return the fact {@code agent_pubkey("ed25519/<hex>")}
     * @throws IllegalArgumentException proof missing, not verified, or key not Ed25519
     */
    static BiscuitMinter.FactSpec agentPubkey(String dpopHeader, String verifiedThumbprint) {
        if (dpopHeader == null || dpopHeader.isBlank() || verifiedThumbprint == null || verifiedThumbprint.isBlank()) {
            throw new IllegalArgumentException("anchored profile requires a DPoP proof verified by Keycloak");
        }
        JWK jwk;
        try {
            jwk = new JWSInput(dpopHeader.trim()).getHeader().getKey();
        } catch (Exception e) {
            throw new IllegalArgumentException("unreadable DPoP proof", e);
        }
        if (jwk == null) {
            throw new IllegalArgumentException("DPoP proof carries no public key");
        }
        if (!verifiedThumbprint.equals(JWKSUtils.computeThumbprint(jwk))) {
            throw new IllegalArgumentException("DPoP key does not match the proof verified by Keycloak");
        }
        Object crv = jwk.getOtherClaims().get("crv");
        Object x = jwk.getOtherClaims().get("x");
        if (!"OKP".equals(jwk.getKeyType()) || !"Ed25519".equals(crv) || !(x instanceof String xs)) {
            throw new IllegalArgumentException("anchored profile requires an Ed25519 DPoP key");
        }
        byte[] raw;
        try {
            raw = Base64.getUrlDecoder().decode(xs);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid Ed25519 DPoP key encoding", e);
        }
        if (raw.length != 32) {
            throw new IllegalArgumentException("invalid Ed25519 DPoP key length");
        }
        return BiscuitFacts.requested("ed25519/" + HexFormat.of().formatHex(raw))
                .orElseThrow(() -> new IllegalArgumentException("invalid agent key"));
    }
}
