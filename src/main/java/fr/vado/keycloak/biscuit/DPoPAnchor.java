// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JWKSUtils;

import java.util.Base64;
import java.util.HexFormat;

/**
 * Clé d'agent tirée de la preuve DPoP (RFC 9449) de la requête de token, pour ancrer un mandat
 * émis par le mapper en profil {@code hardened_biscuit_anchored}.
 *
 * <p>Keycloak valide la preuve (signature, {@code htm}/{@code htu}, fraîcheur, rejeu) avant les
 * mappers mais n'en conserve que l'empreinte (RFC 7638). On relit donc la clé publique dans l'en-tête
 * {@code DPoP} et on exige que son empreinte soit <strong>exactement</strong> celle que Keycloak a
 * vérifiée : la clé ancrée est alors bien celle dont la possession vient d'être prouvée. La signature
 * n'est pas revérifiée ici, c'est le rôle de Keycloak ; sans empreinte vérifiée, on refuse.</p>
 *
 * <p>Seule une clé Ed25519 ({@code kty=OKP}, {@code crv=Ed25519}) est acceptée : c'est la seule forme
 * que la gateway sait vérifier pour {@code agent_pubkey}. Toute autre clé refuse l'émission — jamais de
 * mandat non ancré présenté comme 3b.</p>
 */
final class DPoPAnchor {

    private DPoPAnchor() {
    }

    /**
     * @param dpopHeader         valeur brute de l'en-tête {@code DPoP} de la requête
     * @param verifiedThumbprint empreinte de la clé que Keycloak a vérifiée pour cette même requête
     * @return le fait {@code agent_pubkey("ed25519/<hex>")}
     * @throws IllegalArgumentException preuve absente, non vérifiée, ou clé non Ed25519
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
