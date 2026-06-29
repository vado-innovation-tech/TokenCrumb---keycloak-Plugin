// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;

/**
 * Minimal issuance audit: one structured {@code capability_issued} log line per issued Biscuit,
 * identical for both issuance paths (REST and mapper). Observable via
 * {@code docker compose logs keycloak} or any log collector.
 *
 * <p>Escaped JSON format, dedicated log category ({@code fr.vado.keycloak.biscuit.BiscuitAudit})
 * for easy filtering/extraction. Absent fields are omitted.</p>
 *
 * <p>The {@code revocation_id} field is the authority block's revocation identifier: a service that
 * deny-lists it rejects the token and every attenuated copy of it.</p>
 *
 * <p><strong>Scope.</strong> Hash chaining, signing and external anchoring of the audit log are not
 * implemented yet: this is not a tamper-proof log, but a usable, observable issuance trail. Moving to
 * the Keycloak Event SPI (events visible in the admin console) is future work.</p>
 */
public final class BiscuitAudit {

    private static final Logger LOG = Logger.getLogger(BiscuitAudit.class);

    private BiscuitAudit() {
    }

    /**
     * Logs a capability issuance.
     *
     * @param path  issuance path ({@code rest} or {@code mapper})
     * @param realm name of the issuing realm
     * @param audit issuance summary produced by {@link BiscuitMinter}
     */
    public static void logIssued(String path, String realm, BiscuitMinter.Audit audit) {
        if (audit == null) {
            return;
        }
        LOG.info(issuedJson(path, realm, audit));
    }
    static String issuedJson(String path, String realm, BiscuitMinter.Audit audit) {
        var fields = new java.util.LinkedHashMap<String, Object>();
        fields.put("event", "capability_issued"); fields.put("path", path); fields.put("realm", realm);
        fields.put("capability_id", audit.capabilityId()); fields.put("key_id", audit.keyId());
        fields.put("revocation_id", audit.revocationId());
        fields.put("issuer", audit.issuer()); fields.put("audience", audit.audience());
        fields.put("required_profile", audit.requiredProfile()); fields.put("expires_at", audit.expiresAt());
        fields.put("sub", audit.subject());
        return new com.google.gson.Gson().toJson(fields);
    }
    static void logDenied(String path, String reason) {
        LOG.warn(new com.google.gson.Gson().toJson(java.util.Map.of("event", "capability_denied", "path", path, "reason", reason)));
    }
}
