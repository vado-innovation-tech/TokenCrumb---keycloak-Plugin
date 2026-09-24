// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;

/**
 * Audit d'émission minimal (note §A6) : une ligne de journal structurée {@code capability_issued}
 * par Biscuit émis, identique quelle que soit la voie d'émission (REST ou mapper). Démontrable via
 * {@code docker compose logs keycloak} ou n'importe quel collecteur de logs.
 *
 * <p>Format JSON échappé, catégorie de log dédiée ({@code fr.vado.keycloak.biscuit.BiscuitAudit})
 * pour filtrer/extraire facilement. Les champs absents sont omis.</p>
 *
 * <p><strong>Périmètre V1.</strong> Le hash-chaînage, la signature et l'ancrage externe du journal
 * d'audit (spec §3.7(d)) restent <strong>Lot 3</strong> : ceci n'est pas un journal inviolable, mais
 * une trace d'émission exploitable et démontrable. Une montée vers l'Event SPI Keycloak (événements
 * visibles dans l'admin console) est un durcissement post-V1.</p>
 */
public final class BiscuitAudit {

    private static final Logger LOG = Logger.getLogger(BiscuitAudit.class);

    private BiscuitAudit() {
    }

    /**
     * Journalise une émission de capacité.
     *
     * @param path  voie d'émission ({@code rest} ou {@code mapper})
     * @param realm nom du realm émetteur
     * @param audit résumé d'émission produit par {@link BiscuitMinter}
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
        fields.put("issuer", audit.issuer()); fields.put("audience", audit.audience());
        fields.put("required_profile", audit.requiredProfile()); fields.put("expires_at", audit.expiresAt());
        fields.put("sub", audit.subject());
        return new com.google.gson.Gson().toJson(fields);
    }
    static void logDenied(String path, String reason) {
        LOG.warn(new com.google.gson.Gson().toJson(java.util.Map.of("event", "capability_denied", "path", path, "reason", reason)));
    }
}
