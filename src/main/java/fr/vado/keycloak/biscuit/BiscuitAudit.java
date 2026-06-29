// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;

/**
 * Audit d'émission minimal (note §A6) : une ligne de journal structurée {@code capability_issued}
 * par Biscuit émis, identique quelle que soit la voie d'émission (REST ou mapper). Démontrable via
 * {@code docker compose logs keycloak} ou n'importe quel collecteur de logs.
 *
 * <p>Format clé=valeur stable, catégorie de log dédiée ({@code fr.vado.keycloak.biscuit.BiscuitAudit})
 * pour filtrer/extraire facilement. Les champs absents sont rendus {@code -}.</p>
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
        LOG.infof("event=capability_issued path=%s realm=%s capability_id=%s key_id=%s issuer=%s "
                        + "audience=%s required_profile=%s expires_at=%d sub=%s",
                v(path), v(realm), v(audit.capabilityId()), v(audit.keyId()), v(audit.issuer()),
                v(audit.audience()), v(audit.requiredProfile()), audit.expiresAt(), v(audit.subject()));
    }

    /** Rend {@code -} pour les champs vides afin que le format reste positionnel et parsable. */
    private static String v(String s) {
        return (s == null || s.isBlank()) ? "-" : s;
    }
}
