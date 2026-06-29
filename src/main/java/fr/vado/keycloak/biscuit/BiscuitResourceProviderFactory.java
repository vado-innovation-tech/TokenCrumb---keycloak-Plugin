// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Monte l'extension sous {@code /realms/{realm}/biscuit} (l'id du provider donne le segment d'URL).
 * La configuration est lue une fois au démarrage depuis les variables d'environnement.
 */
public class BiscuitResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "biscuit";

    private static final Logger LOG = Logger.getLogger(BiscuitResourceProviderFactory.class);

    // volatile : écrit une fois dans init() (thread d'init), lu dans create() (threads de requête)
    private volatile BiscuitConfig config;

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new BiscuitResourceProvider(session, config);
    }

    @Override
    public void init(Config.Scope scope) {
        this.config = BiscuitConfig.fromScope(scope);
        LOG.infof("Biscuit exchange extension initialized: %s", config);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // rien à faire
    }

    @Override
    public void close() {
        // rien à libérer
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
