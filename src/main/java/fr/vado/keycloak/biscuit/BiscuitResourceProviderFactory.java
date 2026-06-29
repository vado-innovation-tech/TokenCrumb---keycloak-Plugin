// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Mounts the extension under {@code /realms/{realm}/biscuit} (the provider id gives the URL segment).
 * Configuration is read once at startup from the Keycloak {@code Config.Scope}, falling back to
 * environment variables.
 */
public class BiscuitResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "biscuit";

    private static final Logger LOG = Logger.getLogger(BiscuitResourceProviderFactory.class);

    // volatile: written once in init() (init thread), read in create() (request threads)
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
        // nothing to do
    }

    @Override
    public void close() {
        // nothing to release
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
