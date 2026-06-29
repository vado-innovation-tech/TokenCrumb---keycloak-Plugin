// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

public class BiscuitResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;
    private final BiscuitConfig config;

    public BiscuitResourceProvider(KeycloakSession session, BiscuitConfig config) {
        this.session = session;
        this.config = config;
    }

    @Override
    public Object getResource() {
        return new BiscuitResource(session, config);
    }

    @Override
    public void close() {
        // rien à libérer
    }
}
