// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.utils.MapperTypeSerializer;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.protocol.oidc.mappers.OIDCIDTokenMapper;
import org.keycloak.protocol.oidc.mappers.UserInfoTokenMapper;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Protocol Mapper OIDC : émet un Biscuit (signé par la clé racine du realm) dans un claim du token.
 *
 * <p>Voie d'émission <strong>complémentaire</strong> à l'endpoint REST {@code /biscuit/token}
 * (qui reste inchangé). Son intérêt : la configuration des faits supplémentaires se fait
 * <strong>par client, dans l'admin console</strong> (audience, required_profile, faits libres),
 * sans modifier le code.</p>
 *
 * <p>Séparation des responsabilités : la stratégie de clé et le TTL viennent de la config globale
 * ({@link BiscuitConfig#fromScope}) ; les faits viennent de la config <em>par-mapper</em>. La frappe
 * réutilise telle quelle {@link BiscuitMinter#mint}, donc la surface qui touche Keycloak reste mince.</p>
 */
public class BiscuitProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-biscuit-mapper";

    private static final Logger LOG = Logger.getLogger(BiscuitProtocolMapper.class);

    static final String CLAIM_NAME = "biscuit.claim.name";
    static final String AUDIENCE = "biscuit.audience";
    static final String REQUIRED_PROFILE = "biscuit.required.profile";
    static final String EXTRA_FACTS = "biscuit.extra.facts";
    static final String DERIVED_FACTS = "biscuit.derived.facts";
    static final String DEFAULT_CLAIM_NAME = "biscuit";

    private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = new ArrayList<>();

    static {
        ProviderConfigProperty claimName = new ProviderConfigProperty();
        claimName.setName(CLAIM_NAME);
        claimName.setLabel("Claim name");
        claimName.setType(ProviderConfigProperty.STRING_TYPE);
        claimName.setDefaultValue(DEFAULT_CLAIM_NAME);
        claimName.setHelpText("Nom du claim JWT qui portera le Biscuit (base64url).");
        CONFIG_PROPERTIES.add(claimName);

        ProviderConfigProperty audience = new ProviderConfigProperty();
        audience.setName(AUDIENCE);
        audience.setLabel("Audience");
        audience.setType(ProviderConfigProperty.STRING_TYPE);
        audience.setHelpText("Si non vide, ajoute le fait audience(\"...\") (scoping de la capacité).");
        CONFIG_PROPERTIES.add(audience);

        ProviderConfigProperty profile = new ProviderConfigProperty();
        profile.setName(REQUIRED_PROFILE);
        profile.setLabel("Required profile");
        profile.setType(ProviderConfigProperty.LIST_TYPE);
        // Pas de hardened_biscuit_anchored ici : ce profil exige une clé d'agent ancrée dans le bloc
        // d'autorité, et cette voie ne peut pas en ancrer (agent_pubkey est RESERVED_CORE sur toute
        // voie de config). Le proposer ne produirait que des mandats refusés à chaque appel par la
        // gateway (« profile downgrade »). Seul POST /biscuit/token avec agent_pubkey y donne accès.
        profile.setOptions(List.of("native", "registry_backed"));
        profile.setHelpText("Si défini, ajoute required_profile(\"...\") (anti-downgrade ; enforcé côté "
                + "gateway). registry_backed suppose un agent_id (voir Derived facts) résoluble par le "
                + "registre de la gateway. Le profil hardened_biscuit_anchored n'est atteignable que "
                + "par POST /biscuit/token avec agent_pubkey : cette voie ne peut pas ancrer de clé.");
        CONFIG_PROPERTIES.add(profile);

        ProviderConfigProperty extra = new ProviderConfigProperty();
        extra.setName(EXTRA_FACTS);
        extra.setLabel("Extra facts");
        extra.setType(ProviderConfigProperty.MAP_TYPE);
        extra.setHelpText("Faits supplémentaires nom->valeur littérale (ex. tenant_id). "
                + "Nom Datalog valide requis ; noms cœur ET gouvernés (agent_id, audience…) refusés.");
        CONFIG_PROPERTIES.add(extra);

        ProviderConfigProperty derived = new ProviderConfigProperty();
        derived.setName(DERIVED_FACTS);
        derived.setLabel("Derived facts (from user attribute)");
        derived.setType(ProviderConfigProperty.MAP_TYPE);
        derived.setHelpText("Faits dérivés : nom de fait -> nom d'attribut Keycloak. La valeur est lue "
                + "sur l'utilisateur (ou son service-account) à l'émission. Autorise les faits gouvernés "
                + "(agent_id, principal_id…) car la valeur vient de l'identité, pas d'un texte libre.");
        CONFIG_PROPERTIES.add(derived);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, BiscuitProtocolMapper.class);
    }

    /** Config clé/TTL globale (repli env tant que {@link #init} n'a pas tourné). */
    private volatile BiscuitConfig globalConfig = BiscuitConfig.fromEnv();

    @Override
    public void init(Config.Scope config) {
        this.globalConfig = BiscuitConfig.fromScope(config);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Biscuit Emitter";
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getHelpText() {
        return "Émet un Biscuit signé par la clé racine du realm dans un claim du token. "
                + "Configurable par client : audience, required_profile, faits custom.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    /**
     * Doit s'exécuter <strong>après</strong> les mappers de rôles (priorités 10–40) pour que
     * {@code realm_access}/{@code resource_access} soient déjà peuplés dans l'access token au
     * moment de la frappe — sinon le Biscuit n'embarquerait aucun rôle.
     */
    @Override
    public int getPriority() {
        return ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER + 10;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        // On émet uniquement dans l'access token (cible gateway) ; l'ID token n'a pas vocation à
        // porter une capacité. transformAccessToken passe ici l'AccessToken réel (il étend IDToken).
        if (!(token instanceof AccessToken accessToken)) {
            return;
        }
        try {
            Map<String, String> cfg = mappingModel.getConfig();
            List<BiscuitMinter.FactSpec> facts = factsFromConfig(cfg);
            facts.addAll(derivedFacts(cfg, userSession.getUser()));

            RealmModel realm = session.getContext().getRealm();
            BiscuitKeyManager.RootKey root = BiscuitKeyManager.rootKey(session, realm, globalConfig);
            BiscuitMinter.MintResult result =
                    BiscuitMinter.mint(accessToken, root.keyPair(), root.keyId(),
                            globalConfig.ttlSeconds(), Instant.now(), globalConfig.authorizedFacts(accessToken, facts));

            accessToken.getOtherClaims().put(claimName(cfg), result.biscuitB64());
            BiscuitAudit.logIssued("mapper", realm.getName(), result.audit());
        } catch (Exception e) {
            // Ne jamais casser l'émission du JWT : on logge et on n'ajoute simplement pas le claim.
            BiscuitAudit.logDenied("mapper", "invalid_issuance");
            throw new IllegalStateException("Biscuit mapper: invalid issuance configuration", e);
        }
    }

    private static String claimName(Map<String, String> cfg) {
        String name = cfg.get(CLAIM_NAME);
        return (name == null || name.isBlank()) ? DEFAULT_CLAIM_NAME : name.trim();
    }

    /**
     * Convertit la config du mapper (audience, required_profile, map de faits) en faits validés.
     * Réutilise {@link BiscuitFacts#validated} : mêmes règles que la voie REST.
     */
    static List<BiscuitMinter.FactSpec> factsFromConfig(Map<String, String> cfg) {
        List<BiscuitMinter.FactSpec> facts = new ArrayList<>();

        // Champs dédiés : voie gouvernée (noms validés, fixés par l'admin du client).
        String audience = cfg.get(AUDIENCE);
        if (audience != null && audience.isBlank()) throw new IllegalArgumentException("blank audience");
        if (audience != null && !audience.isBlank()) {
            facts.add(BiscuitFacts.governed("audience", List.of(audience.trim())).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }

        String profile = cfg.get(REQUIRED_PROFILE);
        if (profile != null && profile.isBlank()) throw new IllegalArgumentException("blank profile");
        if (profile != null && !profile.isBlank()) {
            facts.add(BiscuitFacts.governed("required_profile", List.of(profile.trim())).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }

        // Map libre per-client : voie restreinte — ne peut poser ni fait cœur ni fait gouverné,
        // donc ne peut pas forger/dupliquer un required_profile ou une audience.
        String rawMap = cfg.get(EXTRA_FACTS);
        if (rawMap != null && !rawMap.isBlank()) {
            Map<String, List<String>> entries = MapperTypeSerializer.deserialize(rawMap);
            for (Map.Entry<String, List<String>> entry : entries.entrySet()) {
                facts.add(BiscuitFacts.validated(entry.getKey(), entry.getValue()).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
            }
        }
        return facts;
    }

    /**
     * Faits <strong>dérivés</strong> d'attributs Keycloak : la map associe un nom de fait à un nom
     * d'attribut, dont la valeur est lue sur l'utilisateur (ou son service-account) à l'émission.
     * Voie {@link BiscuitFacts#governed} : la valeur provenant de l'identité (gouvernée par qui peut
     * éditer l'attribut), les faits gouvernés ({@code agent_id}…) sont autorisés — contrairement à la
     * map libre {@link #EXTRA_FACTS}. Un attribut absent ou blanc n'émet aucun fait.
     */
    static List<BiscuitMinter.FactSpec> derivedFacts(Map<String, String> cfg, UserModel user) {
        List<BiscuitMinter.FactSpec> facts = new ArrayList<>();
        String raw = cfg.get(DERIVED_FACTS);
        if (raw == null || raw.isBlank() || user == null) {
            return facts;
        }
        for (Map.Entry<String, List<String>> entry : MapperTypeSerializer.deserialize(raw).entrySet()) {
            String factName = entry.getKey();
            if (java.util.Set.of("required_profile", "audience", "budget_cap", "right", "rights_source").contains(factName))
                throw new IllegalArgumentException("authorization metadata cannot come from user attributes");
            String attrName = entry.getValue().isEmpty() ? null : entry.getValue().get(0);
            if (attrName == null || attrName.isBlank()) {
                continue;
            }
            String value = user.getFirstAttribute(attrName.trim());
            if (value == null || value.isBlank()) {
                continue; // attribut non présent sur l'identité → on n'émet rien
            }
            facts.add(BiscuitFacts.governed(factName, List.of(value)).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }
        return facts;
    }
}
