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
import org.keycloak.representations.dpop.DPoP;
import org.keycloak.services.util.DPoPUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Protocol Mapper OIDC : émet un Biscuit (signé par la clé racine du realm) dans un claim du token.
 *
 * <p>Voie d'émission <strong>complémentaire</strong> à l'endpoint REST {@code /biscuit/token}
 * (qui reste inchangé). Son intérêt : tout le mandat se configure <strong>par client, dans l'admin
 * console</strong> (audience, profil, droits par rôle, plafond de budget, durée de vie, faits), sans
 * variable d'environnement globale qui s'appliquerait à tous les realms de l'instance.</p>
 *
 * <p>Profil {@code hardened_biscuit_anchored} : la clé d'agent est celle de la preuve DPoP (RFC 9449)
 * de la requête de token, vérifiée par Keycloak ({@link DPoPAnchor}). Sans preuve Ed25519 valide,
 * l'émission du token échoue : jamais de mandat non ancré présenté comme 3b.</p>
 *
 * <p>Séparation des responsabilités : la stratégie de clé et le TTL plafond viennent de la config
 * globale ({@link BiscuitConfig#fromScope}) ; les faits viennent de la config <em>par-mapper</em>. La
 * frappe réutilise telle quelle {@link BiscuitMinter#mint}, donc la surface qui touche Keycloak reste
 * mince.</p>
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
    static final String ROLE_RIGHTS = "biscuit.role.rights";
    static final String BUDGET_CAP = "biscuit.budget.cap";
    static final String TTL = "biscuit.ttl";
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
        // hardened_biscuit_anchored : la clé d'agent vient de la preuve DPoP de la requête de token,
        // jamais de la configuration (agent_pubkey reste RESERVED_CORE sur toute voie de config).
        profile.setOptions(List.of("native", "registry_backed", BiscuitFacts.ANCHORED_PROFILE));
        profile.setHelpText("Si défini, ajoute required_profile(\"...\") (anti-downgrade ; enforcé côté "
                + "gateway). registry_backed suppose un agent_id (voir Derived facts) résoluble par le "
                + "registre de la gateway. hardened_biscuit_anchored ancre la clé Ed25519 de la preuve "
                + "DPoP de la requête de token : sans preuve DPoP Ed25519, l'émission du token échoue. "
                + "Activer « Require DPoP bound tokens » sur le client.");
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

        ProviderConfigProperty rights = new ProviderConfigProperty();
        rights.setName(ROLE_RIGHTS);
        rights.setLabel("Role rights (JSON)");
        rights.setType(ProviderConfigProperty.TEXT_TYPE);
        rights.setHelpText("Droits d'outils accordés par rôle, en JSON : "
                + "[{\"role\":\"analyst\",\"tool\":\"list_tables\",\"operation\":\"read\"}]. Ajouter "
                + "\"client\":\"<clientId>\" pour un rôle client. Chaque rôle présent dans le JWT émet "
                + "right(tool, operation) ; aucun droit sans correspondance. Vide : table globale "
                + "BISCUIT_ROLE_RIGHTS.");
        CONFIG_PROPERTIES.add(rights);

        ProviderConfigProperty budget = new ProviderConfigProperty();
        budget.setName(BUDGET_CAP);
        budget.setLabel("Budget cap");
        budget.setType(ProviderConfigProperty.STRING_TYPE);
        budget.setHelpText("Plafond de budget du mandat : entier positif ou nul, émis budget_cap(N). "
                + "Vide : aucun plafond.");
        CONFIG_PROPERTIES.add(budget);

        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName(TTL);
        ttl.setLabel("Lifetime (seconds)");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setHelpText("Durée de vie du Biscuit en secondes, plafonnée par BISCUIT_TOKEN_TTL et par "
                + "l'expiration de l'access token. Vide : BISCUIT_TOKEN_TTL.");
        CONFIG_PROPERTIES.add(ttl);

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
        return "Émet un Biscuit signé par la clé racine du realm dans un claim de l'access token. "
                + "Configurable par client : audience, profil (dont ancrage DPoP), droits par rôle, "
                + "budget, durée de vie, faits custom.";
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
            List<RoleRights.Grant> grants = roleRights(cfg);
            facts = grants == null ? globalConfig.authorizedFacts(accessToken, facts)
                    : RoleRights.apply(accessToken, facts, grants, false);
            if (anchored(cfg)) {
                DPoP proof = session.getAttribute(DPoPUtil.DPOP_SESSION_ATTRIBUTE, DPoP.class);
                String header = session.getContext().getHttpRequest().getHttpHeaders()
                        .getHeaderString("DPoP");
                facts = BiscuitFacts.anchored(facts,
                        DPoPAnchor.agentPubkey(header, proof == null ? null : proof.getThumbprint()));
            }

            RealmModel realm = session.getContext().getRealm();
            BiscuitKeyManager.RootKey root = BiscuitKeyManager.rootKey(session, realm, globalConfig);
            BiscuitMinter.MintResult result =
                    BiscuitMinter.mint(accessToken, root.keyPair(), root.keyId(),
                            ttlSeconds(cfg, globalConfig.ttlSeconds()), Instant.now(), facts);

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
        // Profil ancré : posé par BiscuitFacts.anchored avec la clé DPoP, jamais seul depuis la config.
        if (profile != null && !profile.isBlank() && !BiscuitFacts.ANCHORED_PROFILE.equals(profile.trim())) {
            facts.add(BiscuitFacts.governed("required_profile", List.of(profile.trim())).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }

        String budget = cfg.get(BUDGET_CAP);
        if (budget != null && !budget.isBlank()) {
            facts.add(BiscuitFacts.governed("budget_cap", List.of(budget.trim())).orElseThrow(() -> new IllegalArgumentException("invalid budget cap")));
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

    static boolean anchored(Map<String, String> cfg) {
        String profile = cfg.get(REQUIRED_PROFILE);
        return profile != null && BiscuitFacts.ANCHORED_PROFILE.equals(profile.trim());
    }

    /** Table de droits du mapper ; {@code null} si non renseignée (repli sur la table globale). */
    static List<RoleRights.Grant> roleRights(Map<String, String> cfg) {
        String raw = cfg.get(ROLE_RIGHTS);
        return raw == null || raw.isBlank() ? null : RoleRights.parse(raw);
    }

    /** Durée de vie du mapper, jamais au-delà du plafond global. */
    static long ttlSeconds(Map<String, String> cfg, long globalTtl) {
        String raw = cfg.get(TTL);
        if (raw == null || raw.isBlank()) return globalTtl;
        if (!raw.trim().matches("[0-9]{1,10}")) throw new IllegalArgumentException("invalid mapper TTL");
        long ttl = Long.parseLong(raw.trim());
        if (ttl <= 0) throw new IllegalArgumentException("invalid mapper TTL");
        return Math.min(ttl, globalTtl);
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
