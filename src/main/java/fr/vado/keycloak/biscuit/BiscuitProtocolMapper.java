// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

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
 * OIDC Protocol Mapper: emits a Biscuit (signed by the realm's root key) into a token claim.
 *
 * <p>An issuance path <strong>complementary</strong> to the REST endpoint {@code /biscuit/token}
 * (which is unchanged). The advantage is that the whole mandate is configured <strong>per client, in the
 * admin console</strong> (audience, profile, per-role rights, budget cap, lifetime, facts), with no global
 * environment variable applying to every realm on the instance.</p>
 *
 * <p>{@code hardened_biscuit_anchored} profile: the agent key is the one from the DPoP proof (RFC 9449)
 * of the token request, verified by Keycloak ({@link DPoPAnchor}). Without a valid Ed25519 proof,
 * token issuance fails: never an unanchored mandate presented as anchored.</p>
 *
 * <p>Separation of concerns: the key strategy, KEK and TTL cap come from the global config
 * ({@link BiscuitConfig#fromScope} with this provider's own {@code protocol-mapper}/{@code oidc-biscuit-mapper}
 * scope, falling back to the {@code BISCUIT_*} environment variables shared with the REST endpoint); the
 * facts come from the <em>per-mapper</em> config ({@code BISCUIT_EXTRA_FACTS} is not used here). Minting
 * reuses {@link BiscuitMinter#mint} as is, so the surface touching Keycloak stays thin.</p>
 */
public class BiscuitProtocolMapper extends AbstractOIDCProtocolMapper
        implements OIDCAccessTokenMapper {

    public static final String PROVIDER_ID = "oidc-biscuit-mapper";

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
        claimName.setHelpText("Name of the JWT claim that will carry the Biscuit (base64url).");
        CONFIG_PROPERTIES.add(claimName);

        ProviderConfigProperty audience = new ProviderConfigProperty();
        audience.setName(AUDIENCE);
        audience.setLabel("Audience");
        audience.setType(ProviderConfigProperty.STRING_TYPE);
        audience.setHelpText("If not empty, adds the fact audience(\"...\") (capability scoping).");
        CONFIG_PROPERTIES.add(audience);

        ProviderConfigProperty profile = new ProviderConfigProperty();
        profile.setName(REQUIRED_PROFILE);
        profile.setLabel("Required profile");
        profile.setType(ProviderConfigProperty.LIST_TYPE);
        // hardened_biscuit_anchored: the agent key comes from the token request's DPoP proof,
        // never from configuration (agent_pubkey stays RESERVED_CORE on every config path).
        profile.setOptions(List.of("native", "registry_backed", BiscuitFacts.ANCHORED_PROFILE));
        profile.setHelpText("If set, adds required_profile(\"...\") (anti-downgrade; enforced by the "
                + "gateway). registry_backed requires an agent_id (see Derived facts) that the gateway "
                + "registry can resolve. hardened_biscuit_anchored anchors the Ed25519 key from the token "
                + "request's DPoP proof: without an Ed25519 DPoP proof, token issuance fails. "
                + "Enable \"Require DPoP bound tokens\" on the client.");
        CONFIG_PROPERTIES.add(profile);

        ProviderConfigProperty extra = new ProviderConfigProperty();
        extra.setName(EXTRA_FACTS);
        extra.setLabel("Extra facts");
        extra.setType(ProviderConfigProperty.MAP_TYPE);
        extra.setHelpText("Extra facts as name -> literal value (e.g. tenant_id). "
                + "A valid Datalog name is required; core, governed (agent_id, audience…) and "
                + "right/rights_source names are rejected.");
        CONFIG_PROPERTIES.add(extra);

        ProviderConfigProperty derived = new ProviderConfigProperty();
        derived.setName(DERIVED_FACTS);
        derived.setLabel("Derived facts (from user attributes)");
        derived.setType(ProviderConfigProperty.MAP_TYPE);
        derived.setHelpText("Derived facts: fact name -> Keycloak attribute name. The value is read "
                + "from the user (or their service account) at issuance. Governed facts are allowed "
                + "(agent_id, principal_id…) because the value comes from the identity, not from free text.");
        CONFIG_PROPERTIES.add(derived);

        ProviderConfigProperty rights = new ProviderConfigProperty();
        rights.setName(ROLE_RIGHTS);
        rights.setLabel("Role rights (JSON)");
        rights.setType(ProviderConfigProperty.TEXT_TYPE);
        rights.setHelpText("Tool rights granted per role, as JSON: "
                + "[{\"role\":\"analyst\",\"tool\":\"list_tables\",\"operation\":\"read\"}]. Add "
                + "\"client\":\"<clientId>\" for a client role. Each matching role in the JWT adds "
                + "right(tool, operation); roles without an entry grant nothing. Empty: global "
                + "BISCUIT_ROLE_RIGHTS table.");
        CONFIG_PROPERTIES.add(rights);

        ProviderConfigProperty budget = new ProviderConfigProperty();
        budget.setName(BUDGET_CAP);
        budget.setLabel("Budget cap");
        budget.setType(ProviderConfigProperty.STRING_TYPE);
        budget.setHelpText("Mandate budget cap: a non-negative integer, issued as budget_cap(N). "
                + "Empty: no cap.");
        CONFIG_PROPERTIES.add(budget);

        ProviderConfigProperty ttl = new ProviderConfigProperty();
        ttl.setName(TTL);
        ttl.setLabel("Lifetime (seconds)");
        ttl.setType(ProviderConfigProperty.STRING_TYPE);
        ttl.setHelpText("Biscuit lifetime in seconds, capped by BISCUIT_TOKEN_TTL and by the "
                + "access token's expiry. Empty: BISCUIT_TOKEN_TTL.");
        CONFIG_PROPERTIES.add(ttl);

        OIDCAttributeMapperHelper.addIncludeInTokensConfig(CONFIG_PROPERTIES, BiscuitProtocolMapper.class);
    }

    /** Global key/TTL config (falls back to env until {@link #init} has run). */
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
        return "Emits a Biscuit signed by the realm's root key into an access token claim. "
                + "Configurable per client: audience, profile (including DPoP anchoring), per-role rights, "
                + "budget, lifetime, custom facts.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return CONFIG_PROPERTIES;
    }

    /**
     * Must run <strong>after</strong> the role mappers (priorities 10–40) so that
     * {@code realm_access}/{@code resource_access} are already populated in the access token at
     * minting time — otherwise the Biscuit would carry no roles.
     */
    @Override
    public int getPriority() {
        return ProtocolMapperUtils.PRIORITY_SCRIPT_MAPPER + 10;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession,
                            KeycloakSession session, ClientSessionContext clientSessionCtx) {
        // Emit only into the access token (gateway target); the ID token is not meant to carry
        // a capability. transformAccessToken passes the real AccessToken here (it extends IDToken).
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
            // Fail closed: an invalid mapper configuration refuses token issuance.
            BiscuitAudit.logDenied("mapper", "invalid_issuance");
            throw new IllegalStateException("Biscuit mapper: invalid issuance configuration", e);
        }
    }

    private static String claimName(Map<String, String> cfg) {
        String name = cfg.get(CLAIM_NAME);
        return (name == null || name.isBlank()) ? DEFAULT_CLAIM_NAME : name.trim();
    }

    /**
     * Converts the mapper config (audience, required_profile, budget cap, fact map) into validated facts.
     * Dedicated fields go through {@link BiscuitFacts#governed}, the free-form map through
     * {@link BiscuitFacts#validated}; any rejected value fails issuance.
     */
    static List<BiscuitMinter.FactSpec> factsFromConfig(Map<String, String> cfg) {
        List<BiscuitMinter.FactSpec> facts = new ArrayList<>();

        // Dedicated fields: governed path (validated names, set by the client admin).
        String audience = cfg.get(AUDIENCE);
        if (audience != null && audience.isBlank()) throw new IllegalArgumentException("blank audience");
        if (audience != null && !audience.isBlank()) {
            facts.add(BiscuitFacts.governed("audience", List.of(audience.trim())).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }

        String profile = cfg.get(REQUIRED_PROFILE);
        if (profile != null && profile.isBlank()) throw new IllegalArgumentException("blank profile");
        // Anchored profile: set by BiscuitFacts.anchored together with the DPoP key, never alone from config.
        if (profile != null && !profile.isBlank() && !BiscuitFacts.ANCHORED_PROFILE.equals(profile.trim())) {
            facts.add(BiscuitFacts.governed("required_profile", List.of(profile.trim())).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }

        String budget = cfg.get(BUDGET_CAP);
        if (budget != null && !budget.isBlank()) {
            facts.add(BiscuitFacts.governed("budget_cap", List.of(budget.trim())).orElseThrow(() -> new IllegalArgumentException("invalid budget cap")));
        }

        // Free-form per-client map: restricted path — can set neither core nor governed facts,
        // so it cannot forge/duplicate a required_profile or an audience.
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

    /** Mapper rights table; {@code null} if not set (falls back to the global table). */
    static List<RoleRights.Grant> roleRights(Map<String, String> cfg) {
        String raw = cfg.get(ROLE_RIGHTS);
        return raw == null || raw.isBlank() ? null : RoleRights.parse(raw);
    }

    /** Mapper lifetime, never beyond the global cap. */
    static long ttlSeconds(Map<String, String> cfg, long globalTtl) {
        String raw = cfg.get(TTL);
        if (raw == null || raw.isBlank()) return globalTtl;
        if (!raw.trim().matches("[0-9]{1,10}")) throw new IllegalArgumentException("invalid mapper TTL");
        long ttl = Long.parseLong(raw.trim());
        if (ttl <= 0) throw new IllegalArgumentException("invalid mapper TTL");
        return Math.min(ttl, globalTtl);
    }

    /**
     * Facts <strong>derived</strong> from Keycloak attributes: the map associates a fact name with an
     * attribute name, whose value is read from the user (or their service account) at issuance.
     * {@link BiscuitFacts#governed} path: since the value comes from the identity (governed by whoever can
     * edit the attribute), governed facts ({@code agent_id}…) are allowed — unlike the free-form
     * map {@link #EXTRA_FACTS}. A missing or blank attribute issues no fact.
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
                continue; // attribute not present on the identity → issue nothing
            }
            facts.add(BiscuitFacts.governed(factName, List.of(value)).orElseThrow(() -> new IllegalArgumentException("invalid mapper fact")));
        }
        return facts;
    }
}
