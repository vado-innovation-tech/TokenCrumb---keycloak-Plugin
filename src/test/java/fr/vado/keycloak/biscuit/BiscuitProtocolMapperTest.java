// SPDX-License-Identifier: Apache-2.0
package fr.vado.keycloak.biscuit;

import org.junit.jupiter.api.Test;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.MapperTypeSerializer;
import org.keycloak.protocol.oidc.mappers.OIDCAttributeMapperHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Pure mapper logic (UI config → facts) without starting Keycloak. */
class BiscuitProtocolMapperTest {

    private final BiscuitProtocolMapper mapper = new BiscuitProtocolMapper();

    private static List<BiscuitMinter.FactSpec> facts(Map<String, String> cfg) {
        return BiscuitProtocolMapper.factsFromConfig(cfg);
    }

    @Test
    void audienceAndProfileBecomeFacts() {
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.AUDIENCE, "https://gateway.example");
        cfg.put(BiscuitProtocolMapper.REQUIRED_PROFILE, "native");

        List<BiscuitMinter.FactSpec> facts = facts(cfg);
        assertEquals(2, facts.size());
        assertEquals("audience", facts.get(0).name());
        assertEquals(List.of("https://gateway.example"), facts.get(0).values());
        assertEquals("required_profile", facts.get(1).name());
        assertEquals(List.of("native"), facts.get(1).values());
    }

    @Test
    void blankAudienceAndProfileAreRefused() {
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.AUDIENCE, "   ");
        cfg.put(BiscuitProtocolMapper.REQUIRED_PROFILE, "");
        assertThrows(IllegalArgumentException.class, () -> facts(cfg));
    }

    @Test
    void mapTypeExtraFactsWithReservedOrInvalidNamesAreRejected() {
        // value as stored by the Keycloak UI for a MAP_TYPE
        Map<String, List<String>> raw = new HashMap<>();
        raw.put("tenant_id", List.of("acme"));
        raw.put("user", List.of("x"));        // reserved core name → rejected
        raw.put("1bad", List.of("x"));        // invalid Datalog name → rejected
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.EXTRA_FACTS, MapperTypeSerializer.serialize(raw));

        assertThrows(IllegalArgumentException.class, () -> facts(cfg));
    }

    @Test
    void mapTypeCannotForgeGovernedFacts() {
        // the free-form per-client map can set neither core nor governed facts: a required_profile/audience
        // cannot be forged this way (they go through their dedicated field).
        Map<String, List<String>> raw = new HashMap<>();
        raw.put("required_profile", List.of("native"));
        raw.put("audience", List.of("https://evil.example"));
        raw.put("tenant_id", List.of("acme"));
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.EXTRA_FACTS, MapperTypeSerializer.serialize(raw));

        assertThrows(IllegalArgumentException.class, () -> facts(cfg));
    }

    private static Map<String, String> derivedCfg(String factName, String attrName) {
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.DERIVED_FACTS,
                MapperTypeSerializer.serialize(Map.of(factName, List.of(attrName))));
        return cfg;
    }

    @Test
    void derivedGovernedFactReadsUserAttribute() {
        // agent_id is governed: forbidden as a literal, but allowed when derived from an attribute
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("agent_id")).thenReturn("agent-alice-007");

        List<BiscuitMinter.FactSpec> facts =
                BiscuitProtocolMapper.derivedFacts(derivedCfg("agent_id", "agent_id"), user);
        assertEquals(1, facts.size());
        assertEquals("agent_id", facts.get(0).name());
        assertEquals(List.of("agent-alice-007"), facts.get(0).values());
    }

    @Test
    void derivedRejectsCoreFactNameEvenFromAttribute() {
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("whatever")).thenReturn("forged");
        // key_id is core: rejected even through the derived (governed) path
        assertThrows(IllegalArgumentException.class, () -> BiscuitProtocolMapper.derivedFacts(derivedCfg("key_id", "whatever"), user));
    }

    @Test
    void derivedSkipsMissingAttribute() {
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("agent_id")).thenReturn(null);
        assertTrue(BiscuitProtocolMapper.derivedFacts(derivedCfg("agent_id", "agent_id"), user).isEmpty());
    }

    @Test
    void freeMapCannotGrantRightsEvenInStaticMode() {
        // In static rights mode, right(...) facts survive RoleRights.apply: they must therefore only
        // come from the deployer configuration, never from a client admin's free-form map.
        for (String name : List.of("right", "rights_source")) {
            Map<String, String> cfg = Map.of(BiscuitProtocolMapper.EXTRA_FACTS,
                    MapperTypeSerializer.serialize(Map.of(name, List.of("delete_all", "write"))));
            assertThrows(IllegalArgumentException.class, () -> facts(cfg), name);
        }
        assertTrue(BiscuitFacts.validated("right", List.of("delete_all", "write")).isEmpty());
        // the deployer path still accepts static rights
        assertTrue(BiscuitFacts.governed("right", List.of("read_file", "read")).isPresent());
        var staticCfg = BiscuitConfig.from(Map.of("BISCUIT_RIGHTS_MODE", "static",
                "BISCUIT_EXTRA_FACTS", "[{\"name\":\"right\",\"values\":[\"read_file\",\"read\"]}]"));
        assertEquals(List.of(new BiscuitMinter.FactSpec("right", List.of("read_file", "read"))),
                staticCfg.extraFacts());
    }

    @Test
    void freeMapStillRejectsAgentId() {
        Map<String, String> cfg = Map.of(BiscuitProtocolMapper.EXTRA_FACTS,
                MapperTypeSerializer.serialize(Map.of("agent_id", List.of("forged"))));
        assertThrows(IllegalArgumentException.class, () -> facts(cfg));
    }

    @Test
    void configPropertiesExposeUiFieldsAndIncludeFlags() {
        List<String> names = mapper.getConfigProperties().stream()
                .map(ProviderConfigProperty::getName).toList();
        assertTrue(names.contains(BiscuitProtocolMapper.CLAIM_NAME), names.toString());
        assertTrue(names.contains(BiscuitProtocolMapper.AUDIENCE), names.toString());
        assertTrue(names.contains(BiscuitProtocolMapper.REQUIRED_PROFILE), names.toString());
        assertTrue(names.contains(BiscuitProtocolMapper.EXTRA_FACTS), names.toString());
        assertTrue(names.contains(BiscuitProtocolMapper.DERIVED_FACTS), names.toString());
        assertTrue(names.containsAll(List.of(BiscuitProtocolMapper.ROLE_RIGHTS,
                BiscuitProtocolMapper.BUDGET_CAP, BiscuitProtocolMapper.TTL)), names.toString());
        // the "Add to access token / ID token" checkboxes are indeed added by the Keycloak helper
        assertTrue(names.contains(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN), names.toString());
    }

    @Test
    void theProfileListOffersAnchoringThroughDPoP() {
        List<String> options = mapper.getConfigProperties().stream()
                .filter(p -> BiscuitProtocolMapper.REQUIRED_PROFILE.equals(p.getName()))
                .findFirst().orElseThrow().getOptions();
        assertEquals(List.of("native", "registry_backed", BiscuitFacts.ANCHORED_PROFILE), options);
    }

    @Test
    void anchoredProfileIsNeverEmittedFromConfigAlone() {
        // The anchored profile is only set together with the DPoP key (BiscuitFacts.anchored), never alone.
        Map<String, String> cfg = Map.of(BiscuitProtocolMapper.REQUIRED_PROFILE, BiscuitFacts.ANCHORED_PROFILE);
        assertTrue(facts(cfg).isEmpty());
        assertTrue(BiscuitProtocolMapper.anchored(cfg));
        assertFalse(BiscuitProtocolMapper.anchored(Map.of(BiscuitProtocolMapper.REQUIRED_PROFILE, "native")));
    }

    @Test
    void budgetCapIsAnIntegerGovernedFact() {
        List<BiscuitMinter.FactSpec> facts = facts(Map.of(BiscuitProtocolMapper.BUDGET_CAP, " 50 "));
        assertEquals(List.of(new BiscuitMinter.FactSpec("budget_cap", List.of("50"))), facts);
        assertThrows(IllegalArgumentException.class, () -> facts(Map.of(BiscuitProtocolMapper.BUDGET_CAP, "-1")));
        assertThrows(IllegalArgumentException.class, () -> facts(Map.of(BiscuitProtocolMapper.BUDGET_CAP, "cinquante")));
        assertTrue(facts(Map.of(BiscuitProtocolMapper.BUDGET_CAP, "")).isEmpty());
    }

    @Test
    void lifetimeIsCappedByTheGlobalTtl() {
        assertEquals(300, BiscuitProtocolMapper.ttlSeconds(Map.of(), 300));
        assertEquals(100, BiscuitProtocolMapper.ttlSeconds(Map.of(BiscuitProtocolMapper.TTL, "100"), 300));
        assertEquals(300, BiscuitProtocolMapper.ttlSeconds(Map.of(BiscuitProtocolMapper.TTL, "7200"), 300));
        assertThrows(IllegalArgumentException.class, () -> BiscuitProtocolMapper.ttlSeconds(Map.of(BiscuitProtocolMapper.TTL, "0"), 300));
        assertThrows(IllegalArgumentException.class, () -> BiscuitProtocolMapper.ttlSeconds(Map.of(BiscuitProtocolMapper.TTL, "1h"), 300));
    }

    @Test
    void roleRightsAreReadPerMapperOrFallBackToGlobal() {
        assertEquals(null, BiscuitProtocolMapper.roleRights(Map.of()));
        assertEquals(null, BiscuitProtocolMapper.roleRights(Map.of(BiscuitProtocolMapper.ROLE_RIGHTS, " ")));
        assertEquals(List.of(new RoleRights.Grant("analyst", null, "list_tables", "read")),
                BiscuitProtocolMapper.roleRights(Map.of(BiscuitProtocolMapper.ROLE_RIGHTS,
                        "[{\"role\":\"analyst\",\"tool\":\"list_tables\",\"operation\":\"read\"}]")));
        assertThrows(IllegalArgumentException.class, () -> BiscuitProtocolMapper.roleRights(Map.of(
                BiscuitProtocolMapper.ROLE_RIGHTS, "[{\"role\":\"analyst\",\"tool\":\"x\",\"operation\":\"read\",\"extra\":1}]")));
    }

    @Test
    void mapperIdentity() {
        assertEquals("oidc-biscuit-mapper", mapper.getId());
        assertEquals("Biscuit Emitter", mapper.getDisplayType());
        assertEquals("openid-connect", mapper.getProtocol());
    }
}
