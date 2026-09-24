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

/** Logique pure du mapper (config UI → faits) sans démarrer Keycloak. */
class BiscuitProtocolMapperTest {

    private final BiscuitProtocolMapper mapper = new BiscuitProtocolMapper();

    private static List<BiscuitMinter.FactSpec> facts(Map<String, String> cfg) {
        return BiscuitProtocolMapper.factsFromConfig(cfg);
    }

    @Test
    void audienceAndProfileBecomeFacts() {
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.AUDIENCE, "biscuitmcp://exado-gateway");
        cfg.put(BiscuitProtocolMapper.REQUIRED_PROFILE, "native");

        List<BiscuitMinter.FactSpec> facts = facts(cfg);
        assertEquals(2, facts.size());
        assertEquals("audience", facts.get(0).name());
        assertEquals(List.of("biscuitmcp://exado-gateway"), facts.get(0).values());
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
    void mapTypeExtraFactsAreParsedAndFiltered() {
        // valeur telle que stockée par l'UI Keycloak pour un MAP_TYPE
        Map<String, List<String>> raw = new HashMap<>();
        raw.put("tenant_id", List.of("exado"));
        raw.put("user", List.of("x"));        // nom cœur réservé → ignoré
        raw.put("1bad", List.of("x"));        // nom Datalog invalide → ignoré
        Map<String, String> cfg = new HashMap<>();
        cfg.put(BiscuitProtocolMapper.EXTRA_FACTS, MapperTypeSerializer.serialize(raw));

        assertThrows(IllegalArgumentException.class, () -> facts(cfg));
    }

    @Test
    void mapTypeCannotForgeGovernedFacts() {
        // la map libre per-client ne peut poser ni fait cœur ni fait gouverné : impossible de forger
        // un required_profile/audience par ce biais (ils passent par leur champ dédié).
        Map<String, List<String>> raw = new HashMap<>();
        raw.put("required_profile", List.of("native"));
        raw.put("audience", List.of("biscuitmcp://evil"));
        raw.put("tenant_id", List.of("exado"));
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
        // agent_id est gouverné : interdit en littéral, mais autorisé dérivé d'un attribut
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
        // key_id est cœur : refusé même par la voie dérivée (gouvernée)
        assertThrows(IllegalArgumentException.class, () -> BiscuitProtocolMapper.derivedFacts(derivedCfg("key_id", "whatever"), user));
    }

    @Test
    void derivedSkipsMissingAttribute() {
        UserModel user = mock(UserModel.class);
        when(user.getFirstAttribute("agent_id")).thenReturn(null);
        assertTrue(BiscuitProtocolMapper.derivedFacts(derivedCfg("agent_id", "agent_id"), user).isEmpty());
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
        // les cases "Add to access token / ID token" sont bien ajoutées par le helper Keycloak
        assertTrue(names.contains(OIDCAttributeMapperHelper.INCLUDE_IN_ACCESS_TOKEN), names.toString());
    }

    @Test
    void theProfileListNeverOffersAProfileThisPathCannotHonour() {
        // Cette voie ne peut pas ancrer de clé (agent_pubkey est RESERVED_CORE sur toute voie de
        // config) : proposer hardened_biscuit_anchored ne produirait que des mandats refusés à
        // chaque appel par la gateway (« profile downgrade »). Seul POST /biscuit/token y donne accès.
        List<String> options = mapper.getConfigProperties().stream()
                .filter(p -> BiscuitProtocolMapper.REQUIRED_PROFILE.equals(p.getName()))
                .findFirst().orElseThrow().getOptions();
        assertFalse(options.contains(BiscuitFacts.ANCHORED_PROFILE), options.toString());
        assertEquals(List.of("native", "registry_backed"), options);
    }

    @Test
    void mapperIdentity() {
        assertEquals("oidc-biscuit-mapper", mapper.getId());
        assertEquals("Biscuit Emitter", mapper.getDisplayType());
        assertEquals("openid-connect", mapper.getProtocol());
    }
}
