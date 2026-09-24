# Changelog

Toutes les évolutions notables de `keycloak-biscuit-exchange`. Format inspiré de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ; versionnage [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Durcissement — corrections de l'audit du 9 septembre 2026 (rupture)
- **Table rôle → droits** (`BISCUIT_ROLE_RIGHTS`, classe `RoleRights`) : `right("<tool>","<op>")` n'est
  émis que pour les rôles du JWT explicitement associés ; aucun droit par défaut. Fait
  `rights_source("jwt_roles")`, ou `rights_source("static_deployer")` en mode `BISCUIT_RIGHTS_MODE=static`.
  Appliquée sur les voies REST et mapper.
- **Configuration stricte** : `BISCUIT_EXTRA_FACTS`, `BISCUIT_ROLE_RIGHTS`, TTL, stratégie de clé et
  booléens invalides **refusent** la configuration (plus d'ignorance silencieuse avec `WARN`). JSON strict
  (`StrictJson` : 64 Kio, profondeur 16, clés dupliquées et valeurs non standard refusées). Faits
  gouvernés uniques, noms `^[a-z][a-z0-9_]{0,63}$`, valeurs bornées ; `budget_cap` est un entier JSON
  émis comme entier Datalog.
- **Contrat de mandat** : `expires_at(<date>)` signé dans le bloc *authority*, `required_profile("native")`
  par défaut, faits de contexte du vérificateur (`operation`, `resource`, `budget`, preuves…) réservés,
  bornes sur le nombre de rôles/faits et sur la taille du jeton émis.
- **`agent_pubkey` explicitement `null` refusé** (`400 invalid_agent_pubkey`) : plus de mandat non ancré
  renvoyé en `200` à un appelant qui demandait l'ancrage.
- **Clé racine** : stratégie par défaut `generated` (`auto` en devient l'alias, sans bascule opportuniste
  vers la clé JWT du realm) ; `realm` exige `BISCUIT_REALM_KEY_KID`. Génération refusée sans
  `BISCUIT_ALLOW_KEY_BOOTSTRAP=true` (dev mono-nœud). Chiffrement `enc:v2:` lié au realm par AAD ; seeds en
  clair ou `enc:v1:` migrées sans changer la clé publique lors d'une émission authentifiée.
- **Mapper** : cible uniquement l'access token ; une configuration invalide fait échouer l'émission au
  lieu d'omettre le claim ; les attributs utilisateur ne peuvent fournir ni profil, ni audience, ni droits.
- **Audit** au format JSON échappé, avec événement `capability_denied` sur refus.
- `SecurityContractTest` verrouille ces garanties et exporte les fixtures d'interopérabilité vérifiées
  côté Python par `MCPproxy/scripts/check_java_interop.py`.

### Ajouté
- **Ancrage d'une clé d'agent (profil 3b)** : `POST /realms/{realm}/biscuit/token` accepte désormais un
  corps JSON **facultatif** `{"agent_pubkey": "ed25519/<64 hex>"}` — sans corps, le comportement est
  strictement inchangé. La clé est écrite dans le bloc *authority* et l'émission impose
  `required_profile("hardened_biscuit_anchored")`. C'est la **seule** voie qui accepte `agent_pubkey`
  (`BiscuitFacts.requested`), distincte de `validated()` (libre) et `governed()` (config de confiance) :
  une clé posée en configuration vaudrait pour tous les échanges du realm, alors qu'une clé fournie par
  un demandeur déjà authentifié ne fait que **restreindre** son propre mandat — les droits viennent
  intégralement du JWT présenté (*proof-of-possession*, RFC 7800). Format validé strictement
  (`ed25519/` + 64 hexadécimaux, normalisés en minuscules). Erreurs : `400 invalid_agent_pubkey` (clé
  fournie mais mal formée ou non-string), `400 invalid_request` (JSON illisible, non-objet, champ
  inconnu) — contrairement aux voies de config, une valeur invalide n'est **jamais** ignorée avec un
  `WARN`, un `200` non ancré que l'appelant croirait de profil 3b étant pire qu'un refus.
  Réf. ADR-0001 et ADR-0003 du dépôt `MCPproxy`.
- **Faits dérivés d'attributs Keycloak** (champ mapper `Derived facts` / `biscuit.derived.facts`) :
  une map `nom de fait → nom d'attribut` dont la valeur est lue sur l'utilisateur (ou son
  service-account) à l'émission. Voie `BiscuitFacts.governed()` → autorise les faits **gouvernés**
  (`agent_id`, `principal_id`, `rights_source`, `spiffe_id`, `audience`, `required_profile`) car la
  valeur vient de l'identité, pas d'un texte libre ; les noms **cœur** restent refusés. Permet de
  poser `agent_id` per-client sans qu'un champ libre puisse le forger (note §A3 / §A4).
- **Protocol Mapper OIDC « Biscuit Emitter »** (`oidc-biscuit-mapper`) : seconde voie d'émission,
  **configurable par client dans l'admin console**, qui dépose le Biscuit dans un claim du JWT
  (défaut `biscuit`). Champs UI : `claim name`, `audience`, `required_profile` (liste),
  `extra facts` (éditeur clé/valeur `MAP_TYPE`), + cases access/ID token. Réutilise `BiscuitMinter`
  et la résolution de clé existante ; s'exécute après les mappers de rôles (priorité) pour embarquer
  `realm_role`/`client_role`. L'endpoint REST `/biscuit/token` reste inchangé en parallèle.
- Classe utilitaire `BiscuitFacts` : validation/conversion des faits mutualisée entre la voie REST
  (`BISCUIT_EXTRA_FACTS`) et le mapper (source de vérité unique : nom Datalog valide, noms réservés).
- `BISCUIT_EXTRA_FACTS` (clé scope `extra-facts`) : injection de faits supplémentaires dans le bloc
  *authority*, déclarés en JSON (`[{"name":...,"values":[...]}]`). L'émetteur reste générique — aucun
  fait par défaut ; permet de scoper le token (ex. `audience`, `required_profile`) sans modifier le code.
  Validation du nom (prédicat Datalog), refus des noms cœur réservés, valeurs en littéraux string
  (insensibles à l'injection) ; faits invalides ignorés avec `WARN`.
- **Fait `key_id("<kid>")`** dans le bloc *authority* + champ **`kid`** sur `GET /biscuit/public-key` :
  identifie la clé racine signataire (kid de la clé realm, ou empreinte 16 hex de la clé générée),
  pour indexer la **rotation** et la **révocation par époque** côté vérificateur. Exposé aussi via
  `BiscuitKeyManager.RootKey` (couple clé + `keyId`).
- **Audit d'émission** : ligne de journal structurée `event=capability_issued` (catégorie
  `BiscuitAudit`, `INFO`) à chaque Biscuit émis (REST ou mapper), avec `capability_id` (`jti`),
  `key_id`, `issuer`, `audience`, `required_profile`, `expires_at`, `sub`. Trace V1 — hash-chaînage /
  signature / ancrage externe restent Lot 3.

### Sécurité / durcissement
- **L'ancrage écrase tout `required_profile` de configuration** (`BiscuitFacts.anchored`). Sans ce
  retrait, un déployeur ayant configuré `required_profile("native")` produirait un mandat portant à la
  fois une clé ancrée et l'autorisation de s'en passer : l'appelant ancrerait une clé puis présenterait
  le mandat en profil 1, court-circuitant l'attestation. L'extension ouvrirait un contournement au lieu
  de fermer un trou.
- **Le mapper ne propose plus `hardened_biscuit_anchored`** dans sa liste *Required profile* (options :
  `native` / `registry_backed`). Cette voie ne peut pas ancrer de clé — `agent_pubkey` reste refusé sur
  toutes les voies de config — et le profil 3b exige une clé dans le bloc *authority* : les mandats
  ainsi émis étaient refusés à chaque appel par la gateway (« profile downgrade »). Retirer l'option
  n'efface pas une valeur **déjà enregistrée** dans un realm : vérifier les mappers existants.
- **Faits réservés à deux niveaux** (`BiscuitFacts`) : les faits **cœur** (`user`, `client`, `issuer`,
  `realm_role`, `client_role`, `jti`, `time`, `key_id`, `agent_pubkey`, `max_delegation_depth`) sont
  refusés sur toutes les voies de config ; les faits **gouvernés** (`audience`, `required_profile`,
  `agent_id`, `principal_id`, `rights_source`, `spiffe_id`) ne sont acceptés que via une voie dédiée
  (champs nommés du mapper, ou `BISCUIT_EXTRA_FACTS` déployeur) et **jamais** via la map libre
  per-client. Empêche un fait libre de forger/dupliquer un marqueur anti-downgrade ou de scoping.
- Avertissement `WARN` explicite lorsque la seed de la clé racine est persistée **en clair**
  (sans `BISCUIT_KEY_ENCRYPTION_KEY`).
- Borne anti-débordement sur `BISCUIT_TOKEN_TTL` (≤ ~10 ans) + addition saturante et clamp de
  l'expiration (plus de `DateTimeException`/overflow sur TTL démesuré).
- Nouvel env `BISCUIT_REALM_KEY_KID` : épingle la clé EdDSA **dédiée** au Biscuit en stratégie
  `realm`/`auto` (évite de réutiliser la clé de signature JWT) ; `WARN` si non épinglée.
- `GET /public-key` ne provisionne plus de clé (sémantique GET safe) : `503` tant qu'aucun
  échange n'a généré la racine.
- `publicKeyMatches` valide désormais la longueur et l'OID Ed25519 du SPKI avant comparaison.

### Modifié (rupture côté vérificateurs)
- Les rôles ne sont plus aplatis : émission de `realm_role("<r>")` et
  `client_role("<clientId>", "<r>")` (provenance conservée) au lieu de `role("<r>")`.
- Bloc *authority* enrichi : facts `issuer("<iss>")` et `jti("<uuid>")`.
- Configuration lue via le `Config.Scope` Keycloak (`--spi-realm-restapi-extension-biscuit-*` /
  `KC_SPI_*`) avec repli sur les variables d'environnement `BISCUIT_*`.

### Qualité / interne
- `docker-compose.yml` déclare une `audience` via `BISCUIT_EXTRA_FACTS` : un vérificateur refuse tout
  mandat sans `audience` dans le bloc *authority* (absente = DENY, jamais wildcard), et la voie REST
  n'en posait aucune — les jetons de la stack de démo étaient inexploitables par une gateway.
- Factorisation du code commun des endpoints (`guarded(...)`), `SecureRandom` partagé,
  copie défensive de la clé AES, constantes nommées, champ de config `volatile`.
- Préflight `OPTIONS` aligné sur le gate `enabled` (404 si désactivé).

### Tests / build
- `BiscuitAnchoringTest` (14 cas) : format et normalisation de `agent_pubkey`, réserve de config
  toujours fermée sur `validated()`/`governed()`, profil imposé et `required_profile` de config écrasé,
  autres faits de config conservés, et tous les refus du corps de requête (absent/vide/`null`,
  non-string, champ inconnu, JSON illisible ou non-objet). Plus 5 tests d'intégration de bout en bout
  dans `BiscuitExchangeIT` (ancrage réel, exchange sans corps toujours non ancré, `400` × 2, `401`).
- Nouveaux tests unitaires : `BiscuitConfigTest`, `BiscuitKeyManagerTest`, `BiscuitResourceTest`
  (Mockito). Tests temporellement déterministes.
- `jackson-databind` 2.17.2 → 2.19.4 (CVE-2025-52999, scope test).
- `maven-enforcer-plugin` (Java 17 / Maven minimal) + `cyclonedx-maven-plugin` (SBOM).
- CI GitHub Actions, `LICENSE` Apache-2.0 + `NOTICE`, `.editorconfig`.

> Le projet reste en `1.0.0-SNAPSHOT` tant qu'aucune version n'est taggée. À la première
> release : retirer `-SNAPSHOT`, tagger le commit, publier le JAR shadé et figer cette section
> sous le numéro de version.
