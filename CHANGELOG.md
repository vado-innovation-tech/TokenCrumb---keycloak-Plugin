# Changelog

Toutes les évolutions notables de `keycloak-biscuit-exchange`. Format inspiré de
[Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) ; versionnage [SemVer](https://semver.org/lang/fr/).

## [Non publié]

### Ajouté
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
- Factorisation du code commun des endpoints (`guarded(...)`), `SecureRandom` partagé,
  copie défensive de la clé AES, constantes nommées, champ de config `volatile`.
- Préflight `OPTIONS` aligné sur le gate `enabled` (404 si désactivé).

### Tests / build
- Nouveaux tests unitaires : `BiscuitConfigTest`, `BiscuitKeyManagerTest`, `BiscuitResourceTest`
  (Mockito). Tests temporellement déterministes.
- `jackson-databind` 2.17.2 → 2.19.4 (CVE-2025-52999, scope test).
- `maven-enforcer-plugin` (Java 17 / Maven minimal) + `cyclonedx-maven-plugin` (SBOM).
- CI GitHub Actions, `LICENSE` Apache-2.0 + `NOTICE`, `.editorconfig`.

> Le projet reste en `1.0.0-SNAPSHOT` tant qu'aucune version n'est taggée. À la première
> release : retirer `-SNAPSHOT`, tagger le commit, publier le JAR shadé et figer cette section
> sous le numéro de version.
