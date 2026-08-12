# keycloak-biscuit-exchange

Extension Keycloak (provider JAR) qui échange un **access token JWT Keycloak valide** contre un
**token [Biscuit](https://biscuitsec.org)** signé Ed25519. L'extension est **purement additive** :
elle n'altère aucun flow OIDC/JWT existant — Keycloak reste un émetteur JWT standard, et un
endpoint custom frappe à la demande un Biscuit racine que vos services peuvent ensuite
**atténuer** et **vérifier hors-ligne** avec la seule clé publique.

```
[ Client ] --(password grant / code flow)--> [ Keycloak ] --> JWT standard (inchangé)
     |
     | POST /realms/{realm}/biscuit/token   (Authorization: Bearer <JWT>)
     v
[ Extension Biscuit ] --> { "biscuit": "<base64url>", "expires_at": <epoch> }
     |
     v
[ Gateway ] -> [ Service A ] -> [ Service B ]
     chaque saut peut ATTÉNUER le jeton (moindre privilège),
     chaque service VÉRIFIE HORS-LIGNE avec la clé publique exposée par GET /biscuit/public-key
```

## Compatibilité

| Composant | Version |
|---|---|
| Keycloak | **26.4.7** (Quarkus) — testé avec `quay.io/keycloak/keycloak:26.4.7` |
| biscuit-java | `org.biscuitsec:biscuit:4.0.1` (embarqué/shadé dans le JAR) |
| Java | 17+ (le JAR cible le bytecode 17) |

## Prérequis

- JDK 17 ou plus récent (JDK 21 OK).
- Docker (uniquement pour les tests d'intégration et la démo `docker compose`).
- Pas besoin de Maven : le **Maven Wrapper** (`./mvnw`) est fourni.

## Build

```bash
# Build + tests unitaires (sans Docker)
./mvnw -DskipITs package

# Build complet avec tests d'intégration Testcontainers (Docker requis)
./mvnw verify
```

Le JAR shadé est produit dans `target/keycloak-biscuit-exchange.jar`. Toutes les dépendances de
biscuit-java (protobuf, vavr, gson, re2j, eddsa) y sont **relocalisées** sous
`fr.vado.keycloak.biscuit.shaded.*` pour éviter tout conflit de classloading avec le runtime
Quarkus de Keycloak.

## Déploiement

### Sur un Keycloak existant

```bash
cp target/keycloak-biscuit-exchange.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build        # inutile en mode start-dev (build automatique)
/opt/keycloak/bin/kc.sh start
```

### Démo docker compose

```bash
./mvnw -DskipITs package
docker compose up -d
```

Démarre un Keycloak 26.4.7 en `start-dev` avec :
- le provider monté dans `/opt/keycloak/providers/` ;
- un realm de démo `biscuit-demo` importé automatiquement (user `alice` / `alice-password`,
  client public `demo-cli`, rôles realm `admin`+`user`, rôle client `orders:read`) ;
- admin console sur http://localhost:8080 (`admin` / `admin`).

## Endpoints

L'extension s'enregistre sous `/realms/{realm}/biscuit`.

### `POST /realms/{realm}/biscuit/token`

Échange un access token Keycloak valide contre un Biscuit.

- **Auth** : header `Authorization: Bearer <access_token Keycloak>`. Le JWT est validé par le
  mécanisme standard de Keycloak (signature, expiration, session utilisateur active) → `401` sinon.
- **Corps** : facultatif. S'il est présent, il ne peut porter que `{"agent_pubkey": "ed25519/<64 hex>"}`,
  qui **ancre** le mandat sur la clé de l'agent et impose le profil 3b (voir
  [Ancrer une clé d'agent](#ancrer-une-clé-dagent-profil-3b)).
- **Contenu du bloc authority du Biscuit émis** :
  - `user("<sub>")` — le sujet du JWT ;
  - `client("<azp>")` — le client pour lequel le JWT a été émis (omis si absent du JWT) ;
  - `issuer("<iss>")` — l'émetteur du JWT (claim `iss`, omis si absent) ;
  - un fact `realm_role("<r>")` par rôle **realm** (`realm_access.roles`, dédupliqués) ;
  - un fact `client_role("<clientId>", "<r>")` par rôle **client** (chaque entrée de
    `resource_access.*.roles`, qualifié par l'id du client — realm et client ne sont plus confondus) ;
  - les éventuels **faits supplémentaires** déclarés via `BISCUIT_EXTRA_FACTS` (voir Configuration) —
    aucun par défaut : l'émetteur reste générique et ne produit que les faits ci-dessus ;
  - si le corps a demandé un ancrage : `agent_pubkey("ed25519/…")` et
    `required_profile("hardened_biscuit_anchored")`, qui **remplace** tout `required_profile` de
    configuration ;
  - `key_id("<kid>")` — identifiant de la clé racine signataire (kid de la clé realm, ou empreinte de
    la clé générée) : permet la **rotation** et la **révocation par époque** côté vérificateur. Le même
    identifiant est exposé en `kid` par `GET /biscuit/public-key` ;
  - `jti("<uuid>")` — identifiant unique du Biscuit émis (pour une denylist applicative) ;
  - un check d'expiration : `check if time($t), $t < <exp>` avec
    **`exp = min(exp du JWT source, now + BISCUIT_TOKEN_TTL)`**.

Chaque émission produit aussi une **ligne d'audit** `event=capability_issued` (voir
[Audit d'émission](#audit-démission)).
- **Réponse `200`** :

```json
{ "biscuit": "<token biscuit en base64url>", "expires_at": 1765465200 }
```

- **Erreurs** : `401 {"error":"invalid_token"}` (JWT manquant/invalide/expiré/sans session),
  `400 {"error":"invalid_request"}` (JWT sans claim `sub`, corps illisible/non-objet, champ inconnu),
  `400 {"error":"invalid_agent_pubkey"}` (clé d'agent fournie mais mal formée),
  `503 {"error":"biscuit_unavailable"}` (clé racine indisponible),
  `500 {"error":"internal_error"}` (erreur inattendue — détail uniquement dans les logs serveur).

### `GET /realms/{realm}/biscuit/public-key`

Expose la clé publique racine Ed25519 pour les vérificateurs. **Sans authentification** (la clé
publique n'est pas un secret, les services doivent pouvoir la récupérer librement). Cet endpoint
**ne provisionne jamais** de clé (sémantique `GET` safe) : tant qu'aucun échange n'a généré la clé
racine, il répond `503 {"error":"biscuit_unavailable"}`. Faites d'abord un `POST /biscuit/token`.

```json
{
  "algorithm": "ed25519",
  "kid": "a1b2c3d4e5f60718",
  "public_key_hex": "1a2b…64 caractères hex…",
  "public_key_base64": "Gis…44 caractères base64…"
}
```

Le champ `kid` identifie la clé/époque courante ; il correspond au fait `key_id("<kid>")` porté par
les Biscuits signés avec cette clé. Un vérificateur peut donc indexer sa logique de rotation /
révocation par époque sur cette valeur.

### CORS

Les deux endpoints émettent les en-têtes CORS et répondent au préflight `OPTIONS`, afin d'être
appelables directement depuis un navigateur (SPA, page de démo) ou une gateway :
`Access-Control-Allow-Origin` reflète l'`Origin` de la requête (sinon `*`),
`Access-Control-Allow-Methods: GET, POST, OPTIONS`,
`Access-Control-Allow-Headers: authorization, content-type`. Pas de `Allow-Credentials` :
l'auth passe par le header `Authorization: Bearer`, jamais par cookie — les appels navigateur
utilisent donc `credentials:'omit'`.

Côté Keycloak, l'endpoint OIDC `…/protocol/openid-connect/token` n'ajoute ses propres en-têtes
CORS que si le client déclare des **Web Origins**. Le realm de démo configure pour cela
`"webOrigins": ["*"]` sur `demo-cli` (voir `src/test/resources/biscuit-demo-realm.json`) ; en
production, restreignez cette liste aux origines réellement attendues.

## Exemple complet (realm de démo)

```bash
BASE=http://localhost:8080

# 1. Login Keycloak classique (password grant) → JWT standard
JWT=$(curl -s "$BASE/realms/biscuit-demo/protocol/openid-connect/token" \
  -d 'grant_type=password&client_id=demo-cli&username=alice&password=alice-password' \
  | jq -r .access_token)

# 2. Échange JWT → Biscuit
curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" | jq
# { "biscuit": "En0KEwoEdXNlci…", "expires_at": 1765465200 }

# 3. Clé publique pour les vérificateurs
curl -s "$BASE/realms/biscuit-demo/biscuit/public-key" | jq

# 4. Sans token → 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/realms/biscuit-demo/biscuit/token"
```

Vérification hors-ligne côté service (exemple avec [biscuit-cli](https://github.com/eclipse-biscuit/biscuit-cli)) :

```bash
BISCUIT=$(curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" | jq -r .biscuit)
PUBKEY=$(curl -s "$BASE/realms/biscuit-demo/biscuit/public-key" | jq -r .public_key_hex)

echo -n "$BISCUIT" | biscuit inspect - --public-key "$PUBKEY" \
  --verify-with 'allow if user($u);' --include-time
```

Ou en Python (`pip install biscuit-python`) :

```python
from biscuit_auth import Biscuit, PublicKey, AuthorizerBuilder
from datetime import datetime, timezone

token = Biscuit.from_base64(biscuit_b64, PublicKey.from_hex(pubkey_hex))
AuthorizerBuilder(
    "time({now}); allow if user($u), realm_role(\"admin\");",
    {"now": datetime.now(tz=timezone.utc)},
).build(token).authorize()
```

### Ancrer une clé d'agent (profil 3b)

`POST /realms/{realm}/biscuit/token` accepte un corps JSON **facultatif** portant une seule clé :

```bash
curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"agent_pubkey": "ed25519/<64 hex>"}'
```

Le Biscuit émis porte alors `agent_pubkey("ed25519/…")` **et**
`required_profile("hardened_biscuit_anchored")` — le profil est imposé par l'émetteur, et un
`required_profile` déclaré en configuration est écarté pour l'occasion. Sans ce forçage, un
appelant ancrerait une clé puis présenterait le mandat en profil 1, court-circuitant
l'attestation : l'extension ouvrirait un contournement au lieu de fermer un trou.

Ancrer une clé fournie par un demandeur déjà authentifié ne fait que **restreindre** le mandat au
détenteur de la clé privée correspondante ; les droits, eux, viennent intégralement du JWT présenté
(raisonnement *proof-of-possession* de la RFC 7800). L'émetteur valide seulement le format :
`ed25519/` suivi de 64 caractères hexadécimaux, normalisés en minuscules.

C'est la **seule** voie qui accepte `agent_pubkey` : posé en configuration, il vaudrait pour tous
les échanges du realm, et il reste donc refusé sur toutes les voies de config (voir
[Faits réservés](#faits-réservés-deux-niveaux)).

Codes de retour :

| Corps | Réponse |
|---|---|
| absent, vide, `{}`, ou `{"agent_pubkey": null}` | `200` **sans** ancrage — comportement historique inchangé |
| `{"agent_pubkey": "ed25519/<64 hex>"}` | `200` ancré + profil imposé |
| clé présente mais mal formée (ou non-string) | `400 invalid_agent_pubkey` |
| JSON illisible, non-objet, ou champ inconnu | `400 invalid_request` |

Une clé **fournie** n'est donc jamais ignorée en silence : le demandeur ne peut pas recevoir un
`200` qu'il croirait de profil 3b alors que rien n'a été ancré.

> Le vérificateur en aval refuse tout mandat sans `audience` dans le bloc d'autorité. Un jeton ancré
> destiné à une gateway doit donc être émis avec `BISCUIT_EXTRA_FACTS` déclarant cette `audience`
> (voir [Configuration](#configuration)).

Décision de conception : `0003-demo-en-profil-3b-via-extension-du-spi-keycloak.md` du dépôt
`MCPproxy` (ancrage réservé à l'émetteur : ADR-0001 du même dépôt).

## Émission via Protocol Mapper (config dans l'UI)

En plus de l'endpoint REST, l'extension fournit un **Protocol Mapper** OIDC (« Biscuit Emitter »,
id `oidc-biscuit-mapper`) qui dépose le Biscuit **directement dans un claim du JWT** émis par
Keycloak. Son intérêt : la config se fait **par client, dans l'admin console**, sans toucher au code.

**Activer** : Clients → *votre client* → Client scopes → *…-dedicated* → Add mapper → By configuration
→ **Biscuit Emitter**. Champs disponibles :

| Champ UI | Effet |
|---|---|
| **Claim name** (défaut `biscuit`) | nom du claim JWT portant le Biscuit (base64url) |
| **Audience** | si non vide → fait `audience("...")` |
| **Required profile** (`native` / `registry_backed`) | → fait `required_profile("...")`. Pas de `hardened_biscuit_anchored` ici : ce profil exige une clé d'agent ancrée, que cette voie ne peut pas poser — voir [Ancrer une clé d'agent](#ancrer-une-clé-dagent-profil-3b) |
| **Extra facts** (éditeur clé→valeur) | faits custom `nom("valeur littérale")` ajoutés librement |
| **Derived facts** (éditeur clé→valeur) | faits dérivés `nom → attribut Keycloak` : la valeur est **lue sur l'utilisateur** (ou son service-account) à l'émission |
| **Add to access token / ID token** | où injecter le claim (access token par défaut) |

Le Biscuit ainsi émis porte **les mêmes faits cœur** que la voie REST (`user`, `realm_role`,
`client_role`, `issuer`, `key_id`, `jti`, check d'expiration) **plus** les faits configurés. Les
champs ont des **niveaux de confiance distincts** (voir [Faits réservés](#faits-réservés-deux-niveaux)) :

| Champ | Voie | Provenance valeur | Faits gouvernés (`agent_id`, `audience`…) |
|---|---|---|---|
| **Audience / Required profile** | gouvernée (champ dédié) | fixée par l'admin du client | ✅ (champ nommé, validé) |
| **Extra facts** | libre | texte libre per-client | ❌ refusés (ni cœur ni gouverné) |
| **Derived facts** | gouvernée (attribut) | **attribut Keycloak de l'identité** | ✅ autorisés |

> C'est pourquoi `agent_id` **ne peut pas** être tapé en littéral dans *Extra facts* (forgeable),
> mais **peut** être **dérivé** d'un attribut via *Derived facts* : la valeur vient alors de
> l'identité (gouvernée par qui peut éditer l'attribut), pas d'un champ libre. Modèle agent
> recommandé : agent = client avec **service-account**, `agent_id` porté comme attribut de ce compte.

```jsonc
// access token après activation du mapper (audience + required_profile + tenant_id)
{
  "sub": "…", "realm_access": { "roles": ["admin"] },
  "biscuit": "En0KEwoEdXNlci…"   // ← Biscuit signé, à vérifier hors-ligne avec /public-key
}
```

**REST vs mapper** — les deux coexistent, choisissez selon le besoin :

| | REST `/biscuit/token` | Protocol Mapper |
|---|---|---|
| Obtention | échange explicite à la demande | claim dans le JWT, dès le login/refresh |
| Appels | 2 (login + échange) | 1 (login) |
| Config des faits | globale (`BISCUIT_EXTRA_FACTS`, au démarrage) | **par client, dans l'UI** |
| Durée de vie | `BISCUIT_TOKEN_TTL` | idem (calée sur le cycle du JWT) |

> Le mapper **émet** seulement ; l'`audience`/`required_profile` doivent être **vérifiés côté
> gateway** (anti-downgrade). Mettre un Biscuit dans le JWT en augmente la taille (compact,
> ~centaines d'octets) — à garder en tête s'il transite à chaque requête.

## Configuration

La configuration est lue **une fois au démarrage**. Chaque option est résolue d'abord depuis le
`Config.Scope` Keycloak — option `--spi-realm-restapi-extension-biscuit-<clé>` ou variable
`KC_SPI_REALM_RESTAPI_EXTENSION_BISCUIT_<CLÉ>` (clés : `enabled`, `token-ttl`, `key-strategy`,
`realm-key-kid`, `key-encryption-key`, `extra-facts`) — puis, à défaut, depuis les variables d'environnement
`BISCUIT_*` ci-dessous. La config est **globale** (pas par-realm) ; un changement nécessite un
redémarrage.

| Variable d'env (repli) | Défaut | Description |
|---|---|---|
| `BISCUIT_ENABLED` | `true` | `false` → les endpoints répondent `404` (extension désactivée sans redéploiement). |
| `BISCUIT_TOKEN_TTL` | `300` | Durée de vie max du Biscuit en secondes. L'expiration effective est `min(exp du JWT, now + TTL)`. Gardez-la courte (pas de révocation, voir limites). Bornée à `315360000` (~10 ans) : une valeur supérieure est ramenée à ce maximum (au-delà l'expiration dépasserait les dates formatables). |
| `BISCUIT_KEY_STRATEGY` | `auto` | `auto` : clé EdDSA/Ed25519 du realm si exploitable, sinon clé générée. `realm` : exige une clé realm (sinon `503`). `generated` : toujours la clé générée/persistée. |
| `BISCUIT_REALM_KEY_KID` | *(non définie)* | *(stratégies `realm`/`auto`)* kid de la clé EdDSA du realm à **dédier** au Biscuit. Si définie, seule la clé de ce kid est éligible — évite de réutiliser par accident la clé de signature JWT du realm. Si absente, la première clé EdDSA active est utilisée **avec un `WARN`** invitant à l'épingler. |
| `BISCUIT_KEY_ENCRYPTION_KEY` | *(non définie)* | Clé AES-256 (64 caractères hex ou base64 de 32 octets) pour chiffrer la seed générée avant persistance (AES-GCM). Sans elle, la seed est stockée en clair (un `WARN` est émis à la génération, voir ci-dessous). |
| `BISCUIT_EXTRA_FACTS` | *(non définie)* | Faits supplémentaires à injecter dans le bloc authority, en **JSON** : un tableau d'objets `{"name": ..., "values": [...]}`. Permet de scoper le token sans toucher au code (ex. `audience`, `required_profile`). Voir ci-dessous. |

### `BISCUIT_EXTRA_FACTS` — émetteur générique, faits déclarés en config

Le plugin est un **émetteur Biscuit générique** : par défaut il ne produit que les faits issus du
JWT (`user`, `client`, `issuer`, `realm_role`, `client_role`, `jti`). `BISCUIT_EXTRA_FACTS` permet
d'ajouter des faits propres à un déploiement **sans modifier le code** — les valeurs métier (MCP ou
autre) restent de la configuration. Un déploiement qui ne la définit pas n'émet **aucun** champ en plus.

```yaml
environment:
  # Scoping pour une gateway MCP : audience + profil exigé
  BISCUIT_EXTRA_FACTS: >-
    [{"name":"audience","values":["biscuitmcp://exado-gateway"]},
     {"name":"required_profile","values":["native"]}]
```

Produit, en plus des faits JWT : `audience("biscuitmcp://exado-gateway")` et `required_profile("native")`.

Règles de validation (faits invalides **ignorés** avec un `WARN`, l'émission ne plante jamais) :

- le **nom** doit être un prédicat Datalog valide : `^[a-z][a-zA-Z0-9_]*$` ;
- les noms **réservés** sont refusés selon le niveau de la voie (voir
  [Faits réservés](#faits-réservés-deux-niveaux)). `BISCUIT_EXTRA_FACTS` est une config **déployeur de
  confiance** (voie *gouvernée*) : elle peut poser un fait gouverné comme `audience`/`required_profile`,
  mais jamais un fait **cœur** (`user`, `key_id`, `jti`…) ;
- les `values` sont des littéraux **string** (insensibles à l'injection Datalog, comme les faits JWT) ;
- un JSON illisible ou qui n'est pas un tableau ⇒ aucun fait supplémentaire (toujours un `WARN`).

> **Portée** : config **globale** (tous les realms de l'instance), lue au démarrage. Le plugin se
> contente d'**émettre** ces faits ; leur **enforcement** (ex. refus anti-downgrade sur
> `required_profile`) relève du vérificateur/gateway en aval, pas de l'émetteur.

### Faits réservés (deux niveaux)

Pour protéger la sémantique de sécurité, deux ensembles de noms ne sont pas librement configurables :

- **Faits cœur** (`user`, `client`, `issuer`, `realm_role`, `client_role`, `jti`, `time`, `key_id`,
  `agent_pubkey`, `max_delegation_depth`) : frappés par le moteur (ou réservés pour le profil 3b /
  la chaîne de cautions, dérivés du modèle Keycloak — jamais d'une valeur fournie en config).
  **Refusés sur toutes les voies de configuration.** Seule exception, et par un canal distinct :
  `agent_pubkey` fourni **dans le corps d'une requête d'échange authentifiée** (voir
  [Ancrer une clé d'agent](#ancrer-une-clé-dagent-profil-3b)) — une clé posée en config vaudrait pour
  tous les échanges du realm, une clé fournie par le demandeur ne fait que restreindre son propre mandat.
- **Faits gouvernés** (`audience`, `required_profile`, `agent_id`, `principal_id`, `rights_source`,
  `spiffe_id`) : sensibles (anti-downgrade, scoping, identité agent). Acceptés **uniquement par une
  voie dédiée** — champs nommés du mapper, ou `BISCUIT_EXTRA_FACTS` (déployeur) — **jamais** par la
  map libre **Extra facts** per-client. Cela empêche un fait libre de **forger ou dupliquer** un
  `required_profile`/`audience`.

Tout autre nom (ex. `tenant_id`) est un fait métier libre, accepté sur toutes les voies.

### Audit d'émission

Chaque Biscuit émis (REST ou mapper) produit **une ligne de journal** structurée, catégorie
`fr.vado.keycloak.biscuit.BiscuitAudit`, niveau `INFO` :

```text
event=capability_issued path=rest realm=biscuit-demo capability_id=<jti> key_id=<kid> \
  issuer=<iss> audience=<aud> required_profile=<rp> expires_at=<epoch> sub=<sub>
```

`path` vaut `rest` ou `mapper` ; les champs absents valent `-`. Démontrable via
`docker compose logs keycloak | grep capability_issued`.

> **Périmètre V1.** C'est une trace d'émission exploitable, **pas** un journal inviolable : le
> hash-chaînage, la signature et l'ancrage externe du journal (spec §3.7(d)) sont **Lot 3**. Une
> montée vers l'Event SPI Keycloak (événements visibles dans l'admin console) est un durcissement
> post-V1.

Exemple docker :

```yaml
environment:
  BISCUIT_TOKEN_TTL: "120"
  BISCUIT_KEY_STRATEGY: "auto"
  BISCUIT_KEY_ENCRYPTION_KEY: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
```

## Gestion des clés — choix retenu

La clé racine Ed25519 qui signe les Biscuits est résolue ainsi (stratégie `auto`, le défaut) :

1. **Clé EdDSA du realm** (option préférée) : si le realm possède une clé de signature active
   `EdDSA` sur la courbe `Ed25519` (Realm settings → Keys → Add provider → `eddsa-generated`),
   l'extension en extrait la seed et signe les Biscuits avec. Avantage : la clé est gérée par le
   `KeyManager` Keycloak (stockage, console d'admin, rotation outillée). Une vérification croisée
   (clé publique dérivée == clé publique du realm) garantit qu'une extraction incorrecte ne peut
   pas produire de tokens invalides silencieusement.
   ⚠️ Cette clé peut aussi servir à signer des JWT si vous l'activez comme algorithme de realm —
   évitez le double usage en **épinglant** une clé dédiée via `BISCUIT_REALM_KEY_KID` (le kid de la clé
   EdDSA réservée au Biscuit), ou utilisez `generated`. Sans épinglage, la première clé EdDSA active est
   retenue et un `WARN` est journalisé.
2. **Clé générée** (fallback — le cas courant, un realm n'a pas de clé EdDSA par défaut) : au
   premier échange, l'extension génère une paire Ed25519 et persiste la **seed (hex) dans un
   attribut du realm** (`biscuit.root.key`). Les démarrages suivants la rechargent.
   - Si `BISCUIT_KEY_ENCRYPTION_KEY` est définie, la seed est chiffrée **AES-256-GCM** avant
     persistance (format `enc:v1:<base64(iv‖ciphertext)>`). Si la valeur stockée est chiffrée et
     que la variable disparaît, l'extension répond `503` avec un log explicite (jamais de
     régénération silencieuse).
   - Sans cette variable, la seed est stockée **en clair** dans la base Keycloak (un `WARN` est émis à
     la génération) — c'est le même niveau de protection que les client secrets Keycloak (eux aussi en
     clair en base). Assumé et documenté ; chiffrez si votre modèle de menace l'exige.

### Rotation de la clé

Il n'y a pas de rotation automatique. Procédure manuelle :

- **Stratégie `generated`** : supprimez l'attribut de realm `biscuit.root.key`
  (Admin REST : `PUT /admin/realms/{realm}` avec l'attribut retiré, ou directement en base), puis
  refaites un échange — une nouvelle clé est générée. **Tous les Biscuits déjà émis deviennent
  immédiatement invalides**, ce qui est le comportement voulu avec des TTL courts : au pire
  `BISCUIT_TOKEN_TTL` secondes de tokens perdus, les clients refont simplement un échange.
- **Stratégie `realm`** : faites tourner la clé EdDSA du realm via la console Keycloak (ajouter le
  nouveau provider de clé, passer l'ancien en `disabled`). Même effet d'invalidation.
- Dans les deux cas, les vérificateurs doivent **re-récupérer `GET /biscuit/public-key`** après
  rotation. Si vos services mettent la clé en cache, prévoyez un TTL de cache court ou un refresh
  sur échec de vérification.

## Tests

- Unitaires (sans Docker) :
  - `BiscuitMinterTest` : construction du Biscuit, syntaxe datalog, round-trip
    sérialisation/vérification, bornage de l'expiration, non-injection datalog via les claims ;
  - `SeedExtractorTest` : extraction de seed depuis de vraies clés Ed25519 JDK + vérification
    croisée de la clé publique dérivée (la voie « clé realm ») ;
  - `KeyEncryptionTest` : round-trip AES-GCM et échec propre avec une mauvaise clé.
- `BiscuitExchangeIT` (intégration, Testcontainers + `quay.io/keycloak/keycloak:26.4.7`) :
  login password grant → échange JWT→Biscuit → vérification hors-ligne du Biscuit avec la clé
  publique exposée (authorizer biscuit-java), bornage par l'exp du JWT, expiration,
  falsification, 401.

```bash
./mvnw verify          # tout
./mvnw -DskipITs test  # unitaires seulement
```

## Limites connues

- **Pas de révocation des Biscuits émis.** Un Biscuit est un bearer token vérifiable hors-ligne :
  une fois émis, il est valable jusqu'à son expiration même si la session Keycloak est fermée ou
  l'utilisateur désactivé. **Gardez `BISCUIT_TOKEN_TTL` court** (défaut 300 s) et refaites des
  échanges plutôt que de faire vivre des tokens longs.
- **Les rôles proviennent des claims du JWT**, pas d'une requête en base : seuls les rôles
  réellement présents dans l'access token (selon les client scopes) sont recopiés. Les rôles realm
  sont émis comme `realm_role("<r>")` et les rôles client comme `client_role("<clientId>", "<r>")` :
  la provenance est conservée, les homonymes realm/client restent distincts.
- **biscuit-java 4.0.1 est en retard sur la spec Biscuit v3.x** : blocs de génération v2, pas de
  substitution de paramètres côté builder (l'extension utilise l'API programmatique de facts pour
  éviter toute injection datalog). L'interopérabilité de vérification avec les implémentations
  Rust/Python est assurée.
- **Première génération de clé en cluster multi-nœuds** : la génération au premier usage est
  verrouillée par nœud, pas globalement. Deux nœuds frappant leur tout premier Biscuit au même
  instant peuvent générer deux clés (le dernier write gagne ; les Biscuits signés par la clé
  perdante sont invalides). Mitigation : pré-provisionner la clé (un premier appel au déploiement)
  ou utiliser la stratégie `realm`.
- Le endpoint `/public-key` n'expose que la clé **courante** : pas d'historique multi-clés pendant
  une rotation (les vérificateurs doivent basculer en même temps).
