# TokenCrumb — Keycloak Plugin

[![CI](https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin/actions/workflows/ci.yml/badge.svg)](https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Keycloak 26.4.7](https://img.shields.io/badge/Keycloak-26.4.7-4d4d4d.svg)](https://www.keycloak.org/)
[![Java 17+](https://img.shields.io/badge/Java-17%2B-orange.svg)](https://adoptium.net/)

A Keycloak extension that turns a valid Keycloak access token into an Ed25519-signed
[Biscuit](https://biscuitsec.org) capability token. Unlike a JWT, a Biscuit can be **attenuated**
by each service it passes through (least privilege for chained services or AI agents) and
**verified offline** with only the root public key. The extension is purely additive: Keycloak's
OIDC/JWT flows are unchanged. It is part of TokenCrumb, a set of components for issuing and
verifying Biscuit tokens.

```text
[ Client ] --(password grant / code flow)--> [ Keycloak ] --> standard JWT (unchanged)
     |
     | POST /realms/{realm}/biscuit/token   (Authorization: Bearer <JWT>)
     v
[ Biscuit extension ] --> { "biscuit": "<base64url>", "expires_at": <epoch>, "revocation_ids": [...] }
     |
     v
[ Gateway ] -> [ Service A ] -> [ Service B ]
     each hop can ATTENUATE the token (least privilege),
     each service VERIFIES OFFLINE with the root public key exposed by GET /biscuit/public-key
```

## Quickstart

```bash
./mvnw -DskipITs package   # builds target/tokencrumb-keycloak-plugin.jar (Docker not needed)
docker compose up -d       # Keycloak 26.4.7 with the biscuit-demo realm, on http://localhost:8080
```

Then follow the [full example](#full-example-demo-realm) with `curl`, or run the Python client in
[examples/python/](examples/python/), which exchanges a JWT for a Biscuit and verifies it offline.

## Concepts

Biscuit terms (authority block, attenuation, authorizer, root key, revocation identifier) keep
their meaning from the [Biscuit specification](https://github.com/eclipse-biscuit/biscuit/blob/main/SPECIFICATIONS.md).
The terms below are **TokenCrumb conventions, not Biscuit concepts**: the extension encodes them
as ordinary facts in the authority block, and a downstream gateway enforces them.

- **Mandate**: the authority block issued for a user or an agent. It states who the holder is
  (`user`, `client`, roles), what it may do (`right("<tool>", "<operation>")`) and under which
  constraints (`audience`, `budget_cap`, expiry, `required_profile`).
- **Gateway**: the downstream service (for example an MCP gateway) whose authorizer checks every
  call against the mandate. The gateway, not this extension, enforces the conventions below.
- **Profile** (`required_profile` fact): what the gateway must demand from the caller, beyond
  holding the token. `native` (the default): the Biscuit is a plain bearer token.
  `registry_backed`: the gateway must resolve the mandate's `agent_id` in its agent registry.
  `hardened_biscuit_anchored` (called *the anchored profile* below): the mandate carries the agent's Ed25519 public key
  (`agent_pubkey`), and the caller must prove possession of the matching private key on every call.
- **Anti-downgrade**: the gateway rejects a mandate presented under a weaker profile than its
  `required_profile`.

## Compatibility

| Component | Version |
|---|---|
| Keycloak | **26.4.7** (Quarkus); tested with `quay.io/keycloak/keycloak:26.4.7` |
| biscuit-java | `org.biscuitsec:biscuit:4.0.1` (bundled and shaded into the JAR) |
| Java | 17+ (the JAR targets Java 17 bytecode) |

## Prerequisites

- JDK 17 or newer (JDK 21 works).
- Docker (only for the integration tests and the `docker compose` demo).
- No Maven installation needed: the **Maven Wrapper** (`./mvnw`) is included.

## Build

```bash
# Build + unit tests (no Docker)
./mvnw -DskipITs package

# Full build with Testcontainers integration tests (Docker required)
./mvnw verify
```

The shaded JAR is produced at `target/tokencrumb-keycloak-plugin.jar`. All of biscuit-java's
dependencies (protobuf, vavr, gson, re2j, eddsa) are **relocated** under
`fr.vado.keycloak.biscuit.shaded.*` to avoid any classloading conflict with Keycloak's Quarkus
runtime.

Java classes live in `fr.vado.keycloak.biscuit` (log category
`fr.vado.keycloak.biscuit.BiscuitAudit`); the Maven coordinates are
`fr.vado.tokencrumb:tokencrumb-keycloak-plugin`.

## Deployment

### On an existing Keycloak

```bash
cp target/tokencrumb-keycloak-plugin.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build        # not needed in start-dev mode (automatic build)
/opt/keycloak/bin/kc.sh start
```

No root key exists out of the box: until one is provisioned, both endpoints return
`503 biscuit_unavailable`. See [Key management](#key-management).

### docker compose demo

```bash
./mvnw -DskipITs package
docker compose up -d
```

Starts Keycloak 26.4.7 in `start-dev` with:

- the extension JAR mounted in `/opt/keycloak/providers/`;
- a `biscuit-demo` realm imported automatically (user `alice` / `alice-password`,
  public client `demo-cli`, realm roles `admin` and `user`, client role `orders:read`);
- development key bootstrap enabled, so the first exchange generates the realm's root key;
- `BISCUIT_EXTRA_FACTS` set to `audience("https://gateway.example")`, so Biscuits issued by the
  REST endpoint carry an audience;
- the admin console at <http://localhost:8080> (`admin` / `admin`).

The `demo-cli` client also has a [protocol mapper](#issuance-via-a-protocol-mapper-configured-in-the-admin-console)
configured, so its access tokens already carry a `biscuit` claim.

## Endpoints

The extension registers itself under `/realms/{realm}/biscuit`.

### `POST /realms/{realm}/biscuit/token`

Exchanges a valid Keycloak access token for a Biscuit.

- **Auth**: `Authorization: Bearer <Keycloak access_token>` header. The JWT is validated by
  Keycloak's standard mechanism (signature, expiry, active user session); otherwise the response
  is `401`.
- **Body**: optional. If present, it may only carry `{"agent_pubkey": "ed25519/<64 hex>"}`,
  which **anchors** the mandate to the agent key and enforces the anchored profile (see
  [Anchoring an agent key](#anchoring-an-agent-key)).
- **Contents of the authority block**:
  - `user("<sub>")`: the JWT subject;
  - `client("<azp>")`: the client the JWT was issued for (omitted if absent from the JWT);
  - `issuer("<iss>")`: the JWT issuer (`iss` claim, omitted if absent);
  - one `realm_role("<r>")` fact per **realm** role (`realm_access.roles`, deduplicated);
  - one `client_role("<clientId>", "<r>")` fact per **client** role (each entry of
    `resource_access.*.roles`, qualified by the client id, so realm and client roles are never
    conflated);
  - any **additional facts** declared in `BISCUIT_EXTRA_FACTS` (see
    [Configuration](#configuration)); none by default, as the issuer stays generic;
  - `right("<tool>", "<operation>")` for each JWT role mapped to a right by
    `BISCUIT_ROLE_RIGHTS` (see [Rights per role](#rights-per-role--biscuit_role_rights)), plus
    `rights_source("jwt_roles")` (or `rights_source("static_deployer")` in static mode);
  - `required_profile("native")` if the configuration does not declare one;
  - if the body requested anchoring: `agent_pubkey("ed25519/…")` and
    `required_profile("hardened_biscuit_anchored")`, which **replaces** any configured
    `required_profile`;
  - `key_id("<kid>")`: an informational identifier of the signing root key (the pinned realm
    key's kid, or the first 16 hex characters of the generated public key), for audit and
    rotation bookkeeping. Verifiers select the root key with the envelope's `root_key_id`, not
    with this fact (see [Root key selection and rotation](#root-key-selection-and-rotation));
  - `jti("<uuid>")`: a unique identifier of the issued Biscuit;
  - `expires_at(<RFC 3339 date>)` and an expiry check `check if time($t), $t < <exp>`, with
    **`exp = min(source JWT exp, now + BISCUIT_TOKEN_TTL)`**.
- **Token envelope**: the standard `root_key_id` field is always set (see
  [Root key selection and rotation](#root-key-selection-and-rotation)).
- **Audit**: each issuance also writes a `capability_issued` log line (see
  [Issuance audit](#issuance-audit)).
- **`200` response**:

  ```json
  {
    "biscuit": "<base64url biscuit token>",
    "expires_at": 1765465200,
    "revocation_ids": ["<128 hex characters>"]
  }
  ```

  `revocation_ids` lists the token's revocation identifiers in lowercase hex, authority block
  first (a freshly issued token has a single block). Keep the first one if you may need to
  deny-list the token later (see [Known limitations](#known-limitations)).
- **Errors**: `401 {"error":"invalid_token"}` (JWT missing, invalid, expired or without a
  session), `400 {"error":"invalid_request"}` (JWT without a `sub` claim, malformed or non-object
  body, unknown field), `400 {"error":"invalid_agent_pubkey"}` (agent key supplied but malformed),
  `404 {"error":"not_found"}` (extension disabled), `503 {"error":"biscuit_unavailable"}` (root key
  unavailable), `500 {"error":"internal_error"}` (unexpected error; details only in the server
  logs).

### `GET /realms/{realm}/biscuit/public-key`

Exposes the Ed25519 root public key for verifiers. **No authentication** (the public key is not a
secret; services must be able to fetch it freely). This endpoint **never provisions** a key (safe
`GET` semantics): until a root key exists, it returns `503 {"error":"biscuit_unavailable"}`. In
production, provision the root key before going live (see [Key management](#key-management)); in
development, with `BISCUIT_ALLOW_KEY_BOOTSTRAP=true`, the first `POST /biscuit/token` generates it.

```json
{
  "algorithm": "ed25519",
  "kid": "1A2B3C4D5E6F7081",
  "root_key_id": 1234567890,
  "public_key": "ed25519/1a2b3c4d5e6f7081…64 lowercase hex characters…",
  "public_key_hex": "1A2B3C4D5E6F7081…64 hex characters…",
  "public_key_base64": "Gis…44 base64 characters…"
}
```

- `public_key`: the key in the standard Biscuit text form (`ed25519/<lowercase hex>`), accepted
  as is by biscuit-cli, biscuit-python's `PublicKey(...)` and Rust's `PublicKey::from_str`.
- `root_key_id`: the value carried in the envelope of every Biscuit signed with this key.
- `kid`: matches the `key_id("<kid>")` fact of those Biscuits (informational).
- `public_key_hex` and `public_key_base64`: the raw 32-byte key, for other tooling.

### CORS

Both endpoints send CORS headers and answer the `OPTIONS` preflight, so they can be called
directly from a browser (SPA, demo page) or a gateway:
`Access-Control-Allow-Origin` reflects the request's `Origin` (with `Vary: Origin`), or is `*`
when there is none; `Access-Control-Allow-Methods: GET, POST, OPTIONS`;
`Access-Control-Allow-Headers: authorization, content-type`; `Access-Control-Max-Age: 3600`.
There is no `Access-Control-Allow-Credentials`: authentication uses the `Authorization: Bearer`
header, never cookies, so browser calls should use `credentials: 'omit'`.

Keycloak's own OIDC token endpoint (`…/protocol/openid-connect/token`) only sends CORS headers
if the client declares **Web Origins**, which is why the demo realm sets `"webOrigins": ["*"]`
on `demo-cli` (see `src/test/resources/biscuit-demo-realm.json`). In production, restrict this
list to the origins you actually expect.

## Full example (demo realm)

```bash
BASE=http://localhost:8080

# 1. Regular Keycloak login (password grant) → standard JWT
JWT=$(curl -s "$BASE/realms/biscuit-demo/protocol/openid-connect/token" \
  -d 'grant_type=password&client_id=demo-cli&username=alice&password=alice-password' \
  | jq -r .access_token)

# 2. Exchange JWT → Biscuit
curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" | jq
# { "biscuit": "En0KEwoEdXNlci…", "expires_at": 1765465200, "revocation_ids": ["83bf…"] }

# 3. Root public key for verifiers
curl -s "$BASE/realms/biscuit-demo/biscuit/public-key" | jq

# 4. Without a token → 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$BASE/realms/biscuit-demo/biscuit/token"
```

Offline verification by a service, with [biscuit-cli](https://github.com/eclipse-biscuit/biscuit-cli):

```bash
BISCUIT=$(curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" | jq -r .biscuit)
PUBKEY=$(curl -s "$BASE/realms/biscuit-demo/biscuit/public-key" | jq -r .public_key)

echo -n "$BISCUIT" | biscuit inspect - --public-key "$PUBKEY" \
  --authorize-with 'allow if user($u);' --include-time
```

Or in Python with [biscuit-python](https://pypi.org/project/biscuit-python/)
(`pip install biscuit-python`), where `key` is the parsed `/public-key` response:

```python
from datetime import datetime, timezone
from biscuit_auth import AuthorizerBuilder, Biscuit, PublicKey

# Pinned root public keys, indexed by root_key_id
root_keys = {key["root_key_id"]: PublicKey(key["public_key"])}

# The signature is verified while parsing; the callback selects the root key
# from the token's root_key_id (an unknown id raises, so verification fails).
token = Biscuit.from_base64(biscuit_b64, lambda root_key_id: root_keys[root_key_id])
AuthorizerBuilder(
    'time({now}); allow if user($u), realm_role("admin");',
    {"now": datetime.now(tz=timezone.utc)},
).build(token).authorize()
```

A complete, runnable script is available in [examples/python/](examples/python/).

### Anchoring an agent key

`POST /realms/{realm}/biscuit/token` accepts an **optional** JSON body carrying a single key:

```bash
curl -s -X POST "$BASE/realms/biscuit-demo/biscuit/token" \
  -H "Authorization: Bearer $JWT" -H 'Content-Type: application/json' \
  -d '{"agent_pubkey": "ed25519/<64 hex>"}'
```

The issued Biscuit then carries `agent_pubkey("ed25519/…")` **and**
`required_profile("hardened_biscuit_anchored")`: the issuer forces this profile and ignores any
`required_profile` declared in the configuration for that token. Otherwise a caller could anchor
a key and then present the mandate under the `native` profile, skipping proof of possession: the
extension would create a bypass instead of closing one.

Anchoring a key supplied by an already-authenticated requester only **restricts** the mandate to
the holder of the matching private key; the rights themselves come entirely from the presented
JWT (the proof-of-possession model of [RFC 7800](https://www.rfc-editor.org/rfc/rfc7800)). The
issuer only validates the format: `ed25519/` followed by 64 hexadecimal characters, normalized to
lowercase.

This is the **only** path that accepts `agent_pubkey`: if it could be set in configuration, it
would apply to every exchange in the realm, so every configuration path still rejects it (see
[Reserved facts](#reserved-facts)).

Response codes:

| Body | Response |
|---|---|
| absent, empty or `{}` | `200` **without** anchoring |
| `{"agent_pubkey": "ed25519/<64 hex>"}` | `200`, anchored, with the enforced profile |
| malformed key, non-string or `null` | `400 invalid_agent_pubkey` |
| malformed JSON, non-object, duplicate key or unknown field | `400 invalid_request` |

A **supplied** key is therefore never silently ignored: the requester can never receive a `200`
that it would mistake for an anchored mandate when nothing was actually anchored.

## Issuance via a protocol mapper (configured in the admin console)

In addition to the REST endpoint, the extension provides an OIDC **protocol mapper** ("Biscuit
Emitter", id `oidc-biscuit-mapper`) that places the Biscuit **directly in a claim of the access
token** issued by Keycloak. The advantage is that **the whole mandate** is configured **per
client, in the admin console** (audience, profile including anchoring via DPoP, rights per
role, budget, lifetime) instead of a global environment variable that applies to every realm on
the instance.

**To enable it**: Clients → *your client* → Client scopes → *…-dedicated* → Add mapper → By
configuration → **Biscuit Emitter**. Available fields:

| Field | Effect |
|---|---|
| **Claim name** (default `biscuit`) | name of the claim carrying the Biscuit (base64url) |
| **Audience** | if not empty → `audience("...")` fact |
| **Required profile** (`native` / `registry_backed` / `hardened_biscuit_anchored`) | → `required_profile("...")` fact. With `hardened_biscuit_anchored`, the agent key is taken from the token request's **DPoP proof**; see [Anchored profile via DPoP](#anchored-profile-via-dpop) |
| **Role rights (JSON)** | tool rights per role: `[{"role":"analyst","tool":"list_tables","operation":"read"}]` (add `"client"` for a client role) → `right("list_tables", "read")` if the JWT carries the role, and `rights_source("jwt_roles")`. Empty: the global `BISCUIT_ROLE_RIGHTS` table applies |
| **Budget cap** | integer ≥ 0 → `budget_cap(N)` (a Datalog integer) |
| **Lifetime (seconds)** | Biscuit lifetime, capped by `BISCUIT_TOKEN_TTL` and by the access token's expiry |
| **Extra facts** (key → value editor) | custom facts `name("literal value")`, any non-reserved name |
| **Derived facts** (key → value editor) | facts `name → Keycloak attribute`: the value is **read from the user** (or their service account) at issuance |
| **Add to access token** | the claim is added to the access token only (never the ID token) |

The Biscuit issued this way carries **the same core facts** as the REST path (`user`, `client`,
`issuer`, `realm_role`, `client_role`, `key_id`, `jti`, expiry) **plus** the configured facts.
The fields have **different trust levels** (see [Reserved facts](#reserved-facts)):

| Field | Path | Value source | May set governed facts? |
|---|---|---|---|
| **Audience / Required profile / Budget cap / Role rights** | governed (dedicated field) | set by the client administrator | ✅ only its own fact (validated) |
| **Extra facts** | free | per-client free text | ❌ rejected (neither core nor governed) |
| **Derived facts** | governed (attribute) | **Keycloak attribute of the identity** | ✅ allowed, except profile, audience, budget cap and rights |

> This is why `agent_id` **cannot** be typed as a literal in *Extra facts* (it would be forgeable),
> but **can** be **derived** from an attribute in *Derived facts*: the value then comes from the
> identity (governed by whoever can edit the attribute), not from a free-form field. Recommended
> agent model: one client with a **service account** per agent, with `agent_id` stored as an
> attribute of that account.

```jsonc
// access token after enabling the mapper
{
  "sub": "…", "realm_access": { "roles": ["admin"] },
  "biscuit": "En0KEwoEdXNlci…"   // ← signed Biscuit, to be verified offline with /public-key
}
```

> **Free facts are not part of the gateway contract.** A free fact such as `ttl`, `token_budget`
> or `tools` is added as is, but **the gateway ignores it**: use *Lifetime* for the lifetime,
> *Budget cap* for the budget and *Role rights* for tools.

If the mapper cannot issue a valid Biscuit (invalid configuration, missing root key, missing DPoP
proof for the anchored profile), token issuance fails rather than omitting the claim.

### Anchored profile via DPoP

With **Required profile = `hardened_biscuit_anchored`**, the mapper anchors the agent's public key
in the authority block: `agent_pubkey("ed25519/<hex>")` and
`required_profile("hardened_biscuit_anchored")`. This key is the one from the **DPoP proof**
([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) attached to the token request:

1. Keycloak verifies the proof (signature, `htm`/`htu`, freshness, replay protection) and binds
   the access token to the key (`cnf.jkt`);
2. the mapper reads the key back from the `DPoP` header and checks that its RFC 7638 thumbprint
   **matches the one Keycloak verified**; only an **Ed25519** key (`kty=OKP`, `crv=Ed25519`) is
   accepted;
3. without a proof, or with a key of another type, **token issuance fails** (the client gets
   `500 unknown_error` and the audit log records `capability_denied`): an unanchored mandate is
   never presented as anchored.

For a public client, Keycloak requires a new proof from the same key on **refresh**, so the
refreshed mandate stays anchored to that key. The agent uses the same Ed25519 key pair for the
DPoP proof and for the signature it attaches to each gateway call (proof of possession).

Client configuration: enable **Advanced → Require DPoP bound tokens**
(`dpop.bound.access.tokens=true`), so that Keycloak itself rejects a request without a proof.
Example request, against the `biscuit-dpop` realm used by the integration tests
(`src/test/resources/biscuit-dpop-realm.json`, not part of the docker compose demo):

```http
POST /realms/biscuit-dpop/protocol/openid-connect/token
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4Ijoi…

grant_type=password&client_id=agent-cli&username=alice&password=…
```

`BiscuitMapperDPoPIT` covers this flow end to end on a real Keycloak (Ed25519 proof, mapper
rights and budget, TTL, refresh, rejection without a proof and rejection of an EC key).

**REST vs mapper**: both coexist; choose whichever fits your use case.

| | REST `/biscuit/token` | Protocol mapper |
|---|---|---|
| Retrieval | explicit on-demand exchange | claim in the access token, issued at login/refresh |
| Calls | 2 (login + exchange) | 1 (login) |
| Facts and rights configuration | global (`BISCUIT_*`, at startup, all realms) | **per client, in the admin console** |
| Agent key anchoring | request body `{"agent_pubkey": …}` | Ed25519 DPoP proof |
| Lifetime | `BISCUIT_TOKEN_TTL` | *Lifetime*, capped by `BISCUIT_TOKEN_TTL` |
| Revocation ids | in the response body and the audit line | in the audit line only |

> The mapper only **issues** facts; `audience` and `required_profile` must be **enforced by the
> gateway** (anti-downgrade). Embedding a Biscuit adds a few hundred bytes to the JWT; keep that
> in mind if the JWT travels with every request.

## Configuration

Configuration is read **once at startup**. It is **global** (not per realm); any change
requires a restart. Any invalid value **rejects** the whole configuration; no constraint is
silently dropped.

**Use the `BISCUIT_*` environment variables below.** Both issuance paths read them, so the REST
endpoint and the protocol mapper share the same key strategy, KEK, TTL cap and bootstrap setting.

Keycloak SPI options are also accepted, but each one reaches **a single issuance path**, because
Keycloak gives each provider its own configuration scope. A value set there takes precedence over
the `BISCUIT_*` variable for that path only:

- REST endpoint (`realm-restapi-extension` SPI, provider `biscuit`):
  `--spi-realm-restapi-extension--biscuit--<key>` or
  `KC_SPI_REALM_RESTAPI_EXTENSION__BISCUIT__<KEY>` (legacy, deprecated since Keycloak 26.3:
  `--spi-realm-restapi-extension-biscuit-<key>` / `KC_SPI_REALM_RESTAPI_EXTENSION_BISCUIT_<KEY>`);
- protocol mapper (`protocol-mapper` SPI, provider `oidc-biscuit-mapper`):
  `--spi-protocol-mapper--oidc-biscuit-mapper--<key>` or
  `KC_SPI_PROTOCOL_MAPPER__OIDC_BISCUIT_MAPPER__<KEY>` (legacy:
  `--spi-protocol-mapper-oidc-biscuit-mapper-<key>`).

Keys: `token-ttl`, `key-strategy`, `realm-key-kid`, `key-encryption-key`, `extra-facts`,
`role-rights`, `rights-mode`, `allow-key-bootstrap`. Setting, say, the KEK only as an SPI option
of one provider leaves the other path without it; prefer the environment variables. Keycloak
reserves the `enabled` property of an SPI scope for enabling or disabling the provider itself (a
build-time option), so use `BISCUIT_ENABLED` instead.

| Environment variable | Default | Description |
|---|---|---|
| `BISCUIT_ENABLED` | `true` | `false`: the REST endpoints return `404`. The protocol mapper is unaffected: remove it from the client to stop mapper issuance. |
| `BISCUIT_TOKEN_TTL` | `300` | Maximum Biscuit lifetime in seconds. The effective expiry is `min(JWT exp, now + TTL)`. Keep it short (see [Known limitations](#known-limitations)). Must be between `1` and `315360000` (~10 years); other values are rejected. |
| `BISCUIT_KEY_STRATEGY` | `generated` | `generated`: a dedicated root key persisted in the realm. `auto`: alias for `generated` (never falls back to a realm key). `realm`: a pinned, dedicated realm key (see `BISCUIT_REALM_KEY_KID`). |
| `BISCUIT_REALM_KEY_KID` | *(not set)* | Required by the `realm` strategy: kid of an Ed25519 realm key dedicated to Biscuit. If the key cannot be inspected, key resolution fails. |
| `BISCUIT_KEY_ENCRYPTION_KEY` | *(not set)* | AES-256 key (64 hex characters, or base64 of 32 bytes) used to encrypt the generated seed before it is persisted (AES-GCM). Without it, the seed is stored in plaintext (a `WARN` is logged when the key is generated). |
| `BISCUIT_EXTRA_FACTS` | *(not set)* | Additional authority facts, as **JSON**: an array of `{"name": ..., "values": [...]}` objects. Lets you scope the token without touching the code (e.g. `audience`, `required_profile`). See below. |
| `BISCUIT_ROLE_RIGHTS` | *(not set)* | JSON table mapping roles to tool rights. See [Rights per role](#rights-per-role--biscuit_role_rights). |
| `BISCUIT_RIGHTS_MODE` | `roles` | `roles`: rights derived from the JWT roles. `static`: rights fixed by the deployer, marked `rights_source("static_deployer")`. |
| `BISCUIT_ALLOW_KEY_BOOTSTRAP` | `false` | `true` lets the first exchange generate the root key. For single-node development only. |

Docker example:

```yaml
environment:
  BISCUIT_TOKEN_TTL: "120"
  BISCUIT_KEY_STRATEGY: "generated"
  # Generate a KEK with `openssl rand -hex 32`; supply it from a secrets manager
  BISCUIT_KEY_ENCRYPTION_KEY: "${BISCUIT_KEK}"
```

### `BISCUIT_EXTRA_FACTS` — deployment-specific facts

The extension is a **generic Biscuit issuer**. Without configuration, the authority block holds
only the facts listed under [`POST /realms/{realm}/biscuit/token`](#post-realmsrealmbiscuittoken):
the identity and roles taken from the JWT (`user`, `client`, `issuer`, `realm_role`,
`client_role`), the facts the issuer adds itself (`key_id`, `jti`, `expires_at` and the expiry
check), `rights_source("jwt_roles")` and `required_profile("native")`. `BISCUIT_EXTRA_FACTS`
adds deployment-specific facts **without modifying the code**, so business values (MCP or
otherwise) remain configuration. A gateway also expects an `audience`, which only configuration
can provide.

```yaml
environment:
  # Scoping for an MCP gateway: audience + required profile
  BISCUIT_EXTRA_FACTS: >-
    [{"name":"audience","values":["https://gateway.example"]},
     {"name":"required_profile","values":["native"]}]
```

This adds `audience("https://gateway.example")` and `required_profile("native")` (redundant with
the default; shown for illustration).

Validation rules (any invalid fact rejects the entire configuration):

- the **name** must be a valid Datalog predicate: `^[a-z][a-z0-9_]{0,63}$`;
- **reserved** names are rejected depending on the path (see
  [Reserved facts](#reserved-facts)). `BISCUIT_EXTRA_FACTS` is **trusted deployer**
  configuration (a *governed* path): it can set a governed fact such as `audience` or
  `required_profile`, but never a **core** fact (`user`, `key_id`, `jti`…);
- governed facts take exactly one value and may appear only once; `required_profile` must be one
  of `native`, `registry_backed` or `hardened_biscuit_anchored`;
- `values` are string literals, except `budget_cap`, which requires a non-negative JSON integer
  and is issued as a Datalog integer;
- malformed, ambiguous (duplicate keys), mistyped, too deeply nested or oversized JSON rejects
  the configuration.

> **Scope**: **global** configuration (every realm on the instance), read at startup, and applied
> **only by the REST endpoint**. The protocol mapper ignores `BISCUIT_EXTRA_FACTS` and takes its
> facts from its own fields. The extension only **issues** these facts; **enforcing** them (e.g.
> anti-downgrade on `required_profile`) is the job of the downstream gateway's authorizer, not of
> the issuer.
>
> A strict gateway authorizer rejects a mandate without an `audience` fact in the authority
> block: without it, the mandate could be replayed against any deployment exposing the same tool
> name. Declare it with `BISCUIT_EXTRA_FACTS` (REST endpoint) or the mapper's *Audience* field.
> The demo `docker-compose.yml` sets `audience("https://gateway.example")` this way.

### Rights per role — `BISCUIT_ROLE_RIGHTS`

The table explicitly maps authenticated roles to tool rights:

```json
[{"role":"reader","tool":"read_file","operation":"read"},
 {"role":"writer","client":"application","tool":"write_file","operation":"write"}]
```

With `client`, the entry targets a client role (`client_role`); otherwise a realm role. For each
JWT role present in the table, the issuer adds `right("<tool>", "<operation>")`, plus
`rights_source("jwt_roles")`. Roles without a matching entry grant nothing: there are no default
rights. The mapper can define its own per-client table (*Role rights* field).

In `static` mode (`BISCUIT_RIGHTS_MODE=static`), the role table is not used: rights are the
`right` entries declared in `BISCUIT_EXTRA_FACTS` (e.g.
`{"name":"right","values":["read_file","read"]}`), and the token carries
`rights_source("static_deployer")`. In `roles` mode, `right` entries in the configuration are
ignored.

Static mode also applies to the protocol mapper, but the mapper never reads
`BISCUIT_EXTRA_FACTS`: unless the mapper defines its own *Role rights* (which are always
evaluated against the JWT roles, with `rights_source("jwt_roles")`), mapper-issued tokens carry
no `right` facts, only `rights_source("static_deployer")`.

### Reserved facts

To protect the security semantics, three sets of names cannot be configured freely:

- **Core facts**: `user`, `client`, `issuer`, `realm_role`, `client_role`, `jti`, `key_id`,
  `expires_at`, issued by the extension itself, and `agent_pubkey`, `max_delegation_depth`,
  reserved for anchoring (`agent_pubkey`) and future delegation support
  (`max_delegation_depth`). The names a gateway authorizer supplies as
  request context are core as well: `time`, `operation`, `resource`, `arg`, `budget`, `upstream`,
  `delegation_depth`, `call_signature_valid`, `nonce_fresh`, `arguments_bound`,
  `capability_bound`; the issuer therefore cannot pre-populate them. **Core facts are rejected
  on every configuration path.** The only exception, through a separate channel: `agent_pubkey`
  supplied **in the body of an authenticated exchange request** (see
  [Anchoring an agent key](#anchoring-an-agent-key)). A key set in configuration
  would apply to every exchange in the realm, whereas a key supplied by the requester only
  restricts their own mandate.
- **Governed facts**: `audience`, `required_profile`, `agent_id`, `principal_id`,
  `rights_source`, `spiffe_id`, `budget_cap`. They are security-sensitive (anti-downgrade,
  scoping, agent identity) and accepted **only through a dedicated path** (named mapper fields,
  *Derived facts*, or `BISCUIT_EXTRA_FACTS` set by the deployer), **never** through the
  free-form per-client **Extra facts** map. This prevents a free fact from **forging or
  duplicating** a `required_profile` or an `audience`.
- **Deployer-only facts**: `right`. Static rights (`BISCUIT_RIGHTS_MODE=static`) come only from
  `BISCUIT_EXTRA_FACTS` set by the deployer; the free-form *Extra facts* map rejects `right`, so a
  client administrator cannot grant tool rights.

User attributes (*Derived facts*) cannot supply a profile, an audience, a budget cap or rights,
and derived facts are only as trustworthy as whoever administers those attributes.

Any other name (e.g. `tenant_id`) is a free business fact, accepted on every path.

### Issuance audit

Each issued Biscuit (REST or mapper) produces **one structured log line** in the
`fr.vado.keycloak.biscuit.BiscuitAudit` category, at `INFO` level:

```json
{"event":"capability_issued","path":"rest","realm":"biscuit-demo","capability_id":"<jti>","key_id":"<kid>","revocation_id":"<hex>","issuer":"<iss>","audience":"<audience>","required_profile":"native","expires_at":1765465200,"sub":"<sub>"}
```

`path` is `rest` or `mapper`; `revocation_id` is the authority block's revocation identifier
(lowercase hex), on both paths; absent values are omitted. Rejections produce a
`capability_denied` line at `WARN` level, with `path` and `reason`. Values are escaped by the
JSON serializer. To see it in the demo: `docker compose logs keycloak | grep capability_issued`.

> This is a usable issuance trail, **not** a tamper-proof log: no hash chaining, no signature,
> no external anchoring. Forwarding to the Keycloak Event SPI (events visible in the admin
> console) is not implemented yet.

## Key management

The default strategy is `generated`: a dedicated root key persisted in the realm (realm attribute
`biscuit.root.key`); `auto` is an alias for it (never falls back to a realm key). `realm` requires a pinned
`BISCUIT_REALM_KEY_KID` and an active Ed25519 realm key dedicated to Biscuit, whose public and
private components match. An error while inspecting a realm key never causes a replacement key
to be generated.

If the root key is missing, issuance fails; `BISCUIT_ALLOW_KEY_BOOTSTRAP=true` is only meant for
bootstrapping single-node development setups, as in `docker-compose.yml` and the integration
tests. In production, provision the root key before going live: for example, run a single node
once with bootstrap enabled and perform one exchange per realm, then disable bootstrap; or use
the `realm` strategy with a dedicated key.

Without a KEK, the attribute holds the 32-byte Ed25519 seed as 64 hex characters. With a KEK set,
the seed is stored AES-256-GCM-encrypted with the `enc:v2:` prefix; the additional authenticated
data (AAD) binds it to the realm and its purpose. If a KEK is added after a seed was stored in
plaintext, the seed is re-encrypted on the next authenticated issuance and the public key does
not change. Until then, `GET /public-key` returns `503`, because it never modifies the realm. If
the seed is encrypted and the KEK is missing or wrong, issuance fails; the key is never
regenerated.

### Root key selection and rotation

Every Biscuit carries the standard **`root_key_id`** envelope field (`rootKeyId` in the Biscuit
specification), a hint telling verifiers which root public key to use. Its value is the first
4 bytes of SHA-256 over the raw 32-byte Ed25519 public key, read as a big-endian integer and
masked to 31 bits (`& 0x7fffffff`): deterministic, stable across restarts, and different for
each key. `GET /public-key` returns the same value as `root_key_id`.

Verifiers keep a map from `root_key_id` to pinned public keys and select the key with a key
provider callback: a closure in biscuit-rust, a callable in biscuit-python (see the
[Python example](#full-example-demo-realm)). The `key_id(...)` fact cannot serve this purpose:
facts can only be read once the signature has been verified. It remains in the authority block
for audit and bookkeeping.

Rotation is a manual operation:

1. Generate the new root key and add its public key to every verifier's key map, alongside the
   current one.
2. Switch the issuer to the new key. For `generated`, set the `biscuit.root.key` realm attribute
   to the new 32-byte seed as 64 hex characters (e.g. from `openssl rand -hex 32`). Write it in
   plaintext even when a KEK is configured: the next authenticated issuance re-encrypts it to
   `enc:v2:`, and `GET /public-key` returns `503` until then, so perform one exchange per realm
   right after the switch. For `realm`, provision the new realm key and update
   `BISCUIT_REALM_KEY_KID`, which requires a restart.
3. Remove the old key from the verifiers once every token it signed has expired, at most
   `BISCUIT_TOKEN_TTL` after the switch.

Do not delete an active seed to force a new key to be generated. Pin root public keys in the
verifiers' configuration: do not trust a new key just because `/public-key` returns one after a
verification failure.

## Tests

```bash
./mvnw -DskipITs verify   # unit tests only, no Docker
./mvnw verify             # unit + integration (Testcontainers, Docker required)
```

Unit tests:

| Class | Covers |
|---|---|
| `BiscuitMinterTest` | Biscuit construction, serialization/verification round trip, expiry capping, no Datalog injection through claims |
| `BiscuitConfigTest` | configuration resolution and strict validation |
| `BiscuitAnchoringTest` | agent key anchoring, enforced profile, rejection of ambiguous bodies |
| `BiscuitProtocolMapperTest` | mapper fields, free, governed and derived facts |
| `BiscuitResourceTest` | disabled extension (`404`), CORS and preflight, `503` without a provisioned key |
| `BiscuitKeyManagerTest` | seed decoding and persistence, rejection without a KEK, `GET` without generation |
| `KeyEncryptionTest` | AES-GCM round trip, clean failure with a wrong key |
| `SeedExtractorTest` | seed extraction from real JDK Ed25519 keys |
| `DPoPAnchorTest` | RFC 7638 thumbprint against an independent computation |
| `SecurityContractTest` | mandate contract guarantees: governed facts, ambiguous bodies, rights per role, realm-bound encryption, seed migration, pinned realm key, audit injection, bounds |

Integration tests run on a real Keycloak 26.4.7 by default; choose another image with
`./mvnw verify -Dkeycloak.image=quay.io/keycloak/keycloak:<version>`.

- `BiscuitExchangeIT`: password grant → exchange → offline verification with the exposed public
  key, expiry capped by the JWT `exp`, tampering, anchoring, `401`;
- `BiscuitMapperDPoPIT`: mapper with an Ed25519 DPoP proof, rights, budget, TTL, refresh,
  rejection without a proof and rejection of an EC key.

`SecurityContractTest` and the integration tests write interoperability fixtures
(`*-interop.json`, native and anchored tokens) to `target/`, so the same tokens can be verified with
another Biscuit implementation; the suite itself does not run one. The agent keys they contain
are ephemeral and have no value outside the tests.

## Known limitations

- **No revocation list.** The issuer publishes no revocation list. A Biscuit is an
  offline-verifiable bearer token: once issued, it remains valid until it expires, even if the
  Keycloak session is closed or the user is disabled. Services can deny-list a token, and every
  attenuated copy of it, by its authority-block revocation id (the first entry of
  `revocation_ids` in the `/token` response, or `revocation_id` in the audit line), checked
  against the token's revocation identifiers before authorization (`revocation_identifiers()`
  in biscuit-rust, `revocation_ids` in biscuit-python). **Keep `BISCUIT_TOKEN_TTL` short**
  (default 300 s) and request new tokens rather than keeping long-lived ones around.
- **Roles come from the JWT claims**, not from a database lookup: only the roles actually
  present in the access token (depending on client scopes) are copied. Realm roles are issued as
  `realm_role("<r>")` and client roles as `client_role("<clientId>", "<r>")`: provenance is
  preserved, and realm and client roles with the same name remain distinct.
- **biscuit-java 4.0.1** supports Datalog v3.0 to v3.2 (block versions 3 to 5) and issues v3.0
  blocks here. It lacks v3.3 features (`reject if`, null, arrays, maps) and `{param}`
  substitution in its Datalog parser, so the extension builds terms through the programmatic API,
  which also rules out Datalog injection. The tokens it issues verify with biscuit-python 0.4.0,
  which wraps biscuit-rust.
- **Non-distributed key bootstrap**: `BISCUIT_ALLOW_KEY_BOOTSTRAP=true` locks generation per
  node, not cluster-wide. In a cluster, two nodes can generate two different keys. In production,
  leave bootstrap disabled and provision the root key before going live.
- `/public-key` only exposes the **current** key, with no key set or history: during a rotation,
  verifiers must already have the next key pinned (see
  [Root key selection and rotation](#root-key-selection-and-rotation)).

## Security

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin/security/advisories/new)
rather than in a public issue. See [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright 2026 Vado Innovation. See
[NOTICE](NOTICE) for bundled third-party software.
