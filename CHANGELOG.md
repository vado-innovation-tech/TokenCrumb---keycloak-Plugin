# Changelog

All notable changes to TokenCrumb — Keycloak Plugin are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-10-06

Initial release.

### Added

- **Exchange endpoint** `POST /realms/{realm}/biscuit/token`: exchanges a valid Keycloak access
  token (`Authorization: Bearer`, validated by Keycloak: signature, expiry, active session) for an
  Ed25519-signed Biscuit. The response carries `biscuit` (base64url), `expires_at` (epoch
  seconds) and `revocation_ids` (lowercase hex, authority block first).
- **Authority block** issued from the JWT claims through biscuit-java's programmatic API (no
  Datalog string concatenation of claim values): `user`, `client`, `issuer`, one `realm_role` per
  realm role, one `client_role("<clientId>", "<role>")` per client role, `key_id`, `jti`, a
  signed `expires_at` date and an expiry check `check if time($t), $t < <exp>`, with
  `exp = min(JWT exp, now + BISCUIT_TOKEN_TTL)`. `required_profile("native")` is issued unless
  another profile is configured.
- **Root key selection**: every Biscuit sets the standard `root_key_id` envelope field, derived
  from SHA-256 of the raw Ed25519 public key (first 4 bytes, big-endian, masked to 31 bits), so
  verifiers can pick the root key with a key provider callback. The `key_id(...)` fact is kept
  for audit and bookkeeping.
- **Public key endpoint** `GET /realms/{realm}/biscuit/public-key` (no authentication, never
  provisions a key): `public_key` in the standard `ed25519/<hex>` form, `root_key_id`, `kid`,
  `public_key_hex`, `public_key_base64` and `algorithm`.
- **CORS** headers and `OPTIONS` preflight on both endpoints, with no credentials.
- **Agent key anchoring** on the REST path: an optional body
  `{"agent_pubkey": "ed25519/<64 hex>"}` adds `agent_pubkey(...)` to the authority block and
  forces `required_profile("hardened_biscuit_anchored")`, replacing any configured profile.
  Malformed keys (`400 invalid_agent_pubkey`) and malformed bodies, duplicate keys or unknown
  fields (`400 invalid_request`) are rejected, never silently ignored.
- **OIDC protocol mapper "Biscuit Emitter"** (`oidc-biscuit-mapper`), configured per client in
  the admin console: places the Biscuit in an access token claim (default `biscuit`; never the ID
  token). Fields: *Claim name*, *Audience*, *Required profile* (`native`, `registry_backed`,
  `hardened_biscuit_anchored`), *Role rights (JSON)*, *Budget cap*, *Lifetime (seconds)*,
  *Extra facts* and *Derived facts* (fact values read from user or service account attributes).
  An invalid configuration makes token issuance fail instead of omitting the claim.
- **Anchored profile via DPoP** (RFC 9449) on the mapper: with `hardened_biscuit_anchored`, the agent
  key is the Ed25519 key of the token request's DPoP proof, whose RFC 7638 thumbprint must match
  the one Keycloak verified. Without a proof, or with a non-Ed25519 key, token issuance fails.
  Refreshing a public client keeps the anchored key.
- **Rights per role**: `BISCUIT_ROLE_RIGHTS` (or the mapper's *Role rights*) maps JWT realm or
  client roles to `right("<tool>", "<operation>")` facts, with `rights_source("jwt_roles")`; no
  default rights. `BISCUIT_RIGHTS_MODE=static` uses deployer-declared rights instead, marked
  `rights_source("static_deployer")`.
- **Deployment-specific facts** for the REST endpoint with `BISCUIT_EXTRA_FACTS` (JSON), e.g.
  `audience` and `required_profile`; `budget_cap` is issued as a Datalog integer.
- **Configuration** through the `BISCUIT_*` environment variables, read by both issuance paths so
  they share the key strategy, KEK and TTL cap. Keycloak SPI options override them for a single
  path: `--spi-realm-restapi-extension--biscuit--*` for the REST endpoint,
  `--spi-protocol-mapper--oidc-biscuit-mapper--*` for the mapper (legacy single-dash forms also
  accepted).
- **Root key management**: `generated` strategy (default; `auto` is an alias for it) with a dedicated
  root key persisted in the realm, or `realm` strategy with a pinned, dedicated Ed25519 realm key
  (`BISCUIT_REALM_KEY_KID`). Development-only key bootstrap with `BISCUIT_ALLOW_KEY_BOOTSTRAP`.
- **Issuance audit**: one JSON log line per issued Biscuit (`capability_issued`, category
  `fr.vado.keycloak.biscuit.BiscuitAudit`) on both paths, with `capability_id` (the `jti`),
  `key_id`, `revocation_id`, `issuer`, `audience`, `required_profile`, `expires_at` and `sub`;
  rejections are logged as `capability_denied`.
- `docker compose` demo stack (Keycloak 26.4.7, `biscuit-demo` realm) and a Python client example
  (`examples/python`, biscuit-python 0.4.0).
- Unit tests, Testcontainers integration tests on Keycloak 26.4.7 (`BiscuitExchangeIT`,
  `BiscuitMapperDPoPIT`; image configurable with `-Dkeycloak.image`), interoperability fixtures
  written to `target/*-interop.json`, GitHub Actions CI, CycloneDX SBOM.

### Security

- **Reserved facts**: core facts (issued by the extension, reserved for anchoring and future
  delegation support, or supplied by the gateway's authorizer as request context) are rejected
  on every configuration path; governed
  facts (`audience`, `required_profile`, `agent_id`, `principal_id`, `rights_source`,
  `spiffe_id`, `budget_cap`) are only accepted through dedicated paths, never through the
  free-form per-client *Extra facts* map, which also rejects the deployer-only `right` fact.
  User attributes cannot supply a profile, an audience, a budget cap or rights.
- **Strict configuration**: any invalid value (facts, role rights, TTL, key strategy, booleans)
  rejects the whole configuration. JSON is parsed strictly (64 KiB, depth 16, duplicate keys and
  non-standard values rejected); governed facts are unique; names must match
  `^[a-z][a-z0-9_]{0,63}$`; the number of roles and facts and the size of the issued token are
  bounded.
- **Seed encryption at rest** with `BISCUIT_KEY_ENCRYPTION_KEY` (AES-256-GCM, `enc:v2:` format,
  bound to the realm and its purpose through the AAD). A plaintext seed is re-encrypted on the
  next authenticated issuance once a KEK is set, without changing the public key; a missing or
  wrong KEK fails issuance and never regenerates the key. A `WARN` is logged when a seed is stored in
  plaintext.
- `BISCUIT_TOKEN_TTL` must be between 1 and 315360000 seconds (~10 years), and the expiry
  computation saturates instead of overflowing.
- Error responses never include internal details; they are only written to the server logs.

[Unreleased]: https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vado-innovation-tech/TokenCrumb---keycloak-Plugin/releases/tag/v0.1.0
