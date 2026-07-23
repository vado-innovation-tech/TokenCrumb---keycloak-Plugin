# Python client example

Exchanges a Keycloak JWT for a Biscuit against the local demo stack, then verifies the token
offline using only the root public key. Useful for seeing what an issued Biscuit actually
contains.

## Prerequisites

- The demo stack running (start it from the repository root):
  ```bash
  ./mvnw -DskipITs package
  docker compose up -d
  ```
- [`uv`](https://github.com/astral-sh/uv) (dependencies pinned in `uv.lock`: `requests`,
  `biscuit-python`).

## Run

```bash
cd examples/python
uv run exchange.py
```

The script performs, in order: a password-grant login (`alice` / `alice-password`) →
`POST /realms/biscuit-demo/biscuit/token` → `GET /realms/biscuit-demo/biscuit/public-key` →
signature verification, with the root key selected by the token's `root_key_id` → printing each
block → Datalog authorization (`allow if user($u), realm_role("admin")`).

Set `KEYCLOAK_URL` and `KEYCLOAK_REALM` to target another instance (the script still logs in as
`alice` on client `demo-cli`).
