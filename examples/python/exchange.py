"""JWT → Biscuit exchange against the demo stack, followed by offline verification.

Steps: password-grant login → POST /biscuit/token → GET /biscuit/public-key →
signature verification → print the blocks → Datalog authorization, as a service would do it.
"""

import os
from datetime import datetime, timezone

import requests
from biscuit_auth import AuthorizerBuilder, Biscuit, PublicKey

BASE_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
REALM = os.environ.get("KEYCLOAK_REALM", "biscuit-demo")
REALM_URL = f"{BASE_URL}/realms/{REALM}"


def login(username: str, password: str) -> str:
    """Log in with the password grant on the public demo client and return the access token."""
    response = requests.post(
        f"{REALM_URL}/protocol/openid-connect/token",
        data={"grant_type": "password", "client_id": "demo-cli",
              "username": username, "password": password},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def exchange(access_token: str) -> dict:
    """Exchange the access token for a Biscuit."""
    response = requests.post(
        f"{REALM_URL}/biscuit/token",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def public_key() -> dict:
    """Fetch the root public key (verifiers should pin it)."""
    response = requests.get(f"{REALM_URL}/biscuit/public-key", timeout=10)
    response.raise_for_status()
    return response.json()


def main() -> None:
    issued = exchange(login("alice", "alice-password"))
    key = public_key()
    print(f"kid:            {key['kid']}")
    print(f"root_key_id:    {key['root_key_id']}")
    print(f"expires_at:     {datetime.fromtimestamp(issued['expires_at'], tz=timezone.utc).isoformat()}")
    print(f"revocation_ids: {issued['revocation_ids']}")

    # Pinned root public keys, indexed by root_key_id. The signature is verified while parsing:
    # a tampered token, or one signed by an unknown root key, raises an exception here.
    root_keys = {key["root_key_id"]: PublicKey(key["public_key"])}
    token = Biscuit.from_base64(issued["biscuit"], lambda root_key_id: root_keys[root_key_id])

    for i in range(token.block_count()):
        print(f"\n--- block {i} ---")
        print(token.block_source(i))

    # Service-side authorization: the token's expiry check requires a time() fact.
    AuthorizerBuilder(
        'time({now}); allow if user($u), realm_role("admin");',
        {"now": datetime.now(tz=timezone.utc)},
    ).build(token).authorize()
    print('\nauthorization: OK (user + realm_role("admin"))')


if __name__ == "__main__":
    main()
