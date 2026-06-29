# from biscuit_auth import Biscuit, PublicKey, AuthorizerBuilder
# from datetime import datetime, timezone

# token = Biscuit.from_base64(biscuit_b64, PublicKey.from_hex(pubkey_hex))
# AuthorizerBuilder(
#     "time({now}); allow if user($u), role(\"admin\");",
#     {"now": datetime.now(tz=timezone.utc)},
# ).build(token).authorize()



import requests
from biscuit_auth import Biscuit, PublicKey

base_url = "http://localhost:8080"

response = requests.post(f"{base_url}/realms/biscuit-demo/protocol/openid-connect/token", data = {
    "grant_type":"password","client_id":"demo-cli","username":"alice","password":"alice-password"
})

access_token = response.json()["access_token"]

print("access_token")
print(access_token)



response = requests.post(f"{base_url}/realms/biscuit-demo/biscuit/token", headers={
    "Authorization": f"Bearer {access_token}"
})

biscuit = response.json()["biscuit"]

print("\nbiscuit")
print(biscuit)

response = requests.get(f"{base_url}/realms/biscuit-demo/biscuit/public-key")

public_key_base64 = response.json()["public_key_base64"]
public_key_hex = response.json()["public_key_hex"]
kid = response.json().get("kid")

print("\npublic_key_base64")
print(public_key_base64)

print("\npublic_key_hex")
print(public_key_hex)

# kid : identifiant de la clé/époque, à corréler au fait key_id(...) du biscuit
print("\nkid")
print(kid)


# Décodage du biscuit avec vérification de signature, puis affichage de son contenu.
# Le biscuit minté par l'extension contient un seul bloc authority (bloc 0) avec :
#   user("<sub>")                      -> claim `sub` du JWT (obligatoire)
#   client("<azp>")                    -> claim `azp` du JWT (optionnel)
#   realm_role("<r>") / client_role("<client>","<r>")  -> realm_access + resource_access, dédupliqués
#   <faits gouvernés/libres>           -> audience, required_profile, tenant_id… (selon config)
#   key_id("<kid>")                    -> identifiant de la clé racine (== kid ci-dessus)
#   jti("<uuid>")                      -> identifiant unique du biscuit émis
#   check if time($t), $t < <exp>      -> exp = min(jwt.exp, now + TTL)
token = Biscuit.from_base64(biscuit, PublicKey("ed25519/" + public_key_hex.lower()))

print("\nbiscuit content")
print(f"nombre de blocs : {token.block_count()}")
for i in range(token.block_count()):
    print(f"\n--- bloc {i} ---")
    print(token.block_source(i))

print("\nrevocation_ids")
print(token.revocation_ids)


