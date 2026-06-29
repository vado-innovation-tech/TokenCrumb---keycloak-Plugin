# Tests manuels (Python)

Vérification bout-en-bout de l'extension depuis un client Python, contre une pile Keycloak
locale. Utile pour inspecter le contenu réel d'un Biscuit émis (blocs, facts, revocation_ids).

## Prérequis

- La pile de démo lancée : depuis la racine du dépôt
  ```bash
  ./mvnw -DskipITs package
  docker compose up -d
  ```
- [`uv`](https://github.com/astral-sh/uv) pour l'environnement Python (dépendances figées dans
  `uv.lock` : `requests`, `biscuit-python`).

## Lancer

```bash
uv run full_workflow.py
```

Le script enchaîne : login `password grant` (`alice` / `alice-password`) → échange
`POST /realms/biscuit-demo/biscuit/token` → récupération de `GET /biscuit/public-key` → décodage
et **vérification de signature** du Biscuit, puis affiche ses blocs (`user`, `client`, `issuer`,
`realm_role`, `client_role`, `jti`, `check if time`) et ses `revocation_ids`.
