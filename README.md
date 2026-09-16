# API Sentinel

Framework de test de sécurité pour API (REST et GraphQL), spécialisé
dans la détection **BOLA/IDOR** par tests différentiels multi-comptes,
étendu à BFLA, mass assignment, exposition excessive de données,
absence de rate limiting, abus d'introspection/complexité GraphQL, et
SSRF vers les métadonnées cloud (AWS/GCP/Azure).



## Principe

Contrairement aux scanners génériques (Burp, ZAP, Nessus), API
Sentinel ne se contente pas d'une heuristique : il **crée activement**
des ressources de test avec plusieurs comptes réels (victime,
attaquant de même niveau, attaquant de niveau inférieur), trace quel
compte possède quel objet, puis rejoue les requêtes avec les mauvais
jetons pour vérifier l'**exploitabilité réelle** — jamais une simple
suggestion. Chaque finding rapporté est accompagné d'une preuve
rejouable (requête/réponse réelles) et d'un score de confiance.

## Installation

```bash
pip install -e ".[dev]"
```

Nécessite Python ≥ 3.11.

## Utilisation rapide

```bash
api-sentinel \
  --spec chemin/vers/openapi.json \
  --accounts config/accounts_crapi.yaml \
  --target-name "Ma cible"
```

Produit trois rapports dans `reports/` : `rapport_securite.html`
(lisible), `.json` (machine), `.sarif` (intégration GitHub Code
Scanning / outillage AppSec standard).

Avant tout scan :
1. Déclarer la cible dans `config/allowlist.yaml` — **obligatoire**,
   le framework refuse d'émettre la moindre requête contre une cible
   non explicitement autorisée (ENF2).
2. Configurer au moins 3 comptes de test dans un fichier `accounts.yaml`
   (voir `docs/user_guide.md`).

Détail de toutes les options CLI, des détecteurs actifs par défaut vs
opt-in, et du format des fichiers de configuration : voir
[`docs/user_guide.md`](docs/user_guide.md).

## Architecture

Vue d'ensemble du pipeline et des choix de conception :
[`docs/architecture.md`](docs/architecture.md).

## Tests

```bash
pytest
```


