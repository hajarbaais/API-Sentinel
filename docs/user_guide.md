# Guide d'utilisation

## Installation

```bash
pip install -e ".[dev]"
```

## Etape 1 — Autoriser la cible (obligatoire)

Le framework refuse d'emettre la moindre requete contre une cible
absente de l'allowlist (ENF2). Ajouter la cible dans
`config/allowlist.yaml` :

```yaml
authorized_targets:
  - base_url: "http://localhost:8888"
    authorized_by: "Ton nom"
    note: "Contexte du test"
    authorized_until: "2026-12-31"   # optionnel
```

`base_url` doit correspondre exactement (schema + hote + port) a la
cible testee — le chemin est ignore dans la comparaison.

## Etape 2 — Configurer les comptes de test

Minimum **3 comptes**, couvrant au moins 2 roles (EF2) : un compte
"victime", un "attaquant" de meme niveau de privilege (BOLA
horizontal), un "attaquant" de niveau inferieur (BOLA/BFLA vertical).

```yaml
base_url: "http://localhost:8888"
login_endpoint: "/identity/api/auth/login"
profile_endpoint: "/identity/api/auth/me"   # optionnel - verifie le role reel cote API

accounts:
  victim:
    email: "victim@test.com"
    password: "..."
    expected_role: "admin"   # optionnel - alerte si le role reel differe
  attacker_same_level:
    email: "attacker1@test.com"
    password: "..."
  attacker_lower_level:
    email: "attacker2@test.com"
    password: "..."
```

### Chiffrer les mots de passe (ENF5)

Les mots de passe ne doivent jamais rester en clair dans un fichier
versionne. Chiffrement :

```bash
python -m api_sentinel.security.secrets_vault generate-key
# -> exporter la sortie dans API_SENTINEL_VAULT_KEY (ex. via un fichier .env local, jamais commite)

python -m api_sentinel.security.secrets_vault encrypt-file \
  config/accounts_clair.yaml config/accounts_chiffre.yaml
```

`SessionManager` dechiffre automatiquement tout mot de passe deja
chiffre (prefixe `vault:v1:`) a condition que `API_SENTINEL_VAULT_KEY`
soit exportee dans l'environnement. Un fichier encore en clair continue
de fonctionner sans cle (migration progressive).

**Sans la cle, le chargement d'un fichier chiffre echoue
explicitement** — pas de cle par defaut, pas de repli silencieux.

## Etape 3 — Lancer un scan

```bash
api-sentinel \
  --spec chemin/vers/openapi.json \
  --accounts config/accounts_crapi.yaml \
  --target-name "OWASP crAPI"
```

Genere `reports/rapport_securite.html`, `.json` et `.sarif`.

## Detecteurs actifs par defaut vs opt-in

| Detecteur | Par defaut | Flag |
|---|---|---|
| BOLA | toujours actif | - |
| BFLA | actif | `--skip-bfla` |
| Mass assignment | actif | `--skip-mass-assignment` |
| Exposition excessive | actif | `--skip-excessive-exposure` |
| Rate limiting | actif | `--skip-rate-limiting` |
| Introspection GraphQL | actif | `--skip-graphql-introspection` |
| Complexite GraphQL | **desactive** | `--enable-graphql-complexity` |
| SSRF cloud | **desactive** | `--enable-ssrf-cloud` |

Complexite GraphQL et SSRF cloud sont desactives par defaut car ce
sont des tests actifs potentiellement impactants (EF8b les nomme
explicitement) — a n'activer que contre une cible ou ce type de test
est explicitement autorise.

## Options principales

| Option | Role |
|---|---|
| `--roles-tested` | Roles pour lesquels des fixtures sont creees (par defaut les 3 roles standards) |
| `--sensitive-fields` | Fichier de classification des champs sensibles (BOLA + scoring) |
| `--roles` | Hierarchie des roles pour BFLA (`config/roles.yaml`) |
| `--protected-endpoints` | Endpoints reserves a un role minimum pour BFLA |
| `--rate-limiting-request-count` | Nombre de requetes envoyees (plafonne, ENF2) |
| `--graphql-endpoint` | Chemin de l'endpoint GraphQL (defaut `/graphql`) |
| `--graphql-complexity-alias-count` | Nombre d'alias de la requete-sonde (plafonne, ENF2) |
| `--ssrf-request-timeout` | Timeout par requete SSRF (35s par defaut - deliberement genereux) |
| `-v` / `--verbose` | Logs de niveau DEBUG |

Liste complete : `api-sentinel --help`.

## Interpreter le rapport

### Score de risque agrege

Chaque rapport HTML/JSON affiche un score global (0-100) et un score
par categorie OWASP API Top 10, avec un niveau qualitatif
(CRITICAL/HIGH/MEDIUM/LOW/MINIMAL). Une categorie absente du rapport
signifie qu'aucun finding n'y a ete confirme, **pas** qu'elle a ete
testee et jugee saine si son detecteur correspondant n'a pas tourne
(cf. flags ci-dessus).

### Findings a revue manuelle

Les findings confirmes avec une confiance < 60% apparaissent dans une
section separee ("Cas ambigus") plutot que noyes parmi les autres :
ni faux positif assume, ni preuve suffisamment solide pour etre traite
sans verification humaine (ENF1). A verifier manuellement avant
d'agir dessus.

### Preuve par finding

Chaque finding porte un `evidence_test_id` pointant vers un
enregistrement dans `evidence/*.jsonl` (requete/reponse reelles,
horodatees). Les headers sensibles (`Authorization`) y sont deja
tronques a l'ecriture.

## Fichiers de configuration (`config/`)

| Fichier | Role |
|---|---|
| `allowlist.yaml` | Cibles explicitement autorisees (ENF2) |
| `accounts_*.yaml` | Comptes de test par cible |
| `sensitive_fields.yaml` | Champs sensibles (PII/financier/secret) + champs dynamiques a neutraliser |
| `roles.yaml` | Hierarchie des roles + mapping role logique -> role metier reel (BFLA) |
| `protected_endpoints.yaml` | Endpoints reserves a un role minimum (BFLA) |
| `excluded_action_endpoints.yaml` | Endpoints exclus de la creation automatique de fixtures (actions destructives) |
| `mass_assignment_keywords.yaml` | Mots-cles utilises pour reperer des champs suspects a injecter |
| `cloud_metadata_targets.yaml` | Endpoints de metadonnees cloud (AWS/GCP/Azure) + signatures de confirmation |
| `ssrf_url_field_keywords.yaml` | Mots-cles pour reperer les champs de type URL dans la spec OpenAPI |

## Executer un detecteur isolement (debug)

Chaque module de `detectors/` est executable directement :

```bash
python -m api_sentinel.detectors.bola <openapi.json> <accounts.yaml>
python -m api_sentinel.detectors.graphql_introspection <accounts.yaml> [graphql_endpoint]
```

Voir le bloc `if __name__ == "__main__"` de chaque module pour l'usage
exact.
