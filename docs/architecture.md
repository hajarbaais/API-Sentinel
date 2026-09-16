# Architecture

## Vue d'ensemble du pipeline

```
Spec OpenAPI
     │
     ▼
[ discovery/openapi_parser.py ]        Inventaire structure des endpoints (EF1)
     │
     ▼
[ accounts/session_manager.py ]        Authentification simultanee ≥3 comptes (EF2)
     │  └── security/secrets_vault.py  Dechiffrement des mots de passe au chargement (ENF5)
     │  └── guardrails/target_allowlist.py  Verification de la cible AVANT tout login (ENF2)
     ▼
[ fixtures/fixture_manager.py ]        Creation active de ressources + tracage proprietaire (EF3c)
     │  └── fixtures/payload_generator.py  Generation de payloads valides depuis le schema OpenAPI
     ▼
[ detectors/*.py ]                     BOLA, BFLA, mass assignment, excessive exposure,
     │                                 rate limiting, GraphQL (introspection/complexite), SSRF cloud
     │  └── differential/comparator.py     Comparaison differentielle (BOLA)
     │       ├── field_sensitivity.py      Classificateur de champs sensibles (EF3b)
     │       ├── noise_filter.py           Neutralisation des champs dynamiques (EF3b)
     │       └── role_hierarchy.py         Distinction RBAC legitime vs fuite reelle (EF3b)
     ▼
[ evidence/evidence_store.py ]         Capture requete/reponse rejouable, headers sensibles masques (EF4)
     ▼
[ scoring/risk_scorer.py ]             Score de risque agrege par categorie OWASP + global (EF5)
     │  └── scoring/confidence.py          Classification HIGH/MEDIUM/LOW, cas ambigus (ENF1)
     ▼
[ reporting/report_generator.py ]      Assemblage du rapport (HTML/JSON) + score de risque
     └── reporting/sarif_export.py         Export SARIF 2.1.0 (EF5b)
```

Point d'entree unique : `cli.py` (`api-sentinel`), qui orchestre
l'integralite de ce pipeline derriere une seule commande (EF9).

## Decisions de conception

### Fixtures actives plutot que deviner des identifiants

Le detecteur BOLA ne devine jamais un ID. `FixtureManager` cree
reellement une ressource avec chaque compte de test et trace la
correspondance `objet cree -> compte proprietaire`. C'est le seul
moyen de couvrir des identifiants non sequentiels (UUID) sans se
limiter a des cibles jouets a IDs devinables. Contrepartie assumee : un
endpoint dont la creation automatique de fixture echoue (schema trop
complexe, dependances non satisfaites) n'est jamais teste — limite
structurelle documentee et mesuree (`coverage.success_rate` dans
chaque rapport), pas silencieuse.

### Comparaison differentielle plutot que diff naif

`DifferentialComparator` ne compare pas les reponses champ a champ
brut : `NoiseFilter` neutralise d'abord les champs dynamiques non
significatifs (timestamps, IDs auto-generes, nonces — cf.
`config/sensitive_fields.yaml`), puis `FieldSensitivityClassifier`
ne retient que les champs marques sensibles (PII, financier, secret)
pour la decision de fuite. Objectif : distinguer une difference de
champs legitime par conception RBAC (l'admin voit plus de champs) d'une
fuite reelle de donnees appartenant a un autre utilisateur (EF3b) — le
risque principal identifie en section 10 du cahier des charges.

### Confiance par finding, jamais binaire pass/fail

Chaque `Finding` porte un score de confiance (0.0-1.0) calcule par son
propre detecteur (ex. nombre de champs sensibles retrouves pour BOLA,
nombre de signatures de contenu matchees pour SSRF, timeout anormal
comme signal faible). `scoring/risk_scorer.py` agrege ensuite ces
scores par categorie OWASP via un risque complementaire
(`1 - Π(1 - poids_severite × confiance)`) plutot qu'une simple somme :
un seul finding CRITICAL a haute confiance suffit a dominer le score
d'une categorie, sans jamais depasser l'echelle 0-100 quel que soit le
nombre de findings. Les findings a confiance faible (< 60%) sont isoles
comme cas ambigus necessitant une revue manuelle (ENF1), jamais noyes
parmi les findings a haute confiance.

### Garde-fou d'allowlist verifie a plusieurs niveaux

`TargetAllowlist` est verifiee une premiere fois a la construction de
`SessionManager` (avant le moindre login), puis **re-verifiee
explicitement** par chaque detecteur execute un test actif
potentiellement impactant (rate limiting, SSRF cloud, complexite
GraphQL) juste avant d'envoyer sa rafale de requetes. Cette redondance
est deliberee (defense en profondeur, ENF2) : un detecteur ne doit
jamais pouvoir s'executer contre une cible non autorisee meme si un
appelant contourne le flux normal du CLI.

### Secrets chiffres au repos, jamais en dur

`security/secrets_vault.py` chiffre les mots de passe des fichiers de
comptes avec AES-256-GCM. La cle vient exclusivement de la variable
d'environnement `API_SENTINEL_VAULT_KEY` (jamais en dur dans le code,
jamais versionnee) — absence de cle = echec explicite, pas de repli
silencieux sur une cle par defaut. `SessionManager` dechiffre a la
volee uniquement si un mot de passe chiffre est detecte, pour ne
jamais casser une configuration encore en clair (migration
progressive).

## Ce qui n'est pas dans le pipeline principal

- **`benchmark/`** — execution independante contre les cibles de
  reference (OWASP crAPI), avec ground truth documente
  (`benchmark/ground_truth/`) et pronostics vrai/faux positif ecrits
  avant execution, pour la methodologie d'evaluation (section 7 du
  cahier des charges). Ne fait pas partie du scan CLI standard.
- **Infrastructure cloud** (`infra/*.tf`, `docker/`) — prevue mais pas
  encore implementee au moment de la redaction de ce document ; le
  framework tourne actuellement en local.
