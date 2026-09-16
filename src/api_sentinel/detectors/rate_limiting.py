"""
Detecteur d'absence de rate limiting (OWASP API4:2023 - Unrestricted
Resource Consumption).

Principe : envoyer un nombre BORNE de requetes consecutives a un seul
endpoint de lecture (GET, sans parametre de chemin) et verifier
qu'aucune n'est jamais throttlee (code 429). L'absence de 429 sur
l'echantillon suggere qu'aucune protection n'est active a cette
echelle - mais ce n'est jamais une preuve aussi forte qu'un rejeu
differentiel BOLA : un seuil plus eleve ou une fenetre glissante
differente pourrait exister sans que l'echantillon le revele. La
confiance de ce detecteur est donc volontairement plafonnee plus bas
que les autres (ENF1 - fiabilite des findings).

Contrainte ENF2 (non-destructivite) : le nombre de requetes est
STRICTEMENT plafonne (20 par defaut) et un seul endpoint GET est teste
par execution - jamais une rafale sur l'ensemble de l'API. Comme le
detecteur SSRF cloud, il re-verifie explicitement l'allowlist avant
de s'executer.

Extension optionnelle - endpoints POST (`include_post_actions`,
desactivee par defaut) : un vecteur de DoS applicatif frequent n'est
pas une simple lecture repetee mais une ACTION repetee (ex. crAPI,
benchmark crapi-6 : rafale sur "contact mechanic"). Contrairement au
GET, une rafale de POST peut avoir un effet de bord reel (spam
d'email/notification, creation de ressources) - c'est pourquoi cette
extension est opt-in, reutilise la meme liste d'exclusion d'actions
que FixtureManager (config/excluded_action_endpoints.yaml) pour
eviter login/reset de mot de passe/changement d'email, et reste
plafonnee a UN SEUL endpoint POST par execution, comme pour le GET.
"""

import logging
from pathlib import Path
from typing import Optional

import requests
import yaml

from api_sentinel.accounts.session_manager import Account, SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.discovery.openapi_parser import Endpoint
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)

# < scoring.confidence.MANUAL_REVIEW_THRESHOLD (0.6) : ce detecteur doit
# rester classe LOW/"a revue manuelle" (ENF1, cf. docstring du module),
# pas MEDIUM - garde explicite plutot qu'une valeur en dur repetee.
CONFIDENCE = 0.55


def is_missing_rate_limit(status_codes: list[int], expected_count: int) -> bool:
    """
    Decide si l'echantillon de codes HTTP obtenus suggere une absence
    de rate limiting : toutes les requetes prevues ont bien ete
    envoyees (pas d'erreur reseau ayant interrompu le test) et aucune
    n'a recu de code 429.
    """
    if len(status_codes) != expected_count:
        return False
    return 429 not in status_codes


class RateLimitingDetector:

    DETECTOR_NAME = "rate_limiting"

    def __init__(
        self,
        session_manager: SessionManager,
        evidence_store: EvidenceStore,
        request_count: int = 20,
        request_timeout: int = 5,
        raw_openapi_spec: Optional[dict] = None,
        excluded_actions_config: Optional[str] = None,
    ):
        self.session_manager = session_manager
        self.evidence_store = evidence_store
        self.request_count = request_count
        self.request_timeout = request_timeout
        self.raw_spec = raw_openapi_spec
        self.payload_generator = PayloadGenerator(raw_openapi_spec) if raw_openapi_spec else None
        self.excluded_keywords = self._load_excluded_keywords(excluded_actions_config)
        self.findings: list[Finding] = []

    def _load_excluded_keywords(self, config_path: Optional[str]) -> list[str]:
        """Meme fichier de config que FixtureManager (config/excluded_action_endpoints.yaml) -
        reutilise pour ne pas rafaler un endpoint d'action destructive connue
        (login, reset de mot de passe...) quand include_post_actions est active."""
        if not config_path:
            return []
        path = Path(config_path)
        if not path.exists():
            return []
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        return [k.lower() for k in content.get("excluded_path_keywords", [])]

    def run(
        self,
        endpoints: list[Endpoint],
        role: str = "attacker_same_level",
        include_post_actions: bool = False,
    ) -> list[Finding]:
        # ENF2 : re-verification explicite, comme pour le detecteur
        # SSRF cloud - ce detecteur envoie volontairement plusieurs
        # requetes rapprochees, il ne doit jamais tourner sans
        # confirmation que la cible est autorisee.
        self.session_manager.allowlist.enforce(self.session_manager.base_url)

        account = self.session_manager.get_account(role)

        get_candidates = [ep for ep in endpoints if ep.method == "GET" and not ep.has_path_param]
        if get_candidates:
            # Un seul endpoint suffit a demontrer l'absence de
            # limitation : multiplier les rafales sur toute l'API
            # n'apporterait pas de preuve supplementaire et
            # augmenterait le risque de charge (ENF2).
            self._test_get_endpoint(get_candidates[0], account)
        else:
            logger.warning(
                "Aucun endpoint GET sans parametre de chemin trouve - "
                "aucun test GET de rate limiting."
            )

        if include_post_actions:
            self._test_one_post_action(endpoints, account)

        logger.info(
            "Detecteur rate limiting termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _test_one_post_action(self, endpoints: list[Endpoint], account: Account) -> None:
        if self.payload_generator is None:
            logger.warning(
                "include_post_actions active mais aucune spec OpenAPI fournie "
                "au detecteur - test POST de rate limiting ignore."
            )
            return

        post_candidates = [
            ep for ep in endpoints
            if ep.method == "POST" and not ep.has_path_param
            and not self._is_excluded_action(ep.path)
        ]
        if not post_candidates:
            logger.info(
                "Aucun endpoint POST-action eligible (hors exclusions) "
                "trouve - aucun test POST de rate limiting."
            )
            return

        endpoint = post_candidates[0]
        operation = self._get_operation_definition(endpoint)
        payload = self.payload_generator.generate_for_request_body(operation)
        self._test_endpoint(endpoint, account, method="POST", json_body=payload)

    def _is_excluded_action(self, path: str) -> bool:
        normalized = path.lower()
        return any(keyword in normalized for keyword in self.excluded_keywords)

    def _get_operation_definition(self, endpoint: Endpoint) -> dict:
        path_item = (self.raw_spec or {}).get("paths", {}).get(endpoint.path, {})
        return path_item.get(endpoint.method.lower(), {})

    def _test_get_endpoint(self, endpoint: Endpoint, account: Account) -> None:
        self._test_endpoint(endpoint, account, method="GET", json_body=None)

    def _test_endpoint(
        self, endpoint: Endpoint, account: Account, method: str, json_body: Optional[dict]
    ) -> None:
        url = f"{account.base_url}{endpoint.path}"
        status_codes: list[int] = []

        logger.info(
            "Envoi de %d requetes %s consecutives a %s (role: %s) pour "
            "verifier la presence d'un rate limiting...",
            self.request_count, method, endpoint.path, account.role,
        )

        for _ in range(self.request_count):
            try:
                response = requests.request(
                    method, url, json=json_body,
                    headers=account.auth_headers(), timeout=self.request_timeout,
                )
            except requests.RequestException as exc:
                logger.debug(
                    "Erreur reseau lors du test de rate limiting sur %s : %s", url, exc
                )
                break
            status_codes.append(response.status_code)

        confirmed = is_missing_rate_limit(status_codes, self.request_count)

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=method,
            request_url=url,
            request_headers=account.auth_headers(),
            request_body=json_body,
            response_status=status_codes[-1] if status_codes else 0,
            response_body={"status_codes": status_codes},
            finding_confirmed=confirmed,
        )

        if confirmed:
            self._record_finding(endpoint, account, status_codes, evidence.test_id, method)

    def _record_finding(
        self, endpoint: Endpoint, account: Account, status_codes: list[int],
        evidence_test_id: str, method: str,
    ) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.RESOURCE_CONSUMPTION,
            severity=Severity.MEDIUM,
            confidence=CONFIDENCE,
            title=(
                f"Absence de rate limiting detectee sur {method} {endpoint.path} : "
                f"{len(status_codes)} requetes consecutives acceptees sans "
                f"throttling."
            ),
            description=(
                f"{len(status_codes)} requetes ont ete envoyees en succession "
                f"rapide sans qu'aucune ne recoive de code 429 (Too Many "
                f"Requests). Codes recus : {sorted(set(status_codes))}. Cela "
                f"ne prouve pas une absence totale de limitation (un seuil "
                f"plus eleve ou une fenetre glissante differente pourrait "
                f"exister au-dela de cet echantillon volontairement borne), "
                f"mais suggere qu'aucune protection n'est active a cette "
                f"echelle - confiance plafonnee en consequence."
                + (
                    " Un endpoint POST repete a cette echelle peut, "
                    "contrairement a une simple lecture, avoir un impact "
                    "reel (notifications, emails, calcul serveur) - risque "
                    "de deni de service applicatif (layer 7)."
                    if method == "POST" else ""
                )
            ),
            affected_endpoint=f"{method} {endpoint.path}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)


if __name__ == "__main__":
    import sys

    from api_sentinel.discovery.openapi_parser import OpenAPIParser

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print("Usage : python rate_limiting.py <openapi.json> <accounts.yaml> [request_count]")
        sys.exit(1)

    request_count = int(sys.argv[3]) if len(sys.argv) > 3 else 20

    parser = OpenAPIParser(sys.argv[1])
    endpoints = parser.parse()

    session_manager = SessionManager(sys.argv[2])
    session_manager.authenticate_all()

    evidence_store = EvidenceStore("evidence/rate_limiting_evidence.jsonl")

    detector = RateLimitingDetector(
        session_manager=session_manager,
        evidence_store=evidence_store,
        request_count=request_count,
    )
    findings = detector.run(endpoints)

    print(f"\n{len(findings)} probleme(s) de rate limiting confirme(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Rate limiting present (ou test non concluant).")
