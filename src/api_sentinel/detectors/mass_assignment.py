"""
Detecteur de mass assignment (OWASP API3:2023 - Broken Object
Property Level Authorization).

Approche "real world" : plutot que d'injecter une liste statique de
noms de champs devines a l'avance (role, isAdmin...), qui ne
correspondent pas forcement au vocabulaire propre a chaque API, ce
detecteur decouvre dynamiquement les champs suspects a partir des
VRAIES reponses deja observees pour cette cible precise (via
FieldDiscovery), puis tente de les injecter avec une valeur adaptee
a leur type d'origine. Corrige une limite identifiee concretement
sur crAPI : le champ vulnerable reel (available_credit) n'apparaissait
dans aucune liste statique generique, mais est visible directement
dans les reponses de l'API des la phase de creation de fixtures.
"""

import logging
from typing import Optional

import requests

from api_sentinel.accounts.session_manager import Account, SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.detectors.field_discovery import FieldDiscovery, InjectionCandidate
from api_sentinel.discovery.openapi_parser import Endpoint
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import FixtureManager, ID_FIELD_CANDIDATES
from api_sentinel.fixtures.payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)


class MassAssignmentDetector:
    """
    Orchestre le test de mass assignment sur les endpoints de
    creation, en utilisant des candidats d'injection decouverts
    dynamiquement a partir des vraies reponses de l'API cible.
    """

    DETECTOR_NAME = "mass_assignment"

    def __init__(
        self,
        fixture_manager: FixtureManager,
        payload_generator: PayloadGenerator,
        session_manager: SessionManager,
        evidence_store: EvidenceStore,
        field_discovery: FieldDiscovery,
        request_timeout: int = 10,
    ):
        self.fixture_manager = fixture_manager
        self.payload_generator = payload_generator
        self.session_manager = session_manager
        self.evidence_store = evidence_store
        self.field_discovery = field_discovery
        self.request_timeout = request_timeout
        self.findings: list[Finding] = []

    def run(self, fixtures: list) -> list[Finding]:
        """
        Point d'entree principal : decouvre les candidats d'injection
        a partir des fixtures deja creees, puis teste chaque endpoint
        de creation avec ces candidats specifiquement pertinents pour
        cette API.
        """
        candidates = self.field_discovery.discover_from_fixtures(fixtures)

        if not candidates:
            logger.warning(
                "Aucun champ suspect decouvert dans les reponses reelles "
                "de l'API - le detecteur mass assignment n'a rien de "
                "specifique a tester."
            )
            return []

        creation_endpoints = self.fixture_manager.get_creation_endpoints()

        for endpoint in creation_endpoints:
            for role in {fx.owner_role for fx in fixtures}:
                account = self.session_manager.get_account(role)
                self._test_endpoint(endpoint, account, candidates)

        logger.info(
            "Detecteur mass assignment termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _test_endpoint(
        self, endpoint: Endpoint, account: Account, candidates: list[InjectionCandidate]
    ) -> None:
        operation = self.fixture_manager._get_operation_definition(endpoint)
        base_payload = self.payload_generator.generate_for_request_body(operation)

        if base_payload is None:
            return

        baseline_data = self._create_baseline(endpoint, account, base_payload)

        logger.info(
            "Test mass assignment sur %s (role: %s) - %d champ(s) suspect(s) decouvert(s) a tester...",
            endpoint.path, account.role, len(candidates),
        )

        for candidate in candidates:
            self._test_injection(endpoint, account, base_payload, candidate, baseline_data)

    def _create_baseline(
        self, endpoint: Endpoint, account: Account, base_payload: dict
    ) -> dict:
        """
        Cree UNE ressource de controle sans aucun champ injecte, pour
        connaitre la valeur NATURELLE de chaque champ observable a la
        creation. Sans ce controle negatif, un champ dont la valeur
        par defaut cote serveur coincide deja avec la valeur injectee
        (ex. un booleen qui vaut naturellement False, "injecte" a
        False par PayloadGenerator) serait signale a tort comme mass
        assignment confirme, alors que le serveur n'a rien accepte de
        notre injection - il a simplement renvoye sa valeur par
        defaut habituelle.
        """
        url = f"{account.base_url}{endpoint.path}"
        try:
            response = requests.post(
                url, json=base_payload, headers=account.auth_headers(),
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            logger.debug("Baseline mass assignment impossible sur %s : %s", url, exc)
            return {}

        if response.status_code not in (200, 201):
            return {}

        try:
            data = response.json()
        except ValueError:
            return {}

        object_id = self._extract_object_id(data)
        if object_id is not None:
            fetched = self._fetch_full_object(endpoint, object_id, account)
            if fetched is not None:
                return fetched
        return data

    def _test_injection(
        self, endpoint: Endpoint, account: Account, base_payload: dict,
        candidate: InjectionCandidate, baseline_data: dict,
    ) -> None:
        payload = dict(base_payload)
        payload[candidate.field_name] = candidate.injected_value

        url = f"{account.base_url}{endpoint.path}"

        try:
            response = requests.post(
                url, json=payload, headers=account.auth_headers(),
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            logger.debug("Erreur reseau lors du test mass assignment sur %s : %s", url, exc)
            return

        if response.status_code not in (200, 201):
            return

        try:
            response_data = response.json()
        except ValueError:
            return

        object_id = self._extract_object_id(response_data)

        full_data = response_data
        if candidate.field_name not in self._flatten(full_data) and object_id is not None:
            full_data = self._fetch_full_object(endpoint, object_id, account) or response_data

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method="POST",
            request_url=url,
            request_headers=account.auth_headers(),
            request_body=payload,
            response_status=response.status_code,
            response_body=full_data,
            finding_confirmed=False,
        )

        if self._field_was_accepted(
            full_data, baseline_data, candidate.field_name, candidate.injected_value
        ):
            self._record_finding(endpoint, account, candidate, evidence.test_id)

    def _field_was_accepted(
        self, data: dict, baseline_data: dict, field_name: str, injected_value
    ) -> bool:
        flat = self._flatten(data)
        baseline_flat = self._flatten(baseline_data)
        for key, value in flat.items():
            if key.split(".")[-1] != field_name or value != injected_value:
                continue
            if baseline_flat.get(key) == injected_value:
                # Meme valeur obtenue SANS injection (controle negatif) :
                # ce n'est pas une preuve d'acceptation, juste la valeur
                # par defaut habituelle du serveur a la creation.
                continue
            return True
        return False

    def _flatten(self, data, parent_key: str = "") -> dict:
        flat = {}
        if not isinstance(data, dict):
            return flat
        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(value, dict):
                flat.update(self._flatten(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        flat.update(self._flatten(item, f"{full_key}[{i}]"))
                    else:
                        flat[f"{full_key}[{i}]"] = item
            else:
                flat[full_key] = value
        return flat

    def _extract_object_id(self, response_data: dict) -> Optional[str]:
        if not isinstance(response_data, dict):
            return None
        for field_name in ID_FIELD_CANDIDATES:
            if field_name in response_data:
                return response_data[field_name]
        return None

    def _fetch_full_object(
        self, creation_endpoint: Endpoint, object_id: str, account: Account
    ) -> Optional[dict]:
        detail_endpoint = self.fixture_manager._match_detail_endpoint(creation_endpoint)
        if not detail_endpoint:
            return None
        return self.fixture_manager._fetch_full_object(detail_endpoint, object_id, account)

    def _record_finding(
        self, endpoint: Endpoint, account: Account, candidate: InjectionCandidate,
        evidence_test_id: str,
    ) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.BOPLA,
            severity=Severity.HIGH,
            confidence=0.9,
            title=(
                f"Mass assignment confirme sur POST {endpoint.path} : "
                f"le champ '{candidate.field_name}' (observe initialement "
                f"a '{candidate.original_value}' sur {candidate.source_endpoint}) "
                f"a ete accepte avec la valeur '{candidate.injected_value}'."
            ),
            description=(
                f"Le champ '{candidate.field_name}', decouvert dynamiquement "
                f"dans une reponse reelle de l'API, a ete injecte dans une "
                f"requete de creation par le role '{account.role}' et accepte "
                f"tel quel par le serveur - ce champ ne devrait probablement "
                f"pas etre modifiable directement par le client."
            ),
            affected_endpoint=f"POST {endpoint.path}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)


if __name__ == "__main__":
    import sys
    import logging as _logging

    from api_sentinel.discovery.openapi_parser import OpenAPIParser

    _logging.basicConfig(level=_logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python mass_assignment.py <openapi.json> <accounts.yaml> "
            "[excluded_actions.yaml] [suspect_keywords.yaml]"
        )
        sys.exit(1)

    excluded_config = sys.argv[3] if len(sys.argv) > 3 else "config/excluded_action_endpoints.yaml"
    keywords_config = sys.argv[4] if len(sys.argv) > 4 else "config/mass_assignment_keywords.yaml"

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
    fixtures = fixture_manager.create_all_fixtures(
        roles=["victim", "attacker_same_level", "attacker_lower_level"]
    )

    payload_generator = PayloadGenerator(parser.raw_spec)
    evidence_store = EvidenceStore("evidence/mass_assignment_evidence.jsonl")
    field_discovery = FieldDiscovery(keywords_config)

    detector = MassAssignmentDetector(
        fixture_manager=fixture_manager,
        payload_generator=payload_generator,
        session_manager=session_manager,
        evidence_store=evidence_store,
        field_discovery=field_discovery,
        request_timeout=5,
    )
    findings = detector.run(fixtures)

    print(f"\n{len(findings)} faille(s) mass assignment confirmee(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Aucune faille mass assignment detectee.")