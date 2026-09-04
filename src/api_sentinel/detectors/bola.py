
import logging

import requests

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.differential.comparator import DifferentialComparator
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import Fixture

logger = logging.getLogger(__name__)


class BOLADetector:
   

    DETECTOR_NAME = "bola"

    def __init__(
        self,
        session_manager: SessionManager,
        comparator: DifferentialComparator,
        evidence_store: EvidenceStore,
        request_timeout: int = 10,
    ):
        self.session_manager = session_manager
        self.comparator = comparator
        self.evidence_store = evidence_store
        self.request_timeout = request_timeout
        self.findings: list[Finding] = []

    def run(
        self,
        fixtures: list[Fixture],
        victim_role: str = "victim",
        attacker_roles: list[str] | None = None,
    ) -> list[Finding]:
        
        if attacker_roles is None:
            attacker_roles = ["attacker_same_level", "attacker_lower_level"]

        victim_fixtures = [fx for fx in fixtures if fx.owner_role == victim_role]

        if not victim_fixtures:
            logger.warning(
                "Aucune fixture appartenant au role '%s' - le detecteur "
                "BOLA n'a rien a tester.", victim_role
            )
            return []

        for fixture in victim_fixtures:
            for attacker_role in attacker_roles:
                self._test_fixture_against_role(fixture, attacker_role)

        logger.info(
            "Detecteur BOLA termine : %d finding(s) confirme(s) sur %d test(s).",
            len(self.findings),
            len(victim_fixtures) * len(attacker_roles),
        )
        return self.findings

    def _test_fixture_against_role(self, fixture: Fixture, attacker_role: str) -> None:
       
        attacker_account = self.session_manager.get_account(attacker_role)
        url = f"{attacker_account.base_url}{fixture.resolved_detail_url()}"
        headers = attacker_account.auth_headers()

        try:
            response = requests.request(
                fixture.detail_method,
                url,
                headers=headers,
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            logger.error(
                "Erreur reseau lors du test BOLA sur %s (role: %s) : %s",
                url, attacker_role, exc,
            )
            return

        try:
            response_body = response.json()
        except ValueError:
            response_body = None

        comparison = self.comparator.compare(
            known_victim_data=fixture.raw_response,
            attacker_response_data=response_body or {},
            attacker_status_code=response.status_code,
        )

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=fixture.detail_method,
            request_url=url,
            request_headers=headers,
            request_body=None,
            response_status=response.status_code,
            response_body=response_body,
            finding_confirmed=comparison.is_leak,
        )

        if comparison.is_leak:
            self._record_finding(fixture, attacker_role, comparison, evidence.test_id)

    def _record_finding(self, fixture, attacker_role: str, comparison, evidence_test_id: str) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.BOLA,
            severity=Severity.CRITICAL,
            confidence=comparison.confidence,
            title=(
                f"BOLA confirme sur {fixture.resource_type} : le role "
                f"'{attacker_role}' accede aux donnees du role "
                f"'{fixture.owner_role}'"
            ),
            description=comparison.reasoning,
            affected_endpoint=fixture.resolved_detail_url(),
            evidence_test_id=evidence_test_id,
            victim_role=fixture.owner_role,
            attacker_role=attacker_role,
        )
        self.findings.append(finding)
        logger.warning(
            "FINDING CONFIRME : %s (confiance : %.0f%%)",
            finding.title, finding.confidence * 100,
        )


if __name__ == "__main__":
    import sys

    from api_sentinel.accounts.session_manager import SessionManager
    from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
    from api_sentinel.differential.noise_filter import NoiseFilter
    from api_sentinel.discovery.openapi_parser import OpenAPIParser
    from api_sentinel.fixtures.fixture_manager import FixtureManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print("Usage : python bola.py <openapi.yaml> <accounts.yaml>")
        sys.exit(1)

    parser = OpenAPIParser(sys.argv[1])
    endpoints = parser.parse()

    session_manager = SessionManager(sys.argv[2])
    session_manager.authenticate_all()

    fixture_manager = FixtureManager(
        endpoints=endpoints,
        raw_openapi_spec=parser.raw_spec,
        session_manager=session_manager,
        excluded_keywords_config="config/excluded_action_endpoints.yaml",
    )
    fixtures = fixture_manager.create_all_fixtures(
        roles=["victim", "attacker_same_level", "attacker_lower_level"]
    )

    sensitivity = FieldSensitivityClassifier("config/sensitive_fields.yaml")
    noise_filter = NoiseFilter("config/sensitive_fields.yaml")
    comparator = DifferentialComparator(sensitivity, noise_filter)
    evidence_store = EvidenceStore("evidence/bola_evidence.jsonl")

    detector = BOLADetector(session_manager, comparator, evidence_store)
    findings = detector.run(fixtures)

    print(f"\n{len(findings)} faille(s) BOLA confirmee(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Aucune faille BOLA detectee sur les fixtures testees.")