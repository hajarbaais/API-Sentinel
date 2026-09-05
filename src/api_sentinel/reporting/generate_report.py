

import logging
import sys

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.bola import BOLADetector
from api_sentinel.differential.comparator import DifferentialComparator
from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.differential.noise_filter import NoiseFilter
from api_sentinel.discovery.openapi_parser import OpenAPIParser
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import FixtureManager
from api_sentinel.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python generate_report.py <openapi.json> <accounts.yaml> "
            "[excluded_actions.yaml] [target_name]"
        )
        sys.exit(1)

    spec_path = sys.argv[1]
    accounts_path = sys.argv[2]
    excluded_config = sys.argv[3] if len(sys.argv) > 3 else "config/excluded_action_endpoints.yaml"
    target_name = sys.argv[4] if len(sys.argv) > 4 else "Cible testee"

    parser = OpenAPIParser(spec_path)
    endpoints = parser.parse()

    session_manager = SessionManager(accounts_path)
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

    sensitivity = FieldSensitivityClassifier("config/sensitive_fields.yaml")
    noise_filter = NoiseFilter("config/sensitive_fields.yaml")
    comparator = DifferentialComparator(sensitivity, noise_filter)
    evidence_store = EvidenceStore("evidence/report_evidence.jsonl")

    bola_detector = BOLADetector(session_manager, comparator, evidence_store)
    bola_findings = bola_detector.run(fixtures)

    report = ReportGenerator(
        target_name=target_name,
        target_base_url=session_manager.base_url,
    )
    report.add_findings(bola_findings)
    report.set_coverage_from_fixtures(fixtures, fixture_manager.failures)

    report.export_html("reports/rapport_securite.html")
    report.export_json("reports/rapport_securite.json")

    print(f"\nRapport genere : {len(bola_findings)} finding(s), "
          f"couverture fixtures : {report.coverage.success_rate:.0%}")
    print("  -> reports/rapport_securite.html")
    print("  -> reports/rapport_securite.json")


if __name__ == "__main__":
    main()