"""
Script d'assemblage : execute les detecteurs disponibles (BOLA, BFLA,
mass assignment), collecte leurs findings et les metriques de
couverture des fixtures, puis genere le rapport final (HTML + JSON),
conformement a EF5.
"""

import logging
import sys

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.bola import BOLADetector
from api_sentinel.detectors.bfla import BFLADetector
from api_sentinel.detectors.mass_assignment import MassAssignmentDetector
from api_sentinel.detectors.field_discovery import FieldDiscovery
from api_sentinel.differential.comparator import DifferentialComparator
from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.differential.noise_filter import NoiseFilter
from api_sentinel.differential.role_hierarchy import RoleHierarchy
from api_sentinel.discovery.openapi_parser import OpenAPIParser
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import FixtureManager
from api_sentinel.fixtures.payload_generator import PayloadGenerator
from api_sentinel.reporting.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python generate_report.py <openapi.json> <accounts.yaml> "
            "[excluded_actions.yaml] [target_name] [roles.yaml] "
            "[protected_endpoints.yaml] [bfla_baseline_role] "
            "[mass_assignment_keywords.yaml]"
        )
        sys.exit(1)

    spec_path = sys.argv[1]
    accounts_path = sys.argv[2]
    excluded_config = sys.argv[3] if len(sys.argv) > 3 else "config/excluded_action_endpoints.yaml"
    target_name = sys.argv[4] if len(sys.argv) > 4 else "Cible testee"
    roles_config = sys.argv[5] if len(sys.argv) > 5 else "config/roles.yaml"
    protected_endpoints_config = sys.argv[6] if len(sys.argv) > 6 else "config/protected_endpoints.yaml"
    bfla_baseline_role = sys.argv[7] if len(sys.argv) > 7 else "victim"
    mass_assignment_keywords_config = sys.argv[8] if len(sys.argv) > 8 else "config/mass_assignment_keywords.yaml"

    # --- Preparation commune : discovery, comptes, fixtures ---

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

    evidence_store = EvidenceStore("evidence/report_evidence.jsonl")

    # --- Detecteur BOLA ---

    sensitivity = FieldSensitivityClassifier("config/sensitive_fields.yaml")
    noise_filter = NoiseFilter("config/sensitive_fields.yaml")
    comparator = DifferentialComparator(sensitivity, noise_filter)

    bola_detector = BOLADetector(session_manager, comparator, evidence_store)
    bola_findings = bola_detector.run(fixtures)

    # --- Detecteur BFLA ---

    bfla_findings = []
    try:
        role_hierarchy = RoleHierarchy(roles_config)
        bfla_detector = BFLADetector(
            session_manager=session_manager,
            role_hierarchy=role_hierarchy,
            evidence_store=evidence_store,
            protected_endpoints_config=protected_endpoints_config,
        )
        bfla_findings = bfla_detector.run(baseline_role=bfla_baseline_role)
    except FileNotFoundError as exc:
        logger.warning(
            "Detecteur BFLA ignore - configuration manquante (%s). "
            "Le rapport ne contiendra pas de findings BFLA.", exc,
        )

    # --- Detecteur mass assignment ---

    mass_assignment_findings = []
    try:
        field_discovery = FieldDiscovery(mass_assignment_keywords_config)
        ma_detector = MassAssignmentDetector(
            fixture_manager=fixture_manager,
            payload_generator=PayloadGenerator(parser.raw_spec),
            session_manager=session_manager,
            evidence_store=evidence_store,
            field_discovery=field_discovery,
        )
        mass_assignment_findings = ma_detector.run(fixtures)
    except FileNotFoundError as exc:
        logger.warning(
            "Detecteur mass assignment ignore - configuration manquante (%s). "
            "Le rapport ne contiendra pas de findings mass assignment.", exc,
        )

    # --- Assemblage du rapport ---

    report = ReportGenerator(
        target_name=target_name,
        target_base_url=session_manager.base_url,
    )
    report.add_findings(bola_findings)
    report.add_findings(bfla_findings)
    report.add_findings(mass_assignment_findings)
    report.set_coverage_from_fixtures(fixtures, fixture_manager.failures)

    report.export_html("reports/rapport_securite.html")
    report.export_json("reports/rapport_securite.json")

    total = len(bola_findings) + len(bfla_findings) + len(mass_assignment_findings)
    print(
        f"\nRapport genere : {total} finding(s) "
        f"({len(bola_findings)} BOLA, {len(bfla_findings)} BFLA, "
        f"{len(mass_assignment_findings)} mass assignment), "
        f"couverture fixtures : {report.coverage.success_rate:.0%}"
    )
    print("  -> reports/rapport_securite.html")
    print("  -> reports/rapport_securite.json")


if __name__ == "__main__":
    main()