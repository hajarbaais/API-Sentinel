"""Point d'entree CLI d'API Sentinel.

Orchestre le pipeline complet (discovery -> comptes -> fixtures ->
detecteurs -> rapport) derriere une seule commande, pour satisfaire
EF9 (execution CLI, integrable en CI/CD).
"""

import argparse
import logging
import sys
from pathlib import Path

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.bfla import BFLADetector
from api_sentinel.detectors.bola import BOLADetector
from api_sentinel.detectors.excessive_exposure import ExcessiveExposureDetector
from api_sentinel.detectors.field_discovery import FieldDiscovery
from api_sentinel.detectors.graphql_complexity import GraphQLComplexityDetector
from api_sentinel.detectors.graphql_introspection import GraphQLIntrospectionDetector
from api_sentinel.detectors.mass_assignment import MassAssignmentDetector
from api_sentinel.detectors.rate_limiting import RateLimitingDetector
from api_sentinel.detectors.ssrf_cloud import SSRFCloudDetector, URLFieldDiscovery, load_cloud_targets
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="api-sentinel",
        description=(
            "Framework de test de securite pour API : detection BOLA/BFLA/"
            "mass assignment par tests differentiels multi-comptes."
        ),
    )
    parser.add_argument("--spec", required=True, help="Specification OpenAPI (.json/.yaml).")
    parser.add_argument("--accounts", required=True, help="Fichier de comptes de test.")
    parser.add_argument("--target-name", default="Cible testee", help="Nom affiche dans le rapport.")
    parser.add_argument(
        "--roles-tested",
        nargs="+",
        default=["victim", "attacker_same_level", "attacker_lower_level"],
        help="Roles pour lesquels des fixtures sont creees.",
    )
    parser.add_argument("--excluded-actions", default="config/excluded_action_endpoints.yaml")
    parser.add_argument("--sensitive-fields", default="config/sensitive_fields.yaml")
    parser.add_argument("--roles", default="config/roles.yaml", help="Hierarchie des roles (BFLA).")
    parser.add_argument("--protected-endpoints", default="config/protected_endpoints.yaml")
    parser.add_argument("--bfla-baseline-role", default="victim")
    parser.add_argument("--mass-assignment-keywords", default="config/mass_assignment_keywords.yaml")
    parser.add_argument("--skip-bfla", action="store_true", help="Desactive le detecteur BFLA.")
    parser.add_argument(
        "--skip-mass-assignment", action="store_true", help="Desactive le detecteur mass assignment."
    )
    parser.add_argument(
        "--skip-excessive-exposure",
        action="store_true",
        help="Desactive le detecteur d'exposition excessive de donnees.",
    )
    parser.add_argument(
        "--skip-rate-limiting", action="store_true", help="Desactive le detecteur de rate limiting."
    )
    parser.add_argument(
        "--rate-limiting-request-count",
        type=int,
        default=20,
        help="Nombre de requetes consecutives envoyees pour le test de rate limiting (ENF2 : plafonne).",
    )
    parser.add_argument(
        "--enable-rate-limiting-post-actions",
        action="store_true",
        help=(
            "Etend le test de rate limiting a UN endpoint POST-action "
            "(hors exclusions), en plus du GET habituel (desactive par "
            "defaut : une rafale de POST peut avoir un effet de bord reel, "
            "contrairement a une lecture - ENF2)."
        ),
    )
    parser.add_argument(
        "--enable-ssrf-cloud",
        action="store_true",
        help=(
            "Active le detecteur SSRF cloud (desactive par defaut : c'est le "
            "detecteur le plus sensible, a n'activer que contre une cible "
            "explicitement autorisee pour ce type de test - ENF2)."
        ),
    )
    parser.add_argument("--cloud-metadata-targets", default="config/cloud_metadata_targets.yaml")
    parser.add_argument("--ssrf-url-field-keywords", default="config/ssrf_url_field_keywords.yaml")
    parser.add_argument(
        "--graphql-endpoint",
        default="/graphql",
        help="Chemin de l'endpoint GraphQL (utilise par les detecteurs introspection/complexite).",
    )
    parser.add_argument(
        "--skip-graphql-introspection",
        action="store_true",
        help="Desactive le detecteur d'introspection GraphQL non authentifiee.",
    )
    parser.add_argument(
        "--enable-graphql-complexity",
        action="store_true",
        help=(
            "Active le detecteur de complexite GraphQL (desactive par defaut : "
            "test actif nomme explicitement par EF8b aux cotes du SSRF et de la "
            "charge, a n'activer que contre une cible explicitement autorisee)."
        ),
    )
    parser.add_argument(
        "--graphql-complexity-alias-count",
        type=int,
        default=500,
        help="Nombre d'alias envoyes par la requete-sonde de complexite GraphQL (ENF2 : plafonne).",
    )
    parser.add_argument(
        "--ssrf-request-timeout",
        type=int,
        default=35,
        help=(
            "Timeout (s) par requete SSRF. Genereux par defaut : une cible qui "
            "tente reellement d'atteindre 169.254.169.254 sans metadonnees "
            "cloud reelles peut mettre plusieurs secondes a echouer proprement "
            "cote serveur - un timeout trop court fait manquer la preuve."
        ),
    )
    parser.add_argument("--evidence-path", default="evidence/report_evidence.jsonl")
    parser.add_argument("--report-html", default="reports/rapport_securite.html")
    parser.add_argument("--report-json", default="reports/rapport_securite.json")
    parser.add_argument("--report-sarif", default="reports/rapport_securite.sarif")
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def run_scan(args: argparse.Namespace) -> ReportGenerator:
    """Execute le pipeline complet et retourne le rapport assemble."""
    # BOLA n'est pas desactivable (--skip-bola n'existe pas, contrairement
    # aux autres detecteurs) : contrairement a eux, un fichier de
    # sensibilite des champs manquant doit donc etre signale clairement
    # avant tout travail (parsing, authentification), plutot que de
    # planter en cours de scan avec une trace peu lisible.
    if not Path(args.sensitive_fields).exists():
        raise FileNotFoundError(
            f"Fichier de champs sensibles introuvable : '{args.sensitive_fields}' "
            "(--sensitive-fields). Requis pour le detecteur BOLA, qui ne peut "
            "pas etre desactive."
        )

    openapi_parser = OpenAPIParser(args.spec)
    endpoints = openapi_parser.parse()

    session_manager = SessionManager(args.accounts)
    session_manager.authenticate_all()

    fixture_manager = FixtureManager(
        endpoints=endpoints,
        raw_openapi_spec=openapi_parser.raw_spec,
        session_manager=session_manager,
        excluded_keywords_config=args.excluded_actions,
    )
    fixtures = fixture_manager.create_all_fixtures(roles=args.roles_tested)

    evidence_store = EvidenceStore(args.evidence_path)

    sensitivity = FieldSensitivityClassifier(args.sensitive_fields)
    noise_filter = NoiseFilter(args.sensitive_fields)
    comparator = DifferentialComparator(sensitivity, noise_filter)

    bola_detector = BOLADetector(session_manager, comparator, evidence_store)
    bola_findings = bola_detector.run(fixtures)

    bfla_findings = []
    if not args.skip_bfla:
        try:
            role_hierarchy = RoleHierarchy(args.roles)
            bfla_detector = BFLADetector(
                session_manager=session_manager,
                role_hierarchy=role_hierarchy,
                evidence_store=evidence_store,
                protected_endpoints_config=args.protected_endpoints,
            )
            bfla_findings = bfla_detector.run(baseline_role=args.bfla_baseline_role)
        except FileNotFoundError as exc:
            logger.warning(
                "Detecteur BFLA ignore - configuration manquante (%s).", exc
            )

    mass_assignment_findings = []
    if not args.skip_mass_assignment:
        try:
            field_discovery = FieldDiscovery(args.mass_assignment_keywords)
            ma_detector = MassAssignmentDetector(
                fixture_manager=fixture_manager,
                payload_generator=PayloadGenerator(openapi_parser.raw_spec),
                session_manager=session_manager,
                evidence_store=evidence_store,
                field_discovery=field_discovery,
            )
            mass_assignment_findings = ma_detector.run(fixtures)
        except FileNotFoundError as exc:
            logger.warning(
                "Detecteur mass assignment ignore - configuration manquante (%s).", exc
            )

    excessive_exposure_findings = []
    if not args.skip_excessive_exposure:
        sensitivity_for_exposure = FieldSensitivityClassifier(args.sensitive_fields)
        exposure_detector = ExcessiveExposureDetector(
            raw_openapi_spec=openapi_parser.raw_spec,
            sensitivity_classifier=sensitivity_for_exposure,
            evidence_store=evidence_store,
        )
        excessive_exposure_findings = exposure_detector.run(fixtures)

    rate_limiting_findings = []
    if not args.skip_rate_limiting:
        rate_limiting_detector = RateLimitingDetector(
            session_manager=session_manager,
            evidence_store=evidence_store,
            request_count=args.rate_limiting_request_count,
            raw_openapi_spec=openapi_parser.raw_spec,
            excluded_actions_config=args.excluded_actions,
        )
        rate_limiting_findings = rate_limiting_detector.run(
            endpoints, include_post_actions=args.enable_rate_limiting_post_actions
        )

    graphql_introspection_findings = []
    if not args.skip_graphql_introspection:
        introspection_detector = GraphQLIntrospectionDetector(
            session_manager=session_manager,
            evidence_store=evidence_store,
            graphql_endpoint=args.graphql_endpoint,
        )
        graphql_introspection_findings = introspection_detector.run()

    graphql_complexity_findings = []
    if args.enable_graphql_complexity:
        complexity_detector = GraphQLComplexityDetector(
            session_manager=session_manager,
            evidence_store=evidence_store,
            graphql_endpoint=args.graphql_endpoint,
            alias_count=args.graphql_complexity_alias_count,
        )
        graphql_complexity_findings = complexity_detector.run()

    ssrf_findings = []
    if args.enable_ssrf_cloud:
        try:
            url_field_discovery = URLFieldDiscovery(openapi_parser.raw_spec, args.ssrf_url_field_keywords)
            cloud_targets = load_cloud_targets(args.cloud_metadata_targets)
            ssrf_detector = SSRFCloudDetector(
                fixture_manager=fixture_manager,
                payload_generator=PayloadGenerator(openapi_parser.raw_spec),
                session_manager=session_manager,
                evidence_store=evidence_store,
                url_field_discovery=url_field_discovery,
                cloud_targets=cloud_targets,
                request_timeout=args.ssrf_request_timeout,
            )
            ssrf_findings = ssrf_detector.run()
        except FileNotFoundError as exc:
            logger.warning(
                "Detecteur SSRF cloud ignore - configuration manquante (%s).", exc
            )

    report = ReportGenerator(
        target_name=args.target_name,
        target_base_url=session_manager.base_url,
    )
    report.add_findings(bola_findings)
    report.add_findings(bfla_findings)
    report.add_findings(mass_assignment_findings)
    report.add_findings(excessive_exposure_findings)
    report.add_findings(rate_limiting_findings)
    report.add_findings(graphql_introspection_findings)
    report.add_findings(graphql_complexity_findings)
    report.add_findings(ssrf_findings)
    report.set_coverage_from_fixtures(fixtures, fixture_manager.failures)

    report.export_html(args.report_html)
    report.export_json(args.report_json)
    report.export_sarif(args.report_sarif)

    return report


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    report = run_scan(args)

    by_detector = report._build_summary().findings_by_detector
    total = len(report.findings)

    print(
        f"\nRapport genere : {total} finding(s) "
        f"({by_detector.get('bola', 0)} BOLA, {by_detector.get('bfla', 0)} BFLA, "
        f"{by_detector.get('mass_assignment', 0)} mass assignment, "
        f"{by_detector.get('excessive_exposure', 0)} exposition excessive, "
        f"{by_detector.get('rate_limiting', 0)} rate limiting, "
        f"{by_detector.get('graphql_introspection', 0)} introspection GraphQL, "
        f"{by_detector.get('graphql_complexity', 0)} complexite GraphQL, "
        f"{by_detector.get('ssrf_cloud', 0)} SSRF cloud), "
        f"couverture fixtures : {report.coverage.success_rate:.0%}"
    )
    print(f"  -> {args.report_html}")
    print(f"  -> {args.report_json}")
    print(f"  -> {args.report_sarif}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
