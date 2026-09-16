"""
Detecteur d'exposition excessive de donnees (OWASP API3:2023 - Broken
Object Property Level Authorization, meme categorie que le mass
assignment depuis la fusion 2023 de l'ancien "Excessive Data
Exposure").

Principe : comparer les champs REELLEMENT presents dans une reponse
deja capturee (via FixtureManager) au schema de reponse DECLARE dans
la specification OpenAPI. Un champ present dans la reponse mais absent
du schema documente, et classe sensible (config/sensitive_fields.yaml,
le meme classificateur que le comparateur differentiel), signale une
serialisation cote serveur qui renvoie l'objet complet au lieu des
seuls champs prevus - typiquement un mot de passe hache, un champ
interne, ou les donnees d'un autre utilisateur imbriquees par erreur.

Particularite : contrairement aux autres detecteurs, celui-ci
n'emet AUCUNE requete reseau supplementaire - il reutilise les
reponses deja capturees par FixtureManager lors de la creation des
fixtures. Cout nul, aucun risque de charge (ENF2).

Limite connue, a documenter dans le benchmark : la couverture de ce
detecteur depend entierement de la qualite du schema de reponse
declare dans la spec OpenAPI. Un endpoint dont la reponse n'a aucun
schema documente (ou un schema sans "properties" explicite) n'est pas
testable - ce n'est pas une erreur du detecteur, mais une limite de la
documentation de l'API elle-meme.
"""

import logging
from typing import Optional

from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import Fixture

logger = logging.getLogger(__name__)


class ExcessiveExposureDetector:

    DETECTOR_NAME = "excessive_exposure"

    def __init__(
        self,
        raw_openapi_spec: dict,
        sensitivity_classifier: FieldSensitivityClassifier,
        evidence_store: EvidenceStore,
    ):
        self.raw_spec = raw_openapi_spec
        self.components = raw_openapi_spec.get("components", {}).get("schemas", {})
        self.sensitivity_classifier = sensitivity_classifier
        self.evidence_store = evidence_store
        self.findings: list[Finding] = []

    def run(self, fixtures: list[Fixture]) -> list[Finding]:
        tested_endpoints: set[str] = set()

        for fixture in fixtures:
            # Un seul controle par endpoint de detail suffit - le
            # schema declare est le meme quel que soit le role qui a
            # cree la fixture.
            if fixture.detail_endpoint in tested_endpoints:
                continue
            tested_endpoints.add(fixture.detail_endpoint)
            self._check_fixture(fixture)

        logger.info(
            "Detecteur exposition excessive termine : %d finding(s) "
            "confirme(s) sur %d endpoint(s) analyse(s).",
            len(self.findings), len(tested_endpoints),
        )
        return self.findings

    def _check_fixture(self, fixture: Fixture) -> None:
        if not isinstance(fixture.raw_response, dict):
            return

        declared_fields = self._declared_response_fields(
            fixture.detail_endpoint, fixture.detail_method
        )
        if declared_fields is None:
            logger.debug(
                "Pas de schema de reponse exploitable pour %s %s - "
                "endpoint ignore (limite de couverture connue).",
                fixture.detail_method, fixture.detail_endpoint,
            )
            return

        actual_fields = set(fixture.raw_response.keys())
        undocumented_fields = actual_fields - declared_fields
        sensitive_undocumented = sorted(
            f for f in undocumented_fields if self.sensitivity_classifier.is_sensitive(f)
        )

        confirmed = bool(sensitive_undocumented)

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=fixture.detail_method,
            request_url=fixture.resolved_detail_url(),
            request_headers={},
            request_body=None,
            # Reponse deja capturee par FixtureManager via un GET
            # reussi (ou, a defaut, la reponse de creation) - le code
            # exact n'est pas trace individuellement sur Fixture.
            response_status=200,
            response_body={
                "undocumented_fields": sorted(undocumented_fields),
                "sensitive_undocumented_fields": sensitive_undocumented,
            },
            finding_confirmed=confirmed,
        )

        if confirmed:
            self._record_finding(fixture, sensitive_undocumented, evidence.test_id)

    def _declared_response_fields(self, path: str, method: str) -> Optional[set[str]]:
        path_item = self.raw_spec.get("paths", {}).get(path, {})
        operation = path_item.get(method.lower(), {})
        responses = operation.get("responses", {})

        response_schema = None
        for status_code in ("200", "201", "default"):
            response = responses.get(status_code)
            if not response:
                continue
            response_schema = response.get("content", {}).get("application/json", {}).get("schema")
            if response_schema:
                break

        if not response_schema:
            return None

        response_schema = self._resolve(response_schema)
        properties = response_schema.get("properties")
        if properties is None:
            return None

        return set(properties.keys())

    def _resolve(self, schema: dict) -> dict:
        if "$ref" not in schema:
            return schema
        ref = schema["$ref"]
        if not ref.startswith("#/components/schemas/"):
            logger.debug(
                "Reference non supportee ignoree (schema traite comme vide) : %s", ref,
            )
            return {}
        resolved = self.components.get(ref.split("/")[-1])
        if resolved is None:
            logger.debug(
                "Schema reference introuvable, traite comme vide : %s", ref,
            )
            return {}
        return resolved

    def _record_finding(
        self, fixture: Fixture, sensitive_undocumented: list[str], evidence_test_id: str
    ) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.BOPLA,
            severity=Severity.MEDIUM,
            confidence=self._compute_confidence(sensitive_undocumented),
            title=(
                f"Exposition excessive de donnees sur {fixture.detail_method} "
                f"{fixture.detail_endpoint} : {len(sensitive_undocumented)} "
                f"champ(s) sensible(s) non documente(s) retourne(s) "
                f"({', '.join(sensitive_undocumented)})."
            ),
            description=(
                f"La reponse reelle de l'endpoint contient "
                f"{', '.join(sensitive_undocumented)}, absent(s) du schema de "
                f"reponse declare dans la specification OpenAPI. Un client ne "
                f"s'attendant qu'aux champs documentes recoit des donnees "
                f"sensibles supplementaires non prevues - typique d'une "
                f"serialisation cote serveur qui renvoie l'objet complet au "
                f"lieu des seuls champs necessaires (OWASP API3:2023)."
            ),
            affected_endpoint=f"{fixture.detail_method} {fixture.detail_endpoint}",
            evidence_test_id=evidence_test_id,
            victim_role=fixture.owner_role,
            attacker_role="N/A",
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)

    def _compute_confidence(self, sensitive_undocumented: list[str]) -> float:
        categories = {
            self.sensitivity_classifier.category_of(f) for f in sensitive_undocumented
        }
        if "secret" in categories:
            return 0.95
        if len(sensitive_undocumented) >= 2:
            return 0.85
        return 0.7


if __name__ == "__main__":
    import sys

    from api_sentinel.accounts.session_manager import SessionManager
    from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
    from api_sentinel.discovery.openapi_parser import OpenAPIParser
    from api_sentinel.fixtures.fixture_manager import FixtureManager

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python excessive_exposure.py <openapi.json> <accounts.yaml> "
            "[excluded_actions.yaml] [sensitive_fields.yaml]"
        )
        sys.exit(1)

    excluded_config = sys.argv[3] if len(sys.argv) > 3 else "config/excluded_action_endpoints.yaml"
    sensitive_fields_config = sys.argv[4] if len(sys.argv) > 4 else "config/sensitive_fields.yaml"

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

    sensitivity = FieldSensitivityClassifier(sensitive_fields_config)
    evidence_store = EvidenceStore("evidence/excessive_exposure_evidence.jsonl")

    detector = ExcessiveExposureDetector(parser.raw_spec, sensitivity, evidence_store)
    findings = detector.run(fixtures)

    print(f"\n{len(findings)} faille(s) d'exposition excessive confirmee(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Aucune exposition excessive detectee.")
