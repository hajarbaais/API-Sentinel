
import logging
from pathlib import Path

import requests
import yaml

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.differential.role_hierarchy import RoleHierarchy
from api_sentinel.evidence.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)


class BFLADetector:
   

    DETECTOR_NAME = "bfla"

    def __init__(
        self,
        session_manager: SessionManager,
        role_hierarchy: RoleHierarchy,
        evidence_store: EvidenceStore,
        protected_endpoints_config: str,
        request_timeout: int = 10,
    ):
        self.session_manager = session_manager
        self.role_hierarchy = role_hierarchy
        self.evidence_store = evidence_store
        self.request_timeout = request_timeout
        self.protected_endpoints = self._load_protected_endpoints(protected_endpoints_config)
        self.findings: list[Finding] = []

    def _load_protected_endpoints(self, config_path: str) -> list[dict]:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Fichier des endpoints proteges introuvable : {path}"
            )
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        return content.get("protected_endpoints", [])

    def run(
        self,
        baseline_role: str = "victim",
        attacker_roles: list[str] | None = None,
    ) -> list[Finding]:
       
        if attacker_roles is None:
            attacker_roles = ["attacker_same_level", "attacker_lower_level"]

        if not self.protected_endpoints:
            logger.warning(
                "Aucun endpoint protege declare dans la configuration - "
                "le detecteur BFLA n'a rien a tester."
            )
            return []

        for endpoint_config in self.protected_endpoints:
            self._test_endpoint(endpoint_config, baseline_role, attacker_roles)

        logger.info(
            "Detecteur BFLA termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _test_endpoint(
        self, endpoint_config: dict, baseline_role: str, attacker_roles: list[str]
    ) -> None:
        path = endpoint_config["path"]
        method = endpoint_config["method"]
        minimum_role = endpoint_config["minimum_role"]

        baseline_status, _ = self._send_request(path, method, baseline_role)

        if baseline_status not in (200, 201, 204):
            logger.info(
                "Baseline non concluante pour %s %s (code %s, role '%s') - "
                "endpoint ignore pour eviter un faux positif.",
                method, path, baseline_status, baseline_role,
            )
            return

        for attacker_role in attacker_roles:
            try:
                is_lower = self.role_hierarchy.is_lower_privilege(attacker_role, minimum_role)
            except ValueError as exc:
                logger.warning("Test ignore pour '%s' : %s", attacker_role, exc)
                continue

            if not is_lower:
                logger.debug(
                    "Role '%s' non strictement inferieur a '%s', test ignore.",
                    attacker_role, minimum_role,
                )
                continue

            self._test_attacker(path, method, attacker_role, minimum_role)

    def _test_attacker(
        self, path: str, method: str, attacker_role: str, minimum_role: str
    ) -> None:
        account = self.session_manager.get_account(attacker_role)
        url = f"{account.base_url}{path}"

        status, body = self._send_request(path, method, attacker_role)
        finding_confirmed = status in (200, 201, 204)

        self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method=method,
            request_url=url,
            request_headers=account.auth_headers(),
            request_body=None,
            response_status=status,
            response_body=body,
            finding_confirmed=finding_confirmed,
        )

        if finding_confirmed:
            self._record_finding(path, method, attacker_role, minimum_role, status)

    def _send_request(self, path: str, method: str, role: str) -> tuple[int, dict | None]:
        account = self.session_manager.get_account(role)
        url = f"{account.base_url}{path}"

        try:
            response = requests.request(
                method, url, headers=account.auth_headers(), timeout=self.request_timeout
            )
        except requests.RequestException as exc:
            logger.error("Erreur reseau lors du test BFLA sur %s : %s", url, exc)
            return 0, None

        try:
            body = response.json()
        except ValueError:
            body = None

        return response.status_code, body

    def _record_finding(
        self, path: str, method: str, attacker_role: str, minimum_role: str, status: int
    ) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.BFLA,
            severity=Severity.HIGH,
            confidence=0.9,
            title=(
                f"BFLA confirme sur {method} {path} : le role '{attacker_role}' "
                f"(privilege inferieur a '{minimum_role}') a pu executer "
                f"cette action reservee."
            ),
            description=(
                f"La baseline avec un compte reellement autorise a reussi. "
                f"Le meme appel avec le token du role '{attacker_role}' a "
                f"egalement reussi (code {status}), alors qu'il aurait "
                f"du etre refuse."
            ),
            affected_endpoint=f"{method} {path}",
            evidence_test_id="",
            victim_role=minimum_role,
            attacker_role=attacker_role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)


if __name__ == "__main__":
    import sys

    from api_sentinel.accounts.session_manager import SessionManager
    from api_sentinel.evidence.evidence_store import EvidenceStore

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print(
            "Usage : python bfla.py <accounts.yaml> <protected_endpoints.yaml> "
            "[roles.yaml] [baseline_role]"
        )
        sys.exit(1)

    session_manager = SessionManager(sys.argv[1])
    session_manager.authenticate_all()

    roles_config = sys.argv[3] if len(sys.argv) > 3 else "config/roles.yaml"
    role_hierarchy = RoleHierarchy(roles_config)
    evidence_store = EvidenceStore("evidence/bfla_evidence.jsonl")

    detector = BFLADetector(
        session_manager=session_manager,
        role_hierarchy=role_hierarchy,
        evidence_store=evidence_store,
        protected_endpoints_config=sys.argv[2],
    )
    baseline = sys.argv[4] if len(sys.argv) > 4 else "victim"
    findings = detector.run(baseline_role=baseline)

    print(f"\n{len(findings)} faille(s) BFLA confirmee(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Aucune faille BFLA detectee.")