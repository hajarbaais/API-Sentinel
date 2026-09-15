"""
Detecteur d'absence de protection contre les requetes GraphQL trop
complexes (OWASP API4:2023 - Unrestricted Resource Consumption,
OS3 / P2 - bonus).

Technique ("alias overloading", cf. OWASP GraphQL Cheat Sheet) :
demander le meme champ trivial (`__typename`, present sur TOUS les
types GraphQL, ne necessite donc aucune connaissance prealable du
schema) un grand nombre de fois sous des alias distincts, dans UNE
seule requete. Un serveur qui applique une limite de profondeur, de
cout ou de nombre d'alias rejette une telle requete ; un serveur non
protege l'execute integralement.

Non-destructif par construction (ENF2) : `__typename` ne declenche
aucune lecture de donnees ni calcul couteux cote resolveur - seul le
NOMBRE d'alias distingue une requete normale d'une requete-sonde, et
ce nombre est volontairement borne (ALIAS_COUNT) a une valeur qui
reste negligeable pour un serveur sain tout en etant suffisante pour
reveler l'absence de toute limite (la plupart des bibliotheques de
protection - graphql-depth-limit, graphql-cost-analysis, limitation
du nombre d'alias - rejettent bien en-deca de ce seuil).

Comme les autres tests actifs potentiellement impactants nommes dans
le cahier des charges ("SSRF, charge, complexite GraphQL"), ce
detecteur re-verifie explicitement l'allowlist avant de s'executer
(EF8b).
"""

import logging
from typing import Optional

import requests

from api_sentinel.accounts.session_manager import Account, SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.evidence.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)

ALIAS_COUNT = 500


def build_alias_overload_query(alias_count: int) -> str:
    aliases = "\n".join(f"  a{i}: __typename" for i in range(alias_count))
    return f"query APISentinelComplexityProbe {{\n{aliases}\n}}"


def confirms_missing_complexity_protection(
    response_status: int,
    response_json: Optional[dict],
    expected_alias_count: int,
) -> bool:
    """
    Confirme l'absence de protection uniquement si la requete a ete
    executee EN ENTIER sans erreur : code 200, aucune cle 'errors', et
    exactement le nombre d'alias attendus presents dans 'data'. Un
    serveur protege renvoie typiquement une erreur (souvent avec
    'errors' mentionnant la complexite/profondeur/le cout, parfois
    avant meme d'executer quoi que ce soit) - un simple code 200 ne
    suffit donc jamais a lui seul comme preuve.
    """
    if response_status != 200 or not isinstance(response_json, dict):
        return False
    if response_json.get("errors"):
        return False
    data = response_json.get("data")
    if not isinstance(data, dict):
        return False
    return len(data) == expected_alias_count


class GraphQLComplexityDetector:

    DETECTOR_NAME = "graphql_complexity"

    def __init__(
        self,
        session_manager: SessionManager,
        evidence_store: EvidenceStore,
        graphql_endpoint: str = "/graphql",
        alias_count: int = ALIAS_COUNT,
        request_timeout: int = 15,
    ):
        self.session_manager = session_manager
        self.evidence_store = evidence_store
        self.graphql_endpoint = graphql_endpoint
        self.alias_count = alias_count
        self.request_timeout = request_timeout
        self.findings: list[Finding] = []

    def run(self, role: str = "attacker_same_level") -> list[Finding]:
        self.session_manager.allowlist.enforce(self.session_manager.base_url)

        account = self.session_manager.get_account(role)
        url = f"{account.base_url}{self.graphql_endpoint}"
        query = build_alias_overload_query(self.alias_count)

        try:
            response = requests.post(
                url, json={"query": query}, headers=account.auth_headers(),
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            logger.warning(
                "Endpoint GraphQL injoignable sur %s (%s) - detecteur ignore.", url, exc,
            )
            return []

        try:
            response_json = response.json()
        except ValueError:
            response_json = None

        confirmed = confirms_missing_complexity_protection(
            response.status_code, response_json, self.alias_count
        )

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method="POST",
            request_url=url,
            request_headers=account.auth_headers(),
            request_body={"query": f"<requete a {self.alias_count} alias de __typename>"},
            response_status=response.status_code,
            response_body={
                "errors_present": bool(response_json and response_json.get("errors")),
                "data_field_count": len(response_json["data"])
                if isinstance(response_json, dict) and isinstance(response_json.get("data"), dict)
                else 0,
            },
            finding_confirmed=confirmed,
        )

        if confirmed:
            self._record_finding(url, account, evidence.test_id)

        logger.info(
            "Detecteur complexite GraphQL termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _record_finding(self, url: str, account: Account, evidence_test_id: str) -> None:
        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.RESOURCE_CONSUMPTION,
            severity=Severity.MEDIUM,
            confidence=0.7,
            title=(
                f"Absence de limitation de complexite GraphQL sur {url} : "
                f"une requete a {self.alias_count} alias a ete executee "
                f"integralement sans etre rejetee."
            ),
            description=(
                f"Une requete-sonde ('alias overloading', OWASP GraphQL Cheat "
                f"Sheet) demandant le champ __typename sous {self.alias_count} "
                f"alias distincts a recu une reponse HTTP 200 sans aucune "
                f"erreur, avec les {self.alias_count} valeurs attendues "
                f"presentes. Ceci ne consomme en soi quasiment aucune "
                f"ressource (__typename est trivial a resoudre), mais "
                f"l'absence de rejet a ce volume suggere qu'aucune limite de "
                f"profondeur, de cout ou de nombre d'alias n'est appliquee - "
                f"un attaquant pourrait reproduire la meme technique avec des "
                f"champs reellement couteux (resolveurs avec jointures, "
                f"listes non paginees) pour un impact de deni de service "
                f"reel. Confiance plafonnee : ce test borne ne demontre pas "
                f"l'absence de protection a un volume superieur (ENF1, ENF2)."
            ),
            affected_endpoint=f"POST {self.graphql_endpoint}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role=account.role,
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage : python graphql_complexity.py <accounts.yaml> [graphql_endpoint] [alias_count]")
        sys.exit(1)

    graphql_endpoint = sys.argv[2] if len(sys.argv) > 2 else "/graphql"
    alias_count = int(sys.argv[3]) if len(sys.argv) > 3 else ALIAS_COUNT

    session_manager = SessionManager(sys.argv[1])
    session_manager.authenticate_all()

    evidence_store = EvidenceStore("evidence/graphql_complexity_evidence.jsonl")

    detector = GraphQLComplexityDetector(
        session_manager=session_manager,
        evidence_store=evidence_store,
        graphql_endpoint=graphql_endpoint,
        alias_count=alias_count,
    )
    findings = detector.run()

    print(f"\n{len(findings)} probleme(s) de complexite GraphQL confirme(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Protection de complexite presente (ou test non concluant).")
