"""
Detecteur d'introspection GraphQL accessible sans authentification
(OWASP API8:2023 - Security Misconfiguration, EF7 / OS3).

Principe : envoyer la requete d'introspection standard GraphQL a
l'endpoint cible SANS AUCUN jeton d'authentification (c'est le coeur
de EF7 : "verifier si l'introspection est accessible sans
authentification" - un serveur qui exige un token pour l'introspection
mais l'accepte quand meme ici serait un test invalide). Une reponse
n'est confirmee vulnerable que si elle contient un schema reellement
exploitable (`__schema.types` non vide) - un simple code 200 avec un
message d'erreur GraphQL (introspection desactivee cote serveur) ne
doit jamais compter comme une fuite.

Impact documente : un schema expose revele l'integralite des requetes
et MUTATIONS disponibles (y compris celles non documentees ou censees
rester internes), ce qui facilite la reconnaissance pour d'autres
classes d'attaques (BFLA, mass assignment) sans meme necessiter de
compte. Le detecteur extrait donc explicitement les noms des mutations
exposees comme preuve d'impact, au-dela du simple "introspection
activee : oui/non".

Non-destructif par construction (ENF2) : une seule requete de lecture
de schema, aucune mutation n'est jamais executee.
"""

import logging
from typing import Optional

import requests

from api_sentinel.accounts.session_manager import SessionManager
from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.evidence.evidence_store import EvidenceStore

logger = logging.getLogger(__name__)

# Introspection volontairement partielle (queryType/mutationType + noms
# de types et de champs) : suffisante pour prouver l'exposition et
# lister les mutations, sans reconstruire le schema complet (directives,
# interfaces, enums...) dont ce detecteur n'a pas besoin.
INTROSPECTION_QUERY = """
query APISentinelIntrospectionProbe {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields { name }
    }
  }
}
"""


def is_introspection_exposed(response_json: Optional[dict]) -> bool:
    """
    Confirme uniquement si la reponse contient un schema reel et
    exploitable - jamais sur le seul code HTTP (un serveur peut
    repondre 200 a une introspection desactivee, avec `data.__schema`
    absent ou une cle `errors`).
    """
    if not isinstance(response_json, dict):
        return False
    data = response_json.get("data")
    if not isinstance(data, dict):
        return False
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return False
    types = schema.get("types")
    return isinstance(types, list) and len(types) > 0


def extract_mutation_field_names(schema: dict) -> list[str]:
    """
    Retrouve, dans le schema deja recupere, les noms des champs du
    type Mutation racine - la preuve d'impact la plus parlante d'une
    introspection exposee (des actions d'ecriture non documentees
    peuvent etre decouvertes sans authentification).
    """
    mutation_type = schema.get("mutationType")
    if not isinstance(mutation_type, dict) or not mutation_type.get("name"):
        return []

    mutation_type_name = mutation_type["name"]
    for type_entry in schema.get("types", []):
        if type_entry.get("name") == mutation_type_name:
            fields = type_entry.get("fields") or []
            return [f["name"] for f in fields if f.get("name")]
    return []


class GraphQLIntrospectionDetector:

    DETECTOR_NAME = "graphql_introspection"

    def __init__(
        self,
        session_manager: SessionManager,
        evidence_store: EvidenceStore,
        graphql_endpoint: str = "/graphql",
        request_timeout: int = 10,
    ):
        self.session_manager = session_manager
        self.evidence_store = evidence_store
        self.graphql_endpoint = graphql_endpoint
        self.request_timeout = request_timeout
        self.findings: list[Finding] = []

    def run(self) -> list[Finding]:
        self.session_manager.allowlist.enforce(self.session_manager.base_url)

        url = f"{self.session_manager.base_url}{self.graphql_endpoint}"

        try:
            # EF7 : aucun header Authorization - c'est precisement ce
            # que ce detecteur doit verifier.
            response = requests.post(
                url, json={"query": INTROSPECTION_QUERY}, timeout=self.request_timeout,
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

        confirmed = is_introspection_exposed(response_json)

        evidence = self.evidence_store.record(
            detector=self.DETECTOR_NAME,
            request_method="POST",
            request_url=url,
            request_headers={},
            request_body={"query": INTROSPECTION_QUERY},
            response_status=response.status_code,
            response_body=(
                response_json if confirmed
                else {"note": "Introspection non exposee ou reponse non exploitable."}
            ),
            finding_confirmed=confirmed,
        )

        if confirmed:
            self._record_finding(url, response_json["data"]["__schema"], evidence.test_id)

        logger.info(
            "Detecteur introspection GraphQL termine : %d finding(s) confirme(s).",
            len(self.findings),
        )
        return self.findings

    def _record_finding(self, url: str, schema: dict, evidence_test_id: str) -> None:
        type_count = len(schema.get("types", []))
        mutation_names = extract_mutation_field_names(schema)

        mutation_note = ""
        if mutation_names:
            preview = ", ".join(mutation_names[:10])
            more = f" (+{len(mutation_names) - 10} autre(s))" if len(mutation_names) > 10 else ""
            mutation_note = (
                f" {len(mutation_names)} mutation(s) egalement exposee(s) sans "
                f"authentification : {preview}{more}."
            )

        finding = Finding(
            detector=self.DETECTOR_NAME,
            owasp_category=OwaspCategory.SECURITY_MISCONFIGURATION,
            severity=Severity.MEDIUM,
            confidence=0.95,
            title=(
                f"Introspection GraphQL accessible sans authentification sur "
                f"{url} ({type_count} type(s) exposes)."
            ),
            description=(
                f"La requete d'introspection standard a ete acceptee sans "
                f"aucun jeton d'authentification et a retourne un schema "
                f"exploitable ({type_count} type(s)).{mutation_note} Un "
                f"attaquant non authentifie peut ainsi cartographier "
                f"l'integralite de la surface d'attaque de l'API (requetes, "
                f"mutations, champs) sans avoir besoin d'un compte, ce qui "
                f"facilite la decouverte d'endpoints non documentes ou "
                f"destines a rester internes."
            ),
            affected_endpoint=f"POST {self.graphql_endpoint}",
            evidence_test_id=evidence_test_id,
            victim_role="N/A",
            attacker_role="unauthenticated",
        )
        self.findings.append(finding)
        logger.warning("FINDING CONFIRME : %s", finding.title)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage : python graphql_introspection.py <accounts.yaml> [graphql_endpoint]")
        sys.exit(1)

    graphql_endpoint = sys.argv[2] if len(sys.argv) > 2 else "/graphql"

    # Pas d'authentification necessaire : ce detecteur teste
    # precisement l'acces SANS compte. SessionManager n'est instancie
    # ici que pour reutiliser la base_url et l'allowlist deja
    # configurees.
    session_manager = SessionManager(sys.argv[1])

    evidence_store = EvidenceStore("evidence/graphql_introspection_evidence.jsonl")

    detector = GraphQLIntrospectionDetector(
        session_manager=session_manager,
        evidence_store=evidence_store,
        graphql_endpoint=graphql_endpoint,
    )
    findings = detector.run()

    print(f"\n{len(findings)} probleme(s) d'introspection GraphQL confirme(s) :\n")
    for f in findings:
        print(f"  [{f.severity.value.upper()}] {f.title} (confiance: {f.confidence:.0%})")

    if not findings:
        print("Introspection non exposee (ou endpoint GraphQL non atteint).")
