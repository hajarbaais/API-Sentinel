
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

from api_sentinel.discovery.openapi_parser import Endpoint
from api_sentinel.accounts.session_manager import Account, SessionManager
from api_sentinel.fixtures.payload_generator import PayloadGenerator

logger = logging.getLogger(__name__)


ID_FIELD_CANDIDATES = ["id", "uuid", "_id", "objectId"]


class FixtureCreationError(Exception):
   
    pass


@dataclass
class Fixture:
    
    resource_type: str         
    object_id: str             
    owner_role: str             
    detail_endpoint: str        
    detail_method: str         
    creation_payload: dict     
    raw_response: dict          
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def resolved_detail_url(self) -> str:
       
        import re
        return re.sub(r"\{[^}]+\}", self.object_id, self.detail_endpoint, count=1)


@dataclass
class FixtureCreationFailure:
    
    resource_type: str
    owner_role: str
    reason: str


class FixtureManager:
    CREATION_METHOD = "POST"

    def __init__(
        self,
        endpoints: list[Endpoint],
        raw_openapi_spec: dict,
        session_manager: SessionManager,
        request_timeout: int = 10,
    ):
        self.endpoints = endpoints
        self.session_manager = session_manager
        self.payload_generator = PayloadGenerator(raw_openapi_spec)
        self.raw_spec = raw_openapi_spec
        self.request_timeout = request_timeout

        self.fixtures: list[Fixture] = []
        self.failures: list[FixtureCreationFailure] = []

    def create_all_fixtures(self, roles: list[str]) -> list[Fixture]:
       
        creation_endpoints = self._find_creation_endpoints()

        if not creation_endpoints:
            logger.warning(
                "Aucun endpoint de creation (POST sans parametre d'ID) "
                "trouve dans la specification OpenAPI."
            )
            return []

        for role in roles:
            account = self.session_manager.get_account(role)
            for endpoint in creation_endpoints:
                self._create_fixture_for(endpoint, account)

        logger.info(
            "%d fixture(s) creee(s), %d echec(s).",
            len(self.fixtures),
            len(self.failures),
        )
        return self.fixtures

    def _find_creation_endpoints(self) -> list[Endpoint]:
        
        return [
            ep for ep in self.endpoints
            if ep.method == self.CREATION_METHOD and not ep.has_path_param
        ]

    def _create_fixture_for(self, endpoint: Endpoint, account: Account) -> None:
        
        operation = self._get_operation_definition(endpoint)
        payload = self.payload_generator.generate_for_request_body(operation)

        if payload is None:
            self._record_failure(
                endpoint, account,
                "Payload non generable (pas de schema JSON exploitable)."
            )
            return

        url = f"{account.base_url}{endpoint.path}"

        try:
            response = requests.post(
                url,
                json=payload,
                headers=account.auth_headers(),
                timeout=self.request_timeout,
            )
        except requests.RequestException as exc:
            self._record_failure(endpoint, account, f"Erreur reseau : {exc}")
            return

        if response.status_code not in (200, 201):
            self._record_failure(
                endpoint, account,
                f"Code HTTP inattendu : {response.status_code} "
                f"(corps de reponse : {response.text[:200]})"
            )
            return

        try:
            response_data = response.json()
        except ValueError:
            self._record_failure(
                endpoint, account,
                "La reponse du serveur n'est pas un JSON valide."
            )
            return

        object_id = self._extract_object_id(response_data)
        if object_id is None:
            self._record_failure(
                endpoint, account,
                f"Aucun champ d'identifiant reconnu dans la reponse "
                f"(champs recherches : {ID_FIELD_CANDIDATES})."
            )
            return

        detail_endpoint = self._match_detail_endpoint(endpoint)

        fixture = Fixture(
            resource_type=endpoint.path,
            object_id=str(object_id),
            owner_role=account.role,
            detail_endpoint=detail_endpoint.path if detail_endpoint else f"{endpoint.path}/{{id}}",
            detail_method=detail_endpoint.method if detail_endpoint else "GET",
            creation_payload=payload,
            raw_response=response_data,
        )
        self.fixtures.append(fixture)

    def _get_operation_definition(self, endpoint: Endpoint) -> dict:
       
        path_item = self.raw_spec.get("paths", {}).get(endpoint.path, {})
        return path_item.get(endpoint.method.lower(), {})

    def _extract_object_id(self, response_data: dict) -> Optional[str]:
        
        for field_name in ID_FIELD_CANDIDATES:
            if field_name in response_data:
                return response_data[field_name]
        return None

    def _match_detail_endpoint(self, creation_endpoint: Endpoint) -> Optional[Endpoint]:
        
        candidates = [
            ep for ep in self.endpoints
            if ep.method == "GET"
            and ep.has_path_param
            and ep.path.startswith(creation_endpoint.path.rstrip("/") + "/")
        ]
        return candidates[0] if candidates else None

    def _record_failure(self, endpoint: Endpoint, account: Account, reason: str) -> None:
        
        logger.warning(
            "Echec de creation de fixture pour %s %s (role: %s) : %s",
            endpoint.method, endpoint.path, account.role, reason,
        )
        self.failures.append(
            FixtureCreationFailure(
                resource_type=endpoint.path,
                owner_role=account.role,
                reason=reason,
            )
        )


if __name__ == "__main__":
    import sys
    from api_sentinel.discovery.openapi_parser import OpenAPIParser

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 3:
        print("Usage : python fixture_manager.py <openapi.yaml> <accounts.yaml>")
        sys.exit(1)

    parser = OpenAPIParser(sys.argv[1])
    endpoints = parser.parse()

    session_manager = SessionManager(sys.argv[2])
    session_manager.authenticate_all()

    manager = FixtureManager(
        endpoints=endpoints,
        raw_openapi_spec=parser.raw_spec,
        session_manager=session_manager,
    )
    fixtures = manager.create_all_fixtures(
        roles=["victim", "attacker_same_level", "attacker_lower_level"]
    )

    print(f"\n{len(fixtures)} fixture(s) creee(s) :\n")
    for fx in fixtures:
        print(f"  [{fx.owner_role}] {fx.resource_type} -> id={fx.object_id}")

    if manager.failures:
        print(f"\n{len(manager.failures)} echec(s) :\n")
        for f in manager.failures:
            print(f"  [{f.owner_role}] {f.resource_type} -> {f.reason}")