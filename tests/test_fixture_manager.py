"""
Tests unitaires de FixtureManager (api_sentinel.fixtures.fixture_manager).

C'est la piece dont dependent BOLA et mass assignment : si elle ne
cree pas la fixture attendue, ou ne la relie pas au bon endpoint de
detail, ces detecteurs n'ont tout simplement rien a tester - en
silence, sans erreur visible. Aucun appel reseau reel : requests.post
et requests.request sont mockes.

Le matching creation -> detail a d'abord ete limite au prefixe strict
de chemin, ce qui echouait sur des API non strictement RESTful
(decouvert en benchmarkant contre crAPI, ground truth crapi-1) - voir
test_match_detail_endpoint_resolves_non_prefix_crapi_case pour le
repli par segment de ressource qui corrige ce cas.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from api_sentinel.discovery.openapi_parser import Endpoint
from api_sentinel.fixtures.fixture_manager import (
    Fixture,
    FixtureManager,
    _substitute_first_path_param,
)


# --- _substitute_first_path_param : substitution litterale (pas une regex) ---

def test_substitute_first_path_param_basic():
    assert _substitute_first_path_param("/users/{id}", "42") == "/users/42"


def test_substitute_first_path_param_only_replaces_first_segment():
    assert (
        _substitute_first_path_param("/a/{id}/b/{other}", "42")
        == "/a/42/b/{other}"
    )


def test_substitute_first_path_param_value_with_backslash_digit_does_not_crash():
    """Regression : re.sub(pattern, object_id, path) interprete un
    object_id contenant '\\1' comme une reference de groupe et leve
    re.error au lieu de faire une simple substitution litterale."""
    result = _substitute_first_path_param("/users/{id}", "abc\\1def")
    assert result == "/users/abc\\1def"


def test_substitute_first_path_param_value_with_backreference_group_does_not_crash():
    result = _substitute_first_path_param("/users/{id}", "\\g<name>")
    assert result == "/users/\\g<name>"


class _FakeAccount:
    def __init__(self, role: str, base_url: str = "http://api.test"):
        self.role = role
        self.base_url = base_url

    def auth_headers(self) -> dict:
        return {"Authorization": "Bearer faketoken"}


class _FakeSessionManager:
    def __init__(self):
        self._accounts: dict[str, _FakeAccount] = {}

    def get_account(self, role: str) -> _FakeAccount:
        return self._accounts.setdefault(role, _FakeAccount(role))


def _endpoint(path: str, method: str, has_path_param: bool = False) -> Endpoint:
    return Endpoint(path=path, method=method, parameters=[], summary="", has_path_param=has_path_param)


def _simple_creation_spec(path: str = "/items") -> dict:
    return {
        "paths": {
            path: {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"name": {"type": "string"}}}
                            }
                        }
                    }
                }
            }
        }
    }


# --- get_creation_endpoints / exclusions ---

def test_endpoints_with_path_param_are_never_creation_candidates():
    endpoints = [_endpoint("/items/{id}", "POST", has_path_param=True), _endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager())
    assert [ep.path for ep in fm.get_creation_endpoints()] == ["/items"]


def test_login_like_endpoints_are_excluded_from_creation(tmp_path):
    config_path = tmp_path / "excluded.yaml"
    config_path.write_text("excluded_path_keywords:\n  - login\n", encoding="utf-8")
    endpoints = [_endpoint("/auth/login", "POST"), _endpoint("/items", "POST")]
    fm = FixtureManager(
        endpoints=endpoints, raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
        excluded_keywords_config=str(config_path),
    )
    assert [ep.path for ep in fm.get_creation_endpoints()] == ["/items"]


def test_missing_excluded_keywords_config_warns_but_does_not_raise(tmp_path):
    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(
        endpoints=endpoints, raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
        excluded_keywords_config=str(tmp_path / "does_not_exist.yaml"),
    )
    assert [ep.path for ep in fm.get_creation_endpoints()] == ["/items"]


# --- _match_detail_endpoint ---

def test_match_detail_endpoint_finds_prefix_matching_get():
    creation_ep = _endpoint("/items", "POST")
    detail_ep = _endpoint("/items/{id}", "GET", has_path_param=True)
    unrelated_ep = _endpoint("/other/{id}", "GET", has_path_param=True)
    fm = FixtureManager(
        endpoints=[creation_ep, detail_ep, unrelated_ep],
        raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
    )
    assert fm._match_detail_endpoint(creation_ep) is detail_ep


def test_match_detail_endpoint_returns_none_when_nothing_matches():
    creation_ep = _endpoint("/items", "POST")
    fm = FixtureManager(
        endpoints=[creation_ep], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
    )
    assert fm._match_detail_endpoint(creation_ep) is None


def test_match_detail_endpoint_resolves_non_prefix_crapi_case():
    """
    Regression (limite crapi-1 corrigee) : /identity/api/v2/vehicle/add_vehicle
    (creation) et /identity/api/v2/vehicle/{vehicleId}/location (detail)
    designent la meme ressource logique, mais le detail path ne
    commence pas par "creation_path/" - le matching par prefixe seul
    echoue. Le repli sur le segment "vehicle" (partage par les deux
    chemins, juste avant le parametre de detail) doit les relier.
    """
    creation_ep = _endpoint("/identity/api/v2/vehicle/add_vehicle", "POST")
    detail_ep = _endpoint("/identity/api/v2/vehicle/{vehicleId}/location", "GET", has_path_param=True)
    fm = FixtureManager(
        endpoints=[creation_ep, detail_ep], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
    )
    assert fm._match_detail_endpoint(creation_ep) is detail_ep


def test_match_detail_endpoint_fallback_ignores_unrelated_resource():
    """Le repli par segment ne doit matcher que si le nom de ressource
    est reellement partage - pas n'importe quel endpoint GET a parametre."""
    creation_ep = _endpoint("/api/v2/vehicle/add_vehicle", "POST")
    unrelated_detail_ep = _endpoint("/api/v2/coupon/{couponId}", "GET", has_path_param=True)
    fm = FixtureManager(
        endpoints=[creation_ep, unrelated_detail_ep],
        raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
    )
    assert fm._match_detail_endpoint(creation_ep) is None


def test_match_detail_endpoint_prefix_match_still_takes_priority():
    """Quand un match par prefixe strict existe, il doit toujours etre
    prefere au repli par segment (heuristique la plus fiable d'abord)."""
    creation_ep = _endpoint("/items", "POST")
    prefix_detail_ep = _endpoint("/items/{id}", "GET", has_path_param=True)
    fm = FixtureManager(
        endpoints=[creation_ep, prefix_detail_ep],
        raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager(),
    )
    assert fm._match_detail_endpoint(creation_ep) is prefix_detail_ep


# --- _extract_object_id ---

def test_extract_object_id_prefers_id_over_other_candidates():
    fm = FixtureManager(endpoints=[], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager())
    assert fm._extract_object_id({"uuid": "u1", "id": "i1"}) == "i1"


def test_extract_object_id_falls_back_to_later_candidates():
    fm = FixtureManager(endpoints=[], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager())
    assert fm._extract_object_id({"uuid": "u1"}) == "u1"


def test_extract_object_id_returns_none_when_no_candidate_present():
    fm = FixtureManager(endpoints=[], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager())
    assert fm._extract_object_id({"unrelated_field": 1}) is None


# --- Fixture.resolved_detail_url ---

def test_resolved_detail_url_substitutes_the_path_parameter():
    fixture = Fixture(
        resource_type="/x", object_id="99", owner_role="victim",
        detail_endpoint="/x/{id}", detail_method="GET",
        creation_payload={}, raw_response={},
    )
    assert fixture.resolved_detail_url() == "/x/99"


# --- create_all_fixtures : succes ---

@patch("api_sentinel.fixtures.fixture_manager.requests.request")
@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_create_fixture_success_refetches_the_full_object(mock_post, mock_request):
    endpoints = [_endpoint("/items", "POST"), _endpoint("/items/{id}", "GET", has_path_param=True)]
    mock_post.return_value = MagicMock(status_code=201, json=lambda: {"id": "42", "name": "created"})
    mock_request.return_value = MagicMock(status_code=200, json=lambda: {"id": "42", "name": "full", "secret": "x"})

    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())
    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert len(fixtures) == 1
    fx = fixtures[0]
    assert fx.object_id == "42"
    assert fx.owner_role == "victim"
    assert fx.detail_endpoint == "/items/{id}"
    assert fx.detail_method == "GET"
    # La verite terrain vient bien de la relecture (GET), pas de la
    # reponse de creation (POST) - le champ "secret" n'apparait que
    # dans la relecture, ca confirme laquelle des deux reponses est
    # effectivement utilisee.
    assert fx.raw_response == {"id": "42", "name": "full", "secret": "x"}
    assert fm.failures == []


@patch("api_sentinel.fixtures.fixture_manager.requests.request")
@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_create_fixture_falls_back_to_creation_response_when_refetch_fails(mock_post, mock_request):
    endpoints = [_endpoint("/items", "POST"), _endpoint("/items/{id}", "GET", has_path_param=True)]
    mock_post.return_value = MagicMock(status_code=201, json=lambda: {"id": "1", "name": "created"})
    mock_request.return_value = MagicMock(status_code=404)

    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())
    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures[0].raw_response == {"id": "1", "name": "created"}


@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_create_all_fixtures_creates_one_fixture_per_role(mock_post):
    mock_post.return_value = MagicMock(status_code=201, json=lambda: {"id": "1"})

    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())
    fixtures = fm.create_all_fixtures(roles=["victim", "attacker_same_level"])

    assert {fx.owner_role for fx in fixtures} == {"victim", "attacker_same_level"}


# --- create_all_fixtures : echecs ---

def test_failure_recorded_when_payload_not_generable():
    endpoints = [_endpoint("/items", "POST")]
    raw_spec = {"paths": {"/items": {"post": {}}}}  # pas de requestBody
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=raw_spec, session_manager=_FakeSessionManager())

    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures == []
    assert len(fm.failures) == 1
    assert "non generable" in fm.failures[0].reason


@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_failure_recorded_on_unexpected_status_code(mock_post):
    mock_post.return_value = MagicMock(status_code=400, text='{"error":"bad request"}')
    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())

    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures == []
    assert fm.failures[0].reason.startswith("Code HTTP inattendu")


@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_failure_recorded_on_non_json_response(mock_post):
    mock_response = MagicMock(status_code=201)
    mock_response.json.side_effect = ValueError("not json")
    mock_post.return_value = mock_response
    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())

    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures == []
    assert "JSON valide" in fm.failures[0].reason


@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_failure_recorded_when_no_id_field_recognized(mock_post):
    mock_post.return_value = MagicMock(status_code=201, json=lambda: {"name": "no id anywhere"})
    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())

    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures == []
    assert "identifiant reconnu" in fm.failures[0].reason


@patch("api_sentinel.fixtures.fixture_manager.requests.post")
def test_failure_recorded_on_network_error(mock_post):
    mock_post.side_effect = requests.RequestException("connection refused")
    endpoints = [_endpoint("/items", "POST")]
    fm = FixtureManager(endpoints=endpoints, raw_openapi_spec=_simple_creation_spec(), session_manager=_FakeSessionManager())

    fixtures = fm.create_all_fixtures(roles=["victim"])

    assert fixtures == []
    assert "Erreur reseau" in fm.failures[0].reason


def test_no_creation_endpoints_returns_empty_list_without_error():
    fm = FixtureManager(endpoints=[], raw_openapi_spec={"paths": {}}, session_manager=_FakeSessionManager())
    assert fm.create_all_fixtures(roles=["victim"]) == []
    assert fm.failures == []
