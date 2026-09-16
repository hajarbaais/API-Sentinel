"""
Tests unitaires de la logique de decision du detecteur de rate
limiting (api_sentinel.detectors.rate_limiting).

is_missing_rate_limit et la selection de candidat POST-action sont
testees ici : le reste du detecteur emet de vraies requetes HTTP en
rafale, ce qui n'a pas sa place dans des tests unitaires.
"""

from types import SimpleNamespace

from api_sentinel.detectors.rate_limiting import RateLimitingDetector, is_missing_rate_limit
from api_sentinel.discovery.openapi_parser import Endpoint


def test_no_429_among_complete_sample_is_missing_rate_limit():
    assert is_missing_rate_limit([200] * 20, expected_count=20) is True


def test_a_single_429_is_enough_to_disprove_missing_rate_limit():
    statuses = [200] * 15 + [429] * 5
    assert is_missing_rate_limit(statuses, expected_count=20) is False


def test_incomplete_sample_due_to_network_error_is_not_conclusive():
    # Le test s'est arrete en cours de route (erreur reseau) : on ne
    # peut rien conclure, ni positif ni negatif.
    statuses = [200] * 7
    assert is_missing_rate_limit(statuses, expected_count=20) is False


def test_empty_sample_is_not_conclusive():
    assert is_missing_rate_limit([], expected_count=20) is False


def test_all_429_is_not_missing_rate_limit():
    assert is_missing_rate_limit([429] * 20, expected_count=20) is False


def _endpoint(path: str, method: str, has_path_param: bool = False) -> Endpoint:
    return Endpoint(path=path, method=method, parameters=[], summary="", has_path_param=has_path_param)


def _bare_detector(excluded_keywords: list[str] | None = None) -> RateLimitingDetector:
    detector = RateLimitingDetector.__new__(RateLimitingDetector)
    detector.excluded_keywords = excluded_keywords or []
    detector.payload_generator = None
    detector.findings = []
    return detector


# --- _is_excluded_action ---

def test_excluded_action_matches_keyword():
    detector = _bare_detector(excluded_keywords=["login", "password"])
    assert detector._is_excluded_action("/auth/login") is True


def test_non_excluded_action_does_not_match():
    detector = _bare_detector(excluded_keywords=["login", "password"])
    assert detector._is_excluded_action("/workshop/api/merchant/contact_mechanic") is False


# --- _test_one_post_action : selection du candidat (sans reseau) ---

def test_post_action_test_skipped_without_payload_generator():
    """include_post_actions sans spec OpenAPI fournie : ignore proprement,
    ne doit jamais tenter d'appeler _test_endpoint sans generateur."""
    detector = _bare_detector()
    called = []
    detector._test_endpoint = lambda *a, **k: called.append(a)

    detector._test_one_post_action(
        endpoints=[_endpoint("/workshop/api/merchant/contact_mechanic", "POST")],
        account=None,
    )
    assert called == []


def test_post_action_excludes_destructive_endpoints():
    detector = _bare_detector(excluded_keywords=["login"])
    detector.payload_generator = SimpleNamespace(generate_for_request_body=lambda op: {})
    detector.raw_spec = {}
    detector._get_operation_definition = lambda ep: {}

    called = []
    detector._test_endpoint = lambda *a, **k: called.append(a[0])

    detector._test_one_post_action(
        endpoints=[
            _endpoint("/auth/login", "POST"),
            _endpoint("/workshop/api/merchant/contact_mechanic", "POST"),
        ],
        account=None,
    )
    assert len(called) == 1
    assert called[0].path == "/workshop/api/merchant/contact_mechanic"


def test_post_action_ignores_endpoints_with_path_param():
    detector = _bare_detector()
    detector.payload_generator = object()
    detector.raw_spec = {}
    detector._get_operation_definition = lambda ep: {}

    called = []
    detector._test_endpoint = lambda *a, **k: called.append(a[0])

    detector._test_one_post_action(
        endpoints=[_endpoint("/items/{id}/action", "POST", has_path_param=True)],
        account=None,
    )
    assert called == []
