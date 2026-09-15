"""
Tests unitaires du detecteur de complexite GraphQL
(api_sentinel.detectors.graphql_complexity).

Aucune requete reseau : la construction de la requete-sonde et la
logique de confirmation sont testees independamment.
"""

from types import SimpleNamespace

from api_sentinel.detectors.graphql_complexity import (
    GraphQLComplexityDetector,
    build_alias_overload_query,
    confirms_missing_complexity_protection,
)


# --- build_alias_overload_query ---

def test_query_contains_exactly_the_requested_number_of_aliases():
    query = build_alias_overload_query(5)
    assert query.count("__typename") == 5
    assert "a0: __typename" in query
    assert "a4: __typename" in query


def test_zero_aliases_produces_an_empty_selection():
    query = build_alias_overload_query(0)
    assert "__typename" not in query


# --- confirms_missing_complexity_protection ---

def test_full_execution_without_errors_confirms_missing_protection():
    response_json = {"data": {f"a{i}": "Query" for i in range(500)}}
    assert confirms_missing_complexity_protection(200, response_json, 500) is True


def test_rejection_with_errors_is_not_confirmed():
    response_json = {"errors": [{"message": "Query is too complex"}]}
    assert confirms_missing_complexity_protection(200, response_json, 500) is False


def test_non_200_status_is_not_confirmed():
    response_json = {"data": {f"a{i}": "Query" for i in range(500)}}
    assert confirms_missing_complexity_protection(400, response_json, 500) is False


def test_partial_data_below_expected_count_is_not_confirmed():
    """Le serveur a execute une partie mais pas la totalite - signal ambigu,
    pas une preuve d'absence de protection."""
    response_json = {"data": {f"a{i}": "Query" for i in range(200)}}
    assert confirms_missing_complexity_protection(200, response_json, 500) is False


def test_non_dict_response_is_not_confirmed():
    assert confirms_missing_complexity_protection(200, None, 500) is False


def test_missing_data_key_is_not_confirmed():
    assert confirms_missing_complexity_protection(200, {}, 500) is False


# --- Enregistrement du finding (sans reseau) ---

class _FakeEvidenceStore:
    def __init__(self):
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)
        return SimpleNamespace(test_id="fake-evidence-001")


def test_record_finding_reports_alias_count_and_confidence():
    detector = GraphQLComplexityDetector.__new__(GraphQLComplexityDetector)
    detector.evidence_store = _FakeEvidenceStore()
    detector.findings = []
    detector.graphql_endpoint = "/graphql"
    detector.alias_count = 500
    account = SimpleNamespace(role="attacker_same_level")

    detector._record_finding("http://localhost:8888/graphql", account, "fake-evidence-001")

    assert len(detector.findings) == 1
    finding = detector.findings[0]
    assert finding.confidence == 0.7
    assert finding.severity.value == "medium"
    assert "500" in finding.title
    assert finding.attacker_role == "attacker_same_level"
