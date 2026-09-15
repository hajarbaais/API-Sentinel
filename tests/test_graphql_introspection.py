"""
Tests unitaires du detecteur d'introspection GraphQL
(api_sentinel.detectors.graphql_introspection).

Aucune requete reseau : la logique de confirmation (is_introspection_exposed),
l'extraction des mutations exposees, et l'enregistrement du finding sont
testes independamment.
"""

from types import SimpleNamespace

from api_sentinel.detectors.graphql_introspection import (
    GraphQLIntrospectionDetector,
    extract_mutation_field_names,
    is_introspection_exposed,
)


# --- is_introspection_exposed ---

def test_real_schema_with_types_is_exposed():
    response = {"data": {"__schema": {"types": [{"name": "Query"}, {"name": "User"}]}}}
    assert is_introspection_exposed(response) is True


def test_missing_data_key_is_not_exposed():
    assert is_introspection_exposed({"errors": [{"message": "Introspection disabled"}]}) is False


def test_null_schema_is_not_exposed():
    assert is_introspection_exposed({"data": {"__schema": None}}) is False


def test_empty_types_list_is_not_exposed():
    assert is_introspection_exposed({"data": {"__schema": {"types": []}}}) is False


def test_non_dict_response_is_not_exposed():
    assert is_introspection_exposed(None) is False
    assert is_introspection_exposed("not json") is False


# --- extract_mutation_field_names ---

def test_extract_mutation_field_names_from_matching_type():
    schema = {
        "mutationType": {"name": "Mutation"},
        "types": [
            {"name": "Query", "fields": [{"name": "getUser"}]},
            {"name": "Mutation", "fields": [{"name": "deleteUser"}, {"name": "createOrder"}]},
        ],
    }
    assert extract_mutation_field_names(schema) == ["deleteUser", "createOrder"]


def test_no_mutation_type_returns_empty_list():
    schema = {"mutationType": None, "types": [{"name": "Query", "fields": []}]}
    assert extract_mutation_field_names(schema) == []


def test_mutation_type_declared_but_absent_from_types_returns_empty_list():
    schema = {"mutationType": {"name": "Mutation"}, "types": [{"name": "Query", "fields": []}]}
    assert extract_mutation_field_names(schema) == []


# --- Enregistrement du finding (sans reseau) ---

class _FakeEvidenceStore:
    def __init__(self):
        self.records = []

    def record(self, **kwargs):
        self.records.append(kwargs)
        return SimpleNamespace(test_id="fake-evidence-001")


def _bare_detector():
    detector = GraphQLIntrospectionDetector.__new__(GraphQLIntrospectionDetector)
    detector.evidence_store = _FakeEvidenceStore()
    detector.findings = []
    detector.graphql_endpoint = "/graphql"
    return detector


def test_record_finding_lists_exposed_mutations_in_description():
    detector = _bare_detector()
    schema = {
        "types": [{"name": "Query"}, {"name": "Mutation"}],
        "mutationType": {"name": "Mutation"},
    }
    schema["types"][1]["fields"] = [{"name": "deleteAccount"}]

    detector._record_finding("http://localhost:8888/graphql", schema, "fake-evidence-001")

    assert len(detector.findings) == 1
    finding = detector.findings[0]
    assert finding.confidence == 0.95
    assert finding.severity.value == "medium"
    assert "deleteAccount" in finding.description
    assert finding.attacker_role == "unauthenticated"


def test_record_finding_without_mutations_has_no_mutation_note():
    detector = _bare_detector()
    schema = {"types": [{"name": "Query"}], "mutationType": None}

    detector._record_finding("http://localhost:8888/graphql", schema, "fake-evidence-001")

    assert "egalement exposee" not in detector.findings[0].description
