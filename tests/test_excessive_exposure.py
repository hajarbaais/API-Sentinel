"""
Tests unitaires du detecteur d'exposition excessive
(api_sentinel.detectors.excessive_exposure).

Ce detecteur ne fait aucun appel reseau : il compare des reponses
deja capturees (Fixture.raw_response) au schema de reponse declare
dans la spec OpenAPI. Tout est donc testable sans mock HTTP.
"""

import pytest

from api_sentinel.detectors.excessive_exposure import ExcessiveExposureDetector
from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.evidence.evidence_store import EvidenceStore
from api_sentinel.fixtures.fixture_manager import Fixture

SENSITIVE_FIELDS_YAML = """
sensitive_fields:
  pii:
    - email
  secret:
    - password_hash

dynamic_fields:
  - id
"""


def _make_fixture(raw_response, detail_endpoint="/users/{id}", detail_method="GET"):
    return Fixture(
        resource_type="/users",
        object_id="42",
        owner_role="victim",
        detail_endpoint=detail_endpoint,
        detail_method=detail_method,
        creation_payload={},
        raw_response=raw_response,
    )


def _detector(tmp_path, raw_spec, evidence_filename="evidence.jsonl"):
    config_path = tmp_path / "sensitive_fields.yaml"
    config_path.write_text(SENSITIVE_FIELDS_YAML, encoding="utf-8")
    sensitivity = FieldSensitivityClassifier(str(config_path))
    evidence_store = EvidenceStore(str(tmp_path / evidence_filename))
    return ExcessiveExposureDetector(raw_spec, sensitivity, evidence_store)


def _spec_with_user_response_schema(properties: dict) -> dict:
    return {
        "paths": {
            "/users/{id}": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object", "properties": properties}
                                }
                            }
                        }
                    }
                }
            }
        }
    }


def test_undocumented_sensitive_field_is_a_finding(tmp_path):
    spec = _spec_with_user_response_schema({"id": {"type": "string"}, "name": {"type": "string"}})
    detector = _detector(tmp_path, spec)

    fixture = _make_fixture({"id": "42", "name": "vic", "email": "vic@test.com"})
    findings = detector.run([fixture])

    assert len(findings) == 1
    assert "email" in findings[0].title


def test_documented_field_is_never_a_finding(tmp_path):
    spec = _spec_with_user_response_schema({"id": {"type": "string"}, "email": {"type": "string"}})
    detector = _detector(tmp_path, spec)

    fixture = _make_fixture({"id": "42", "email": "vic@test.com"})
    findings = detector.run([fixture])

    assert findings == []


def test_undocumented_non_sensitive_field_is_not_a_finding(tmp_path):
    spec = _spec_with_user_response_schema({"id": {"type": "string"}})
    detector = _detector(tmp_path, spec)

    # "nickname" n'est pas dans SENSITIVE_FIELDS_YAML pour ce test.
    fixture = _make_fixture({"id": "42", "nickname": "vic"})
    findings = detector.run([fixture])

    assert findings == []


def test_endpoint_without_response_schema_is_skipped(tmp_path):
    spec = {"paths": {"/users/{id}": {"get": {"responses": {"200": {"description": "OK"}}}}}}
    detector = _detector(tmp_path, spec)

    fixture = _make_fixture({"id": "42", "password_hash": "abc123"})
    findings = detector.run([fixture])

    assert findings == []


def test_ref_resolution_in_response_schema(tmp_path):
    spec = {
        "components": {
            "schemas": {
                "User": {"type": "object", "properties": {"id": {"type": "string"}}}
            }
        },
        "paths": {
            "/users/{id}": {
                "get": {
                    "responses": {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/User"}
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    detector = _detector(tmp_path, spec)

    fixture = _make_fixture({"id": "42", "password_hash": "abc123"})
    findings = detector.run([fixture])

    assert len(findings) == 1
    assert "password_hash" in findings[0].title


def test_same_endpoint_is_checked_only_once_across_fixtures(tmp_path):
    spec = _spec_with_user_response_schema({"id": {"type": "string"}})
    detector = _detector(tmp_path, spec)

    fixtures = [
        _make_fixture({"id": "1", "email": "a@test.com"}, detail_endpoint="/users/{id}"),
        _make_fixture({"id": "2", "email": "b@test.com"}, detail_endpoint="/users/{id}"),
    ]
    findings = detector.run(fixtures)

    assert len(findings) == 1


def test_secret_field_yields_higher_confidence_than_pii(tmp_path):
    spec = _spec_with_user_response_schema({"id": {"type": "string"}})
    detector = _detector(tmp_path, spec)

    secret_findings = detector.run([_make_fixture({"id": "1", "password_hash": "x"})])
    assert secret_findings[0].confidence == 0.95

    detector2 = _detector(tmp_path, spec, evidence_filename="evidence2.jsonl")
    pii_findings = detector2.run([_make_fixture({"id": "1", "email": "x@test.com"})])
    assert pii_findings[0].confidence == 0.7
