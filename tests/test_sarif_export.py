import json

from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.reporting.sarif_export import (
    SARIF_VERSION,
    endpoint_to_artifact_path,
    export_sarif,
    to_sarif,
)


def _finding(
    detector="bola",
    category=OwaspCategory.BOLA,
    severity=Severity.CRITICAL,
    confidence=0.9,
    affected_endpoint="GET /users/{id}",
    evidence_test_id="bola-00001",
) -> Finding:
    return Finding(
        detector=detector,
        owasp_category=category,
        severity=severity,
        confidence=confidence,
        title="Test finding",
        description="Description du finding de test.",
        affected_endpoint=affected_endpoint,
        evidence_test_id=evidence_test_id,
        victim_role="victim",
        attacker_role="attacker_same_level",
    )


# --- endpoint_to_artifact_path ---

def test_endpoint_converted_to_synthetic_path():
    assert endpoint_to_artifact_path("GET /users/{id}") == "api-endpoints/GET/users/{id}"


def test_same_endpoint_produces_same_path():
    assert endpoint_to_artifact_path("POST /orders") == endpoint_to_artifact_path("POST /orders")


def test_different_endpoints_produce_different_paths():
    assert endpoint_to_artifact_path("GET /a") != endpoint_to_artifact_path("GET /b")


# --- to_sarif : structure ---

def test_empty_findings_produces_valid_empty_document():
    doc = to_sarif([])
    assert doc["version"] == SARIF_VERSION
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["rules"] == []


def test_one_rule_per_detector_not_per_finding():
    findings = [
        _finding(detector="bola", severity=Severity.CRITICAL),
        _finding(detector="bola", severity=Severity.HIGH),
        _finding(detector="bfla", category=OwaspCategory.BFLA),
    ]
    doc = to_sarif(findings)
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == ["bola", "bfla"]
    assert len(doc["runs"][0]["results"]) == 3


def test_result_rule_index_matches_its_detector_rule():
    findings = [
        _finding(detector="bola"),
        _finding(detector="bfla", category=OwaspCategory.BFLA),
    ]
    doc = to_sarif(findings)
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    results = doc["runs"][0]["results"]

    for result in results:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_critical_severity_maps_to_error_level():
    doc = to_sarif([_finding(severity=Severity.CRITICAL)])
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_low_severity_maps_to_note_level():
    doc = to_sarif([_finding(severity=Severity.LOW)])
    assert doc["runs"][0]["results"][0]["level"] == "note"


def test_confidence_is_preserved_in_properties():
    doc = to_sarif([_finding(confidence=0.42)])
    assert doc["runs"][0]["results"][0]["properties"]["confidence"] == 0.42


def test_evidence_test_id_is_preserved_as_pointer_only():
    doc = to_sarif([_finding(evidence_test_id="bola-00007")])
    props = doc["runs"][0]["results"][0]["properties"]
    assert props["evidence_test_id"] == "bola-00007"


def test_no_raw_request_or_response_fields_present():
    """ENF5 : le SARIF ne doit jamais vehiculer de preuve brute (jeton, en-tetes)."""
    doc = to_sarif([_finding()])
    serialized = json.dumps(doc)
    assert "request_body" not in serialized
    assert "response_body" not in serialized
    assert "Bearer " not in serialized


def test_document_is_json_serializable():
    doc = to_sarif([_finding(), _finding(detector="ssrf_cloud", category=OwaspCategory.SSRF)])
    json.dumps(doc)  # ne doit pas lever


# --- export_sarif : ecriture sur disque ---

def test_export_sarif_writes_valid_json_file(tmp_path):
    output_path = tmp_path / "nested" / "report.sarif"
    export_sarif([_finding()], str(output_path))

    assert output_path.exists()
    content = json.loads(output_path.read_text(encoding="utf-8"))
    assert content["version"] == SARIF_VERSION
    assert len(content["runs"][0]["results"]) == 1
