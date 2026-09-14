"""
Tests unitaires du script de scoring de benchmark
(benchmark/run_benchmark.py).

benchmark/ n'est pas un sous-package de api_sentinel (c'est un outil
d'evaluation, pas une brique du framework livre) - le module est donc
charge directement par chemin de fichier plutot qu'importe normalement.
"""

import importlib.util
from pathlib import Path

import pytest

_MODULE_PATH = Path(__file__).resolve().parent.parent / "benchmark" / "run_benchmark.py"
_spec = importlib.util.spec_from_file_location("run_benchmark", _MODULE_PATH)
run_benchmark = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_benchmark)


# --- _endpoint_pattern / _matches ---

def test_endpoint_pattern_matches_templated_param():
    pattern = run_benchmark._endpoint_pattern("GET", "/users/{id}/videos")
    assert pattern.match("GET /users/42/videos")
    assert pattern.match("/users/42/videos")  # methode absente, tolere (cas BOLA)
    assert not pattern.match("GET /users/42/photos")


def test_matches_requires_same_detector():
    vuln = {"detector": "bola", "endpoint": "GET /users/{id}"}
    finding = {"detector": "bfla", "affected_endpoint": "GET /users/42"}
    assert run_benchmark._matches(vuln, finding) is False


def test_matches_handles_bola_style_endpoint_without_method_prefix():
    vuln = {"detector": "bola", "endpoint": "GET /vehicle/{vehicleId}/location"}
    finding = {"detector": "bola", "affected_endpoint": "/vehicle/abc-123-guid/location"}
    assert run_benchmark._matches(vuln, finding) is True


def test_matches_false_when_no_endpoint_template():
    vuln = {"detector": "bola", "endpoint": None}
    finding = {"detector": "bola", "affected_endpoint": "/vehicle/42/location"}
    assert run_benchmark._matches(vuln, finding) is False


# --- score() ---

@pytest.fixture
def ground_truth():
    return {
        "target": "Cible de test",
        "vulnerabilities": [
            {
                "id": "v1", "challenge_name": "BOLA sur les factures",
                "in_scope": True, "detector": "bola",
                "endpoint": "GET /factures/{id}", "predicted_outcome": "tp",
            },
            {
                "id": "v2", "challenge_name": "BFLA sur l'admin",
                "in_scope": True, "detector": "bfla",
                "endpoint": "GET /admin/users", "predicted_outcome": "fn",
            },
            {
                "id": "v3", "challenge_name": "Hors perimetre (injection SQL)",
                "in_scope": False, "detector": None,
                "endpoint": None, "predicted_outcome": "not_applicable",
            },
        ],
    }


def test_score_counts_true_positive_when_finding_matches(ground_truth):
    report = {
        "findings": [
            {"detector": "bola", "affected_endpoint": "/factures/99", "title": "BOLA confirme"},
        ]
    }
    result = run_benchmark.score(report, ground_truth)

    assert result["true_positives"] == 1
    assert result["false_negatives"] == 1
    assert result["recall"] == 0.5
    assert result["in_scope_vulnerability_count"] == 2  # v3 exclu (hors perimetre)


def test_score_flags_a_regression_when_a_predicted_tp_is_actually_missed(ground_truth):
    # v1 etait pronostique "tp" mais aucun finding ne le confirme.
    report = {"findings": []}
    result = run_benchmark.score(report, ground_truth)

    assert result["true_positives"] == 0
    assert result["false_negatives"] == 2
    regression_ids = [r["id"] for r in result["regressions_vs_prediction"]]
    assert regression_ids == ["v1"]


def test_score_does_not_flag_a_confirmed_prediction_as_a_surprise(ground_truth):
    report = {
        "findings": [
            {"detector": "bola", "affected_endpoint": "/factures/99", "title": "BOLA confirme"},
        ]
    }
    result = run_benchmark.score(report, ground_truth)

    # v1: predit tp, obtenu tp -> pas une surprise. v2: predit fn, obtenu fn -> pas une surprise.
    assert result["regressions_vs_prediction"] == []
    assert result["other_surprises_vs_prediction"] == []


def test_score_buckets_unmatched_findings_for_manual_triage(ground_truth):
    report = {
        "findings": [
            {"detector": "bola", "affected_endpoint": "/factures/99", "title": "BOLA confirme"},
            {
                "detector": "bola", "affected_endpoint": "/community/posts/xyz",
                "title": "BOLA non documente officiellement", "confidence": 0.9,
            },
        ]
    }
    result = run_benchmark.score(report, ground_truth)

    assert result["findings_requiring_manual_triage"] == 1
    assert result["findings_beyond_ground_truth_detail"][0]["title"] == (
        "BOLA non documente officiellement"
    )


def test_score_does_not_double_count_the_same_finding_for_two_vulnerabilities():
    ground_truth_with_duplicate_endpoint = {
        "target": "Cible de test",
        "vulnerabilities": [
            {
                "id": "v1", "challenge_name": "Premiere entree", "in_scope": True,
                "detector": "bola", "endpoint": "GET /factures/{id}", "predicted_outcome": "tp",
            },
            {
                "id": "v2", "challenge_name": "Deuxieme entree, meme endpoint", "in_scope": True,
                "detector": "bola", "endpoint": "GET /factures/{id}", "predicted_outcome": "tp",
            },
        ],
    }
    report = {
        "findings": [
            {"detector": "bola", "affected_endpoint": "/factures/99", "title": "BOLA confirme"},
        ]
    }
    result = run_benchmark.score(report, ground_truth_with_duplicate_endpoint)

    assert result["true_positives"] == 1
    assert result["false_negatives"] == 1
