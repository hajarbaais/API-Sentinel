"""
Export SARIF 2.1.0 (EF5b) - permet l'integration native des findings
d'API Sentinel avec GitHub Code Scanning et l'outillage AppSec
standard (GitLab, DefectDojo, etc.), tous consommateurs du meme
format d'echange.

ENF5 : cet export ne contient JAMAIS de preuve brute (requete/reponse
capturee) - uniquement `evidence_test_id`, un pointeur vers
evidence_store.jsonl (acces restreint, ENF8). Un Finding est deja, par
construction (cf. base_detector.Finding), depourvu de tout secret en
clair : rien a filtrer ici, le SARIF ne fait que reformater ce que le
Finding expose deja.

Localisation : SARIF est concu pour du code source (fichier + ligne),
pas pour des endpoints d'API. A defaut de ligne de code reelle, chaque
finding est rattache a un chemin de "fichier" synthetique et STABLE
derive de son endpoint (ex. `GET /users/{id}` ->
`api-endpoints/GET/users/{id}`) : GitHub Code Scanning affiche alors
les findings groupes par endpoint dans son interface, plutot que comme
des alertes sans aucun contexte de localisation.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from api_sentinel.detectors.base_detector import Finding, Severity

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "API Sentinel"
TOOL_INFORMATION_URI = "https://github.com/api-sentinel/api-sentinel"

# SARIF 'level' : severite generique comprise par tout consommateur SARIF.
_LEVEL_BY_SEVERITY = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# 'security-severity' (extension GitHub, dans `properties`) : score
# 0-10 utilise par GitHub Code Scanning pour SON PROPRE badge
# Critical/High/Medium/Low, independant de 'level'. Bandes alignees
# sur les seuils par defaut de GitHub (>=9.0 critical, >=7.0 high,
# >=4.0 medium, sinon low).
_SECURITY_SEVERITY_BY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.5",
    Severity.INFO: "0.5",
}

_NON_PATH_CHARS = re.compile(r"[^A-Za-z0-9/_.{}-]+")


def endpoint_to_artifact_path(affected_endpoint: str) -> str:
    """
    Derive un chemin de "fichier" synthetique et stable a partir d'un
    endpoint (ex. 'GET /users/{id}' -> 'api-endpoints/GET/users/{id}'),
    pour que SARIF puisse le rattacher a une localisation. Deux
    findings sur le meme endpoint produisent le meme chemin, donc
    apparaissent regroupes dans l'interface de GitHub Code Scanning.
    """
    method, _, path = affected_endpoint.partition(" ")
    path = path or "unknown"
    sanitized = _NON_PATH_CHARS.sub("_", path.strip("/"))
    return f"api-endpoints/{method or 'UNKNOWN'}/{sanitized}"


def _group_by_detector(findings: list[Finding]) -> dict[str, list[Finding]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.detector, []).append(finding)
    return grouped


def _build_rule(detector_name: str, findings: list[Finding]) -> dict:
    # Chaque detecteur ne mappe qu'une seule categorie OWASP en
    # pratique (cf. base_detector.py) : le premier finding suffit a
    # documenter la regle.
    representative = findings[0]
    return {
        "id": detector_name,
        "name": detector_name,
        "shortDescription": {"text": representative.owasp_category.value},
        "fullDescription": {"text": representative.owasp_category.value},
        "helpUri": TOOL_INFORMATION_URI,
        "defaultConfiguration": {"level": _LEVEL_BY_SEVERITY[representative.severity]},
        "properties": {
            "tags": ["security", "api-security", representative.owasp_category.name.lower()],
        },
    }


def _build_result(finding: Finding, rule_index: int) -> dict:
    return {
        "ruleId": finding.detector,
        "ruleIndex": rule_index,
        "level": _LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": finding.description},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": endpoint_to_artifact_path(finding.affected_endpoint)},
                },
                "logicalLocations": [
                    {"fullyQualifiedName": finding.affected_endpoint, "kind": "resource"},
                ],
            }
        ],
        "properties": {
            # ENF5/EF5 : la confiance par finding voyage jusque dans
            # l'export SARIF, pas seulement dans le rapport HTML/JSON.
            "security-severity": _SECURITY_SEVERITY_BY_SEVERITY[finding.severity],
            "confidence": finding.confidence,
            "owasp_category": finding.owasp_category.value,
            "victim_role": finding.victim_role,
            "attacker_role": finding.attacker_role,
            "evidence_test_id": finding.evidence_test_id,
            "detected_at": finding.detected_at,
        },
    }


def to_sarif(findings: list[Finding], tool_version: str = "0.1.0") -> dict:
    """Construit le document SARIF 2.1.0 complet a partir des findings confirmes."""
    grouped = _group_by_detector(findings)
    detector_names = list(grouped.keys())
    rule_index_by_detector = {name: i for i, name in enumerate(detector_names)}

    rules = [_build_rule(name, grouped[name]) for name in detector_names]
    results = [_build_result(f, rule_index_by_detector[f.detector]) for f in findings]

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "informationUri": TOOL_INFORMATION_URI,
                        "version": tool_version,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def export_sarif(findings: list[Finding], output_path: str, tool_version: str = "0.1.0") -> None:
    """Ecrit le document SARIF sur disque, en creant le dossier parent si besoin."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(to_sarif(findings, tool_version), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
