"""
Calcule les metriques de benchmark (vrais positifs / faux negatifs sur
le ground truth, findings hors ground truth a trier manuellement) a
partir d'un rapport JSON deja produit par `api-sentinel` et d'un
fichier de ground truth documente (section 7 du cahier des charges).

Ce script ne relance PAS de scan : il se contente de SCORER un rapport
existant. Ca decouple explicitement "executer le framework contre une
cible" (deja fait par la CLI) de "evaluer la qualite des resultats"
(ce script) - le meme rapport peut etre re-score sans re-tester la
cible, et un rapport produit par n'importe quel run (y compris un
outil concurrent adapte au meme format) peut en principe etre score de
la meme facon.

Methodologie de matching : chaque entree du ground truth porte un
endpoint template (ex: "GET /users/{id}"). Un finding y correspond si
son detecteur est identique ET si son affected_endpoint matche le
template une fois les segments {...} traites comme des jokers - gere
a la fois le format "METHODE /chemin" (BFLA, mass assignment,
excessive exposure, rate limiting, SSRF) et le format sans methode
utilisant l'URL resolue (BOLA, dont l'ID est deja substitue dans le
chemin).

Ne compte PAS automatiquement les findings non apparies comme des
faux positifs : un finding hors ground truth peut etre soit une vraie
faille non documentee officiellement (le detecteur BOLA a par exemple
trouve une fuite sur /community/api/v2/community/posts, absente de la
liste officielle des challenges crAPI, mais bien reelle), soit un
vrai faux positif - seule une verification manuelle tranche (ENF1).
"""

import argparse
import json
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _endpoint_pattern(method: str, templated_path: str) -> re.Pattern:
    segments = []
    for segment in templated_path.split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            segments.append(r"[^/]+")
        else:
            segments.append(re.escape(segment))
    path_pattern = "/".join(segments)
    # La methode est optionnelle en prefixe : certains detecteurs
    # (BOLA) ne la mettent pas dans affected_endpoint.
    return re.compile(rf"^(?:{re.escape(method)}\s+)?{path_pattern}$")


def _matches(vuln: dict, finding: dict) -> bool:
    if vuln.get("detector") != finding.get("detector"):
        return False
    endpoint_template = vuln.get("endpoint")
    if not endpoint_template:
        return False
    if " " not in endpoint_template:
        return False
    method, path = endpoint_template.split(" ", 1)
    pattern = _endpoint_pattern(method, path)
    return bool(pattern.match(finding.get("affected_endpoint", "")))


def score(report: dict, ground_truth: dict) -> dict:
    findings = report.get("findings", [])
    vulns = ground_truth.get("vulnerabilities", [])

    in_scope_vulns = [v for v in vulns if v.get("in_scope") and v.get("endpoint")]
    unmappable_in_scope = [v for v in vulns if v.get("in_scope") and not v.get("endpoint")]

    matched_finding_indices: set[int] = set()
    per_vulnerability_results = []

    for vuln in in_scope_vulns:
        matched_finding = None
        for i, finding in enumerate(findings):
            if i in matched_finding_indices:
                continue
            if _matches(vuln, finding):
                matched_finding = finding
                matched_finding_indices.add(i)
                break

        actual_outcome = "tp" if matched_finding else "fn"
        predicted_outcome = vuln.get("predicted_outcome")

        per_vulnerability_results.append({
            "id": vuln["id"],
            "challenge_name": vuln["challenge_name"],
            "endpoint": vuln["endpoint"],
            "predicted_outcome": predicted_outcome,
            "actual_outcome": actual_outcome,
            "prediction_confirmed": actual_outcome == predicted_outcome,
            "matched_finding_title": matched_finding["title"] if matched_finding else None,
        })

    true_positives = sum(1 for r in per_vulnerability_results if r["actual_outcome"] == "tp")
    false_negatives = sum(1 for r in per_vulnerability_results if r["actual_outcome"] == "fn")
    total = true_positives + false_negatives
    recall = (true_positives / total) if total else None

    surprises = [r for r in per_vulnerability_results if not r["prediction_confirmed"]]
    regressions = [
        r for r in surprises
        if r["predicted_outcome"] == "tp" and r["actual_outcome"] == "fn"
    ]

    findings_beyond_ground_truth = [
        {
            "title": f.get("title"),
            "detector": f.get("detector"),
            "affected_endpoint": f.get("affected_endpoint"),
            "confidence": f.get("confidence"),
            "note": (
                "Ne correspond a aucune entree du ground truth - peut etre "
                "une vraie faille non documentee officiellement, ou un faux "
                "positif : verification manuelle requise avant de la "
                "compter dans une metrique de precision."
            ),
        }
        for i, f in enumerate(findings)
        if i not in matched_finding_indices
    ]

    return {
        "target": ground_truth.get("target"),
        "in_scope_vulnerability_count": len(in_scope_vulns),
        "unmappable_in_scope_vulnerability_count": len(unmappable_in_scope),
        "true_positives": true_positives,
        "false_negatives": false_negatives,
        "recall": recall,
        "total_findings_in_report": len(findings),
        "findings_matched_to_ground_truth": len(matched_finding_indices),
        "findings_requiring_manual_triage": len(findings_beyond_ground_truth),
        "per_vulnerability_results": per_vulnerability_results,
        "regressions_vs_prediction": regressions,
        "other_surprises_vs_prediction": [r for r in surprises if r not in regressions],
        "findings_beyond_ground_truth_detail": findings_beyond_ground_truth,
    }


def render_text_summary(result: dict) -> str:
    lines = []
    lines.append(f"Benchmark : {result['target']}")
    lines.append("=" * 60)
    lines.append(
        f"Recall (sur ground truth cartographie et dans le "
        f"perimetre) : {result['true_positives']}/{result['in_scope_vulnerability_count']}"
        + (f" ({result['recall']:.0%})" if result["recall"] is not None else "")
    )
    if result["unmappable_in_scope_vulnerability_count"]:
        lines.append(
            f"  ({result['unmappable_in_scope_vulnerability_count']} vulnerabilite(s) "
            f"dans le perimetre mais sans endpoint cartographiable - exclue(s) du calcul)"
        )
    lines.append("")
    lines.append("Detail par vulnerabilite :")
    for r in result["per_vulnerability_results"]:
        mark = "OK" if r["actual_outcome"] == "tp" else "MANQUE"
        surprise = "" if r["prediction_confirmed"] else "  <-- INATTENDU (different du pronostic)"
        lines.append(f"  [{mark}] {r['id']} - {r['challenge_name']}{surprise}")

    if result["regressions_vs_prediction"]:
        lines.append("")
        lines.append("!!! REGRESSIONS (predites detectees, en realite manquees) :")
        for r in result["regressions_vs_prediction"]:
            lines.append(f"  - {r['id']} : {r['challenge_name']}")

    lines.append("")
    lines.append(
        f"Findings hors ground truth (a trier manuellement) : "
        f"{result['findings_requiring_manual_triage']}"
    )
    for f in result["findings_beyond_ground_truth_detail"]:
        lines.append(f"  - [{f['detector']}] {f['title']}")

    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Score un rapport API Sentinel deja produit contre un ground truth documente."
    )
    parser.add_argument("--report", required=True, help="Rapport JSON produit par `api-sentinel`.")
    parser.add_argument("--ground-truth", required=True, help="Fichier de ground truth (JSON).")
    parser.add_argument("--output", help="Chemin de sortie JSON pour le resultat du scoring.")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    ground_truth = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))

    result = score(report, ground_truth)

    print(render_text_summary(result))

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\nResultat detaille exporte : {output_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
