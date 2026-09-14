
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from api_sentinel.detectors.base_detector import Finding
from api_sentinel.fixtures.fixture_manager import Fixture, FixtureCreationFailure
from api_sentinel.scoring.risk_scorer import RiskScorer

logger = logging.getLogger(__name__)


@dataclass
class CoverageStats:
    
    total_creation_endpoints_attempted: int
    fixtures_created_successfully: int
    creation_failures: int
    failure_reasons: list[dict] = field(default_factory=list)

    @property
    def success_rate(self) -> float:
        if self.total_creation_endpoints_attempted == 0:
            return 0.0
        return self.fixtures_created_successfully / self.total_creation_endpoints_attempted


@dataclass
class ReportSummary:
    
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_detector: dict[str, int]
    findings_by_owasp_category: dict[str, int]


class ReportGenerator:
    
    def __init__(self, target_name: str, target_base_url: str):
        self.target_name = target_name
        self.target_base_url = target_base_url
        self.findings: list[Finding] = []
        self.coverage: CoverageStats | None = None
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self._risk_scorer = RiskScorer()

    def add_findings(self, findings: list[Finding]) -> None:
       
        self.findings.extend(findings)

    def set_coverage_from_fixtures(
        self, fixtures: list[Fixture], failures: list[FixtureCreationFailure]
    ) -> None:
       
        total_attempted = len(fixtures) + len(failures)
        self.coverage = CoverageStats(
            total_creation_endpoints_attempted=total_attempted,
            fixtures_created_successfully=len(fixtures),
            creation_failures=len(failures),
            failure_reasons=[
                {
                    "endpoint": f.resource_type,
                    "role": f.owner_role,
                    "reason": f.reason,
                }
                for f in failures
            ],
        )

    def _build_summary(self) -> ReportSummary:
        by_severity: dict[str, int] = {}
        by_detector: dict[str, int] = {}
        by_category: dict[str, int] = {}

        for finding in self.findings:
            severity_key = finding.severity.value
            by_severity[severity_key] = by_severity.get(severity_key, 0) + 1

            by_detector[finding.detector] = by_detector.get(finding.detector, 0) + 1

            category_key = finding.owasp_category.value
            by_category[category_key] = by_category.get(category_key, 0) + 1

        return ReportSummary(
            total_findings=len(self.findings),
            findings_by_severity=by_severity,
            findings_by_detector=by_detector,
            findings_by_owasp_category=by_category,
        )

    def to_dict(self) -> dict:

        summary = self._build_summary()
        risk_score = self._risk_scorer.score(self.findings)

        return {
            "target_name": self.target_name,
            "target_base_url": self.target_base_url,
            "generated_at": self.generated_at,
            "summary": asdict(summary),
            "risk_score": risk_score.to_dict(),
            "coverage": asdict(self.coverage) if self.coverage else None,
            "findings": [
                {
                    "detector": f.detector,
                    "owasp_category": f.owasp_category.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "title": f.title,
                    "description": f.description,
                    "affected_endpoint": f.affected_endpoint,
                    "evidence_test_id": f.evidence_test_id,
                    "victim_role": f.victim_role,
                    "attacker_role": f.attacker_role,
                    "detected_at": f.detected_at,
                }
                for f in self.findings
            ],
        }

    def export_json(self, output_path: str) -> None:
        """Exporte le rapport complet au format JSON."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Rapport JSON exporte : %s", path)

    def export_html(self, output_path: str) -> None:
        """Exporte le rapport complet au format HTML lisible."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        html = self._render_html()
        path.write_text(html, encoding="utf-8")
        logger.info("Rapport HTML exporte : %s", path)

    def _render_html(self) -> str:
        summary = self._build_summary()
        risk_score = self._risk_scorer.score(self.findings)

        severity_colors = {
            "critical": "#7a1f1f",
            "high": "#a8471f",
            "medium": "#a88a1f",
            "low": "#4a7a2f",
            "info": "#3a5a7a",
        }
        risk_level_colors = {
            "critical": "#7a1f1f",
            "high": "#a8471f",
            "medium": "#a88a1f",
            "low": "#4a7a2f",
            "minimal": "#2a2d33",
        }

        risk_score_html = self._render_risk_score_html(risk_score, risk_level_colors)
        manual_review_html = self._render_manual_review_html(risk_score)

        findings_html = ""
        if not self.findings:
            findings_html = "<p class='no-findings'>Aucun finding confirme.</p>"
        else:
            for f in self.findings:
                color = severity_colors.get(f.severity.value, "#555")
                findings_html += f"""
                <div class="finding" style="border-left: 4px solid {color};">
                    <div class="finding-header">
                        <span class="severity" style="background:{color};">{f.severity.value.upper()}</span>
                        <span class="confidence">Confiance : {f.confidence:.0%}</span>
                    </div>
                    <h3>{self._escape(f.title)}</h3>
                    <p class="category">{self._escape(f.owasp_category.value)}</p>
                    <p class="description">{self._escape(f.description)}</p>
                    <table>
                        <tr><td>Endpoint</td><td>{self._escape(f.affected_endpoint)}</td></tr>
                        <tr><td>Detecteur</td><td>{self._escape(f.detector)}</td></tr>
                        <tr><td>Role victime</td><td>{self._escape(f.victim_role)}</td></tr>
                        <tr><td>Role attaquant</td><td>{self._escape(f.attacker_role)}</td></tr>
                        <tr><td>ID de preuve</td><td>{self._escape(f.evidence_test_id or "N/A")}</td></tr>
                        <tr><td>Detecte le</td><td>{self._escape(f.detected_at)}</td></tr>
                    </table>
                </div>
                """

        coverage_html = ""
        if self.coverage:
            rate = self.coverage.success_rate * 100
            failure_rows = "".join(
                f"<tr><td>{self._escape(r['endpoint'])}</td>"
                f"<td>{self._escape(r['role'])}</td>"
                f"<td>{self._escape(r['reason'])}</td></tr>"
                for r in self.coverage.failure_reasons
            )
            coverage_html = f"""
            <section class="coverage-warning">
                <h2>Limite de couverture connue</h2>
                <p>
                    La detection BOLA/BFLA repose sur la creation reelle de ressources
                    de test (fixtures), afin d'eviter de deviner des identifiants non
                    sequentiels (UUID). Cette approche garantit la fiabilite des findings
                    (aucun faux positif du a un identifiant devine), mais implique une
                    <strong>limite structurelle</strong> : un endpoint dont la creation
                    automatique de fixture echoue n'est jamais teste, quelle que soit
                    l'API cible.
                </p>
                <p class="coverage-rate">
                    Taux de reussite de creation de fixtures :
                    <strong>{self.coverage.fixtures_created_successfully} / {self.coverage.total_creation_endpoints_attempted}
                    ({rate:.0f}%)</strong>
                </p>
                <details>
                    <summary>Detail des {self.coverage.creation_failures} echec(s) de creation ({len(self.coverage.failure_reasons)} affiches)</summary>
                    <table class="failures-table">
                        <tr><th>Endpoint</th><th>Role</th><th>Raison</th></tr>
                        {failure_rows}
                    </table>
                </details>
            </section>
            """

        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Rapport API Sentinel - {self._escape(self.target_name)}</title>
<style>
    body {{ font-family: -apple-system, Segoe UI, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #0f1115; color: #e4e4e7; }}
    h1 {{ font-size: 1.8em; border-bottom: 2px solid #333; padding-bottom: 10px; }}
    h2 {{ font-size: 1.3em; margin-top: 30px; }}
    .meta {{ color: #999; font-size: 0.9em; margin-bottom: 30px; }}
    .summary-grid {{ display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }}
    .summary-card {{ background: #1c1f26; border-radius: 8px; padding: 15px 20px; flex: 1; min-width: 140px; }}
    .summary-card .number {{ font-size: 2em; font-weight: bold; }}
    .summary-card .label {{ color: #999; font-size: 0.85em; }}
    .finding {{ background: #1c1f26; border-radius: 6px; padding: 18px 20px; margin: 15px 0; }}
    .finding-header {{ display: flex; gap: 12px; align-items: center; margin-bottom: 8px; }}
    .severity {{ color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
    .confidence {{ color: #aaa; font-size: 0.85em; }}
    .finding h3 {{ margin: 8px 0; }}
    .category {{ color: #8ab4f8; font-size: 0.85em; }}
    .description {{ color: #ccc; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.85em; }}
    table td, table th {{ border-bottom: 1px solid #333; padding: 6px 8px; text-align: left; }}
    table td:first-child {{ color: #999; width: 160px; }}
    .no-findings {{ color: #6a9955; font-style: italic; }}
    .coverage-warning {{ background: #26201c; border-left: 4px solid #a8471f; border-radius: 6px; padding: 18px 20px; margin-top: 40px; }}
    .coverage-rate {{ font-size: 1.1em; }}
    .failures-table th {{ color: #999; }}
    details summary {{ cursor: pointer; color: #8ab4f8; margin-top: 10px; }}
    .risk-score {{ margin: 30px 0; }}
    .overall-score {{ background: #1c1f26; border-radius: 8px; padding: 20px 24px; display: flex; align-items: baseline; gap: 16px; margin-bottom: 12px; }}
    .overall-number {{ font-size: 2.6em; font-weight: bold; }}
    .overall-max {{ font-size: 0.4em; color: #999; }}
    .overall-level {{ font-size: 1.1em; font-weight: bold; letter-spacing: 0.05em; }}
    .category-scores {{ display: flex; flex-direction: column; gap: 8px; }}
    .category-score {{ display: flex; justify-content: space-between; align-items: center; background: #1c1f26; border-radius: 6px; padding: 10px 16px; }}
    .category-name {{ color: #ccc; }}
    .category-badge {{ color: white; padding: 3px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }}
    .manual-review-warning {{ background: #201c26; border-left: 4px solid #6a4fa8; border-radius: 6px; padding: 18px 20px; margin-top: 30px; }}
    .manual-review-table {{ margin-top: 10px; }}
    .manual-review-table th {{ color: #999; }}
</style>
</head>
<body>
    <h1>Rapport de securite API - {self._escape(self.target_name)}</h1>
    <div class="meta">
        Cible : {self._escape(self.target_base_url)}<br>
        Genere le : {self._escape(self.generated_at)}
    </div>

    <div class="summary-grid">
        <div class="summary-card">
            <div class="number">{summary.total_findings}</div>
            <div class="label">Finding(s) confirme(s)</div>
        </div>
        {"".join(f'<div class="summary-card"><div class="number">{count}</div><div class="label">{sev.upper()}</div></div>' for sev, count in summary.findings_by_severity.items())}
    </div>

    {risk_score_html}

    <h2>Findings detailles</h2>
    {findings_html}

    {manual_review_html}

    {coverage_html}
</body>
</html>"""

    def _render_risk_score_html(self, risk_score, risk_level_colors: dict) -> str:
        overall_color = risk_level_colors.get(risk_score.overall_risk_level.value, "#555")
        category_rows = "".join(
            f"""<div class="category-score">
                <span class="category-name">{self._escape(c.category.value)}</span>
                <span class="category-badge" style="background:{risk_level_colors.get(c.risk_level.value, '#555')};">
                    {c.score:.0f}/100 - {c.risk_level.value.upper()} ({c.finding_count} finding(s))
                </span>
            </div>"""
            for c in risk_score.by_category
        )
        if not category_rows:
            category_rows = "<p class='no-findings'>Aucune categorie a risque (aucun finding confirme).</p>"

        return f"""
        <section class="risk-score">
            <h2>Score de risque agrege (OWASP API Top 10)</h2>
            <div class="overall-score" style="border-left: 4px solid {overall_color};">
                <div class="overall-number">{risk_score.overall_score:.0f}<span class="overall-max">/100</span></div>
                <div class="overall-level" style="color:{overall_color};">{risk_score.overall_risk_level.value.upper()}</div>
            </div>
            <div class="category-scores">
                {category_rows}
            </div>
        </section>
        """

    def _render_manual_review_html(self, risk_score) -> str:
        findings = risk_score.findings_requiring_manual_review
        if not findings:
            return ""

        rows = "".join(
            f"<tr><td>{self._escape(f.detector)}</td>"
            f"<td>{self._escape(f.title)}</td>"
            f"<td>{f.confidence:.0%}</td></tr>"
            for f in findings
        )
        return f"""
        <section class="manual-review-warning">
            <h2>Cas ambigus - revue manuelle recommandee (ENF1)</h2>
            <p>
                Ces findings sont confirmes mais avec une confiance faible (&lt; 60%) :
                ni un faux positif assume, ni une preuve suffisamment solide pour etre
                traite comme les autres findings sans verification humaine.
            </p>
            <table class="manual-review-table">
                <tr><th>Detecteur</th><th>Finding</th><th>Confiance</th></tr>
                {rows}
            </table>
        </section>
        """

    @staticmethod
    def _escape(text: str) -> str:
        """Echappement HTML basique pour eviter toute injection dans le rapport."""
        if text is None:
            return ""
        return (
            str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )