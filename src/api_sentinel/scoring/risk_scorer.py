"""
Moteur de scoring de risque agrege, mappe sur l'OWASP API Security
Top 10 (cahier des charges section 3 : "Moteur de scoring de risque
agrege, mappe sur l'OWASP API Security Top 10, avec un score de
confiance par finding (et non un simple binaire pass/fail) pour
exposer les cas ambigus").

Principe : transformer une liste de findings individuels (chacun deja
porteur d'une severite ET d'une confiance, cf. Finding) en :
  - un score de risque par categorie OWASP (0-100) ;
  - un score de risque global pour la cible (0-100) ;
  - un niveau de risque qualitatif (CRITICAL/HIGH/MEDIUM/LOW/MINIMAL) ;
  - la liste des findings a confiance faible, isoles comme cas
    ambigus necessitant une revue manuelle (ENF1, confidence.py).

Agregation : PAS une simple somme des poids de severite (qui
depasserait trivialement 100 des que plusieurs findings CRITICAL
existent, et qui traiterait un finding a confiance 0.4 exactement
comme un a confiance 0.99). A la place, chaque finding contribue un
"poids de risque" = poids_de_severite * confiance, et les findings
d'une meme categorie sont combines par risque complementaire
(traites comme des sources de risque independantes) :

    score = 1 - PRODUIT(1 - poids_i)

Cela donne : jamais de depassement de l'echelle 0-100 ; un deuxieme
finding de meme severite augmente toujours le score mais avec des
rendements decroissants ; un seul finding CRITICAL a haute confiance
suffit a lui seul a approcher le score maximal, conforme a l'intuition
qu'une seule faille grave rend deja la categorie a risque.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from math import prod

from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.scoring.confidence import requires_manual_review

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


# Poids de severite dans [0,1] : la contribution au risque d'un
# finding de cette severite, seul et a confiance maximale (1.0).
# Deliberement conservateur pour LOW/INFO (jamais suffisants seuls
# pour approcher un score CRITICAL) et agressif pour CRITICAL (un
# seul finding CRITICAL a haute confiance doit dominer le score).
_SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 0.95,
    Severity.HIGH: 0.75,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.25,
    Severity.INFO: 0.05,
}

# Seuils de classification du score agrege (0-100) en niveau de
# risque qualitatif affiche dans le rapport, du plus eleve au plus bas.
_RISK_LEVEL_THRESHOLDS: list[tuple[float, RiskLevel]] = [
    (80.0, RiskLevel.CRITICAL),
    (60.0, RiskLevel.HIGH),
    (35.0, RiskLevel.MEDIUM),
    (15.0, RiskLevel.LOW),
]


def _finding_weight(finding: Finding) -> float:
    """Poids de risque individuel : severite ponderee par la propre
    confiance du finding - un CRITICAL a confiance 0.4 pese moins
    qu'un CRITICAL a confiance 0.99. C'est l'usage concret du score de
    confiance par finding exige par EF5, au-dela du simple affichage."""
    return _SEVERITY_WEIGHTS[finding.severity] * finding.confidence


def _aggregate_score_0_100(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    complement = prod(1.0 - _finding_weight(f) for f in findings)
    return round((1.0 - complement) * 100, 1)


def _classify_score(score_0_100: float) -> RiskLevel:
    for threshold, level in _RISK_LEVEL_THRESHOLDS:
        if score_0_100 >= threshold:
            return level
    return RiskLevel.MINIMAL


@dataclass
class CategoryRiskScore:
    category: OwaspCategory
    score: float
    risk_level: RiskLevel
    finding_count: int

    def to_dict(self) -> dict:
        return {
            "category": self.category.value,
            "score": self.score,
            "risk_level": self.risk_level.value,
            "finding_count": self.finding_count,
        }


@dataclass
class RiskScore:
    overall_score: float
    overall_risk_level: RiskLevel
    by_category: list[CategoryRiskScore] = field(default_factory=list)
    findings_requiring_manual_review: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "overall_score": self.overall_score,
            "overall_risk_level": self.overall_risk_level.value,
            "by_category": [c.to_dict() for c in self.by_category],
            "findings_requiring_manual_review": [
                {
                    "detector": f.detector,
                    "title": f.title,
                    "confidence": f.confidence,
                    "evidence_test_id": f.evidence_test_id,
                }
                for f in self.findings_requiring_manual_review
            ],
        }


class RiskScorer:
    """
    Point d'entree unique : `score(findings)` transforme une liste de
    findings confirmes en un RiskScore agrege, mappe OWASP API Top 10.

    Ne fait aucune hypothese sur quels detecteurs ont tourne : une
    categorie sans finding n'apparait simplement pas dans
    `by_category` plutot que d'etre affichee a 0 - un score de 0
    laisserait croire a tort que la categorie a ete testee et jugee
    saine, alors qu'elle n'a peut-etre pas ete testee du tout.
    """

    def score(self, findings: list[Finding]) -> RiskScore:
        by_category: dict[OwaspCategory, list[Finding]] = {}
        for finding in findings:
            by_category.setdefault(finding.owasp_category, []).append(finding)

        category_scores = []
        for category, cat_findings in by_category.items():
            cat_score = _aggregate_score_0_100(cat_findings)
            category_scores.append(
                CategoryRiskScore(
                    category=category,
                    score=cat_score,
                    risk_level=_classify_score(cat_score),
                    finding_count=len(cat_findings),
                )
            )
        category_scores.sort(key=lambda c: c.score, reverse=True)

        overall_score = _aggregate_score_0_100(findings)
        manual_review = [f for f in findings if requires_manual_review(f.confidence)]

        result = RiskScore(
            overall_score=overall_score,
            overall_risk_level=_classify_score(overall_score),
            by_category=category_scores,
            findings_requiring_manual_review=manual_review,
        )
        logger.info(
            "Score de risque calcule : %.1f/100 (%s), %d categorie(s), "
            "%d finding(s) a revue manuelle.",
            result.overall_score, result.overall_risk_level.value,
            len(category_scores), len(manual_review),
        )
        return result
