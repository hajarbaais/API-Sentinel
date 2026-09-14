"""
Interpretation du score de confiance par finding (EF5, ENF1).

Chaque detecteur calcule deja sa propre confiance par finding (0.0-1.0)
selon sa propre logique metier (nombre de champs sensibles retrouves
pour BOLA, nombre de signatures de contenu matchees pour SSRF, etc.) -
ce module ne remplace pas ce calcul. Il fournit l'echelle commune
d'interpretation utilisee par le rapport et par le moteur de scoring
agrege (risk_scorer.py), pour que "confiance 0.55" veuille dire la
meme chose partout dans le framework plutot que d'etre relu
detecteur par detecteur.
"""

from enum import Enum


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Seuils centralises : recalibrer ici affecte a la fois le libelle
# affiche dans le rapport et le declenchement de la revue manuelle -
# un seul endroit a changer.
_HIGH_THRESHOLD = 0.85
_MEDIUM_THRESHOLD = 0.6

MANUAL_REVIEW_THRESHOLD = _MEDIUM_THRESHOLD


def classify(confidence: float) -> ConfidenceLevel:
    """Classe une confiance brute (0.0-1.0) en niveau qualitatif."""
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"Confiance hors intervalle [0,1] : {confidence}")
    if confidence >= _HIGH_THRESHOLD:
        return ConfidenceLevel.HIGH
    if confidence >= _MEDIUM_THRESHOLD:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def requires_manual_review(confidence: float) -> bool:
    """
    ENF1 : un finding confirme mais a confiance faible n'est ni un
    faux positif assume ni une preuve solide - c'est un cas AMBIGU
    (cf. cahier des charges section 3 : "score de confiance par
    finding ... pour exposer les cas ambigus") a signaler
    explicitement au lecteur du rapport plutot qu'a noyer parmi les
    findings a haute confiance.
    """
    return classify(confidence) == ConfidenceLevel.LOW
