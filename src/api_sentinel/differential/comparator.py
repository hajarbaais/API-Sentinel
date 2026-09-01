
import logging
from dataclasses import dataclass, field

from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.differential.noise_filter import NoiseFilter

logger = logging.getLogger(__name__)


@dataclass
class ComparisonResult:
    is_leak: bool
    leaked_fields: list[str] = field(default_factory=list)
    confidence: float = 0.0         
    reasoning: str = ""             


class DifferentialComparator:
    
    def __init__(
        self,
        sensitivity_classifier: FieldSensitivityClassifier,
        noise_filter: NoiseFilter,
    ):
        self.sensitivity_classifier = sensitivity_classifier
        self.noise_filter = noise_filter

    def compare(
        self,
        known_victim_data: dict,
        attacker_response_data: dict,
        attacker_status_code: int,
    ) -> ComparisonResult:
        """
        Compare les donnees reellement possedees par la victime
        (known_victim_data, issues de la creation de la fixture)
        avec ce que l'attaquant a obtenu en interrogeant cet objet.
        """
        if attacker_status_code in (401, 403, 404):
            return ComparisonResult(
                is_leak=False,
                confidence=1.0,
                reasoning=(
                    f"Acces correctement refuse (code {attacker_status_code}) : "
                    "aucune fuite."
                ),
            )

        if attacker_status_code != 200:
            return ComparisonResult(
                is_leak=False,
                confidence=0.3,
                reasoning=(
                    f"Code HTTP inattendu ({attacker_status_code}), ni un refus "
                    "clair ni un succes standard - resultat ambigu, a verifier "
                    "manuellement."
                ),
            )

        clean_victim = self.noise_filter.strip(known_victim_data)
        clean_attacker = self.noise_filter.strip(attacker_response_data)

        leaked_fields = self._find_matching_sensitive_fields(clean_victim, clean_attacker)

        if not leaked_fields:
            return ComparisonResult(
                is_leak=False,
                confidence=0.5,
                reasoning=(
                    "L'attaquant a recu une reponse 200, mais aucune valeur "
                    "sensible connue de la victime n'a ete retrouvee dans "
                    "cette reponse - probablement pas une fuite, mais a "
                    "verifier si la sensibilite des champs est bien configuree."
                ),
            )

        confidence = self._compute_confidence(leaked_fields, clean_victim)

        return ComparisonResult(
            is_leak=True,
            leaked_fields=[name for name, _ in leaked_fields],
            confidence=confidence,
            reasoning=(
                f"{len(leaked_fields)} champ(s) sensible(s) appartenant a la "
                "victime ont ete retrouves, avec la meme valeur, dans la "
                "reponse obtenue par l'attaquant."
            ),
        )

    def _find_matching_sensitive_fields(
        self, victim_data: dict, attacker_data: dict
    ) -> list[tuple[str, str]]:
        
        matches = []
        for key, victim_value in victim_data.items():
            if key not in attacker_data:
                continue
            if attacker_data[key] != victim_value:
                continue
            if victim_value in (None, "", 0):
               
                continue
            if self.sensitivity_classifier.is_sensitive(key):
                matches.append((key, self.sensitivity_classifier.category_of(key)))
        return matches

    def _compute_confidence(
        self, leaked_fields: list[tuple[str, str]], victim_data: dict
    ) -> float:
        
        categories_found = {category for _, category in leaked_fields}

        if "secret" in categories_found:
            return 0.98
        if "financial" in categories_found and "pii" in categories_found:
            return 0.95
        if len(leaked_fields) >= 2:
            return 0.9
        return 0.75