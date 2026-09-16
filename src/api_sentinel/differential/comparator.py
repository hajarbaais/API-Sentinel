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

        if not isinstance(known_victim_data, dict) or not isinstance(attacker_response_data, dict):
            return ComparisonResult(
                is_leak=False,
                confidence=0.3,
                reasoning=(
                    "Reponse non structuree en objet JSON - comparaison "
                    "differentielle impossible, resultat ambigu."
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

        confidence = self._compute_confidence(leaked_fields)

        return ComparisonResult(
            is_leak=True,
            leaked_fields=[name for name, _ in leaked_fields],
            confidence=confidence,
            reasoning=(
                f"{len(leaked_fields)} champ(s) sensible(s) appartenant a la "
                "victime ont ete retrouves, avec la meme valeur, dans la "
                "reponse obtenue par l'attaquant : "
                f"{', '.join(name for name, _ in leaked_fields)}."
            ),
        )

    def _flatten(self, data: dict, parent_key: str = "") -> dict:
        
        flat = {}
        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(value, dict):
                flat.update(self._flatten(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        flat.update(self._flatten(item, f"{full_key}[{i}]"))
                    else:
                        flat[f"{full_key}[{i}]"] = item
            else:
                flat[full_key] = value
        return flat

    def _find_matching_sensitive_fields(
        self, victim_data: dict, attacker_data: dict
    ) -> list[tuple[str, str]]:
       
        flat_victim = self._flatten(victim_data)
        flat_attacker = self._flatten(attacker_data)

        matches = []
        seen_field_names = set()

        for key, victim_value in flat_victim.items():
            if key not in flat_attacker:
                continue
            if flat_attacker[key] != victim_value:
                continue
            if victim_value is None or victim_value == "":
                # Valeur absente/vide : rien a "fuiter". Ne PAS exclure 0
                # ou False ici - ce sont des valeurs sensibles reelles
                # possibles (solde a 0, compte non verifie) et
                # `False in (None, "", 0)` vaut True en Python (False == 0),
                # ce qui masquait a tort ces fuites.
                continue

            field_name = key.split(".")[-1].split("[")[0]

            if field_name in seen_field_names:
               
                continue

            if self.sensitivity_classifier.is_sensitive(field_name):
                category = self.sensitivity_classifier.category_of(field_name)
                matches.append((field_name, category))
                seen_field_names.add(field_name)

        return matches

    def _compute_confidence(self, leaked_fields: list[tuple[str, str]]) -> float:
       
        categories_found = {category for _, category in leaked_fields}

        if "secret" in categories_found:
            return 0.98
        if "financial" in categories_found and "pii" in categories_found:
            return 0.95
        if len(leaked_fields) >= 2:
            return 0.9
        return 0.75