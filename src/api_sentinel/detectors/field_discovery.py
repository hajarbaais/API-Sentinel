"""
Decouverte dynamique de champs suspects : plutot que de deviner a
l'avance des noms de champs (role, isAdmin...) qui ne correspondent
pas forcement au vocabulaire de l'API testee, ce module observe les
vraies reponses deja collectees (fixtures) et en extrait les champs
dont le NOM correspond a un mot-cle suspect (credit, balance, role...).

Le nom exact du champ ainsi que son type/valeur observee sont utilises
pour construire un candidat d'injection realiste, plutot qu'une valeur
fixe arbitraire. Approche "real world" : le detecteur s'adapte au
vocabulaire propre a chaque cible, au lieu de se limiter a une liste
statique de noms de champs generiques.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from api_sentinel.fixtures.fixture_manager import Fixture

logger = logging.getLogger(__name__)


@dataclass
class InjectionCandidate:
    """
    Un champ suspect reellement observe dans une reponse de l'API,
    avec une valeur d'injection construite en fonction de son type
    d'origine.
    """
    field_name: str             # nom exact observe (ex: "available_credit")
    original_value: Any         # valeur vue a l'origine (ex: 100.0)
    injected_value: Any         # valeur a tenter d'injecter (ex: 999999)
    source_endpoint: str        # endpoint ou ce champ a ete observe


class FieldDiscovery:
    """
    Parcourt les fixtures deja creees pour identifier des champs
    suspects reellement presents dans les reponses de l'API, et
    construit des candidats d'injection adaptes.
    """

    def __init__(self, keywords_config: str):
        self.keywords = self._load_keywords(keywords_config)

    def _load_keywords(self, config_path: str) -> list[str]:
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(
                f"Fichier de mots-cles suspects introuvable : {path}"
            )
        content = yaml.safe_load(path.read_text(encoding="utf-8"))
        return [k.lower() for k in content.get("suspect_keywords", [])]

    def discover_from_fixtures(self, fixtures: list[Fixture]) -> list[InjectionCandidate]:
        """
        Parcourt toutes les fixtures et retourne un candidat unique
        par (endpoint, nom de champ) - evite de tester deux fois le
        meme champ observe dans plusieurs fixtures du meme endpoint.
        """
        seen: set[tuple[str, str]] = set()
        candidates: list[InjectionCandidate] = []

        for fixture in fixtures:
            flat = self._flatten(fixture.raw_response)
            for key, value in flat.items():
                field_name = key.split(".")[-1].split("[")[0]

                if not self._is_suspect(field_name):
                    continue

                dedup_key = (fixture.resource_type, field_name)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                injected_value = self._build_injected_value(value)
                if injected_value is None:
                    continue

                candidates.append(InjectionCandidate(
                    field_name=field_name,
                    original_value=value,
                    injected_value=injected_value,
                    source_endpoint=fixture.resource_type,
                ))

        logger.info(
            "Decouverte dynamique de champs : %d candidat(s) suspect(s) "
            "trouve(s) dans les reponses reelles de l'API (%s).",
            len(candidates),
            ", ".join(f"{c.field_name}@{c.source_endpoint}" for c in candidates) or "aucun",
        )
        return candidates

    def _is_suspect(self, field_name: str) -> bool:
        """
        Verifie si le nom de champ contient un des mots-cles suspects
        configures (correspondance partielle, ex: "available_credit"
        contient "credit").
        """
        normalized = field_name.lower()
        return any(keyword in normalized for keyword in self.keywords)

    def _build_injected_value(self, original_value: Any) -> Any:
        """
        Construit une valeur d'injection plausible en fonction du
        TYPE de la valeur reellement observee - plus realiste qu'une
        valeur fixe arbitraire qui pourrait ne pas correspondre au
        type attendu par le serveur (ce qui provoquerait un rejet
        pour une mauvaise raison, faussant le test).
        """
        if isinstance(original_value, bool):
            return not original_value
        if isinstance(original_value, (int, float)):
            # Une valeur nettement superieure a l'original, pour
            # detecter une elevation de privilege/credit/quota.
            return original_value + 999999 if original_value >= 0 else 999999
        if isinstance(original_value, str):
            # Pour les champs textuels (role, status...), une valeur
            # "elevee" plausible generique. Le nom du champ specifique
            # (ex: "role") pourrait beneficier de valeurs ciblees,
            # mais celle-ci reste un signal exploitable : une valeur
            # qui change bien la donnee d'origine.
            return "admin"
        return None

    def _flatten(self, data: dict, parent_key: str = "") -> dict:
        flat = {}
        if not isinstance(data, dict):
            return flat
        for key, value in data.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            if isinstance(value, dict):
                flat.update(self._flatten(value, full_key))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        flat.update(self._flatten(item, f"{full_key}[{i}]"))
            else:
                flat[full_key] = value
        return flat