import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class FieldSensitivityClassifier:

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self._categories: dict[str, set[str]] = {}
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier de configuration des champs sensibles introuvable : "
                f"{self.config_path}"
            )

        content = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        sensitive = content.get("sensitive_fields", {})

        for category, field_names in sensitive.items():
            self._categories[category] = {name.lower() for name in field_names}

        logger.info(
            "Classificateur de sensibilite charge : %d categorie(s), %d champ(s) au total.",
            len(self._categories),
            sum(len(v) for v in self._categories.values()),
        )

    def is_sensitive(self, field_name: str) -> bool:
       
        return self.category_of(field_name) is not None

    def category_of(self, field_name: str) -> str | None:
        
        normalized = field_name.lower()
        for category, field_names in self._categories.items():
            if normalized in field_names:
                return category
        return None