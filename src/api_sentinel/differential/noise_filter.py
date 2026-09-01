

import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class NoiseFilter:
   
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.dynamic_fields: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier de configuration introuvable : {self.config_path}"
            )

        content = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        fields = content.get("dynamic_fields", [])
        self.dynamic_fields = {f.lower() for f in fields}

        logger.info(
            "Filtre de bruit charge : %d champ(s) dynamique(s) ignores.",
            len(self.dynamic_fields),
        )

    def strip(self, data: dict) -> dict:
        
        if not isinstance(data, dict):
            return data
        return {
            key: value
            for key, value in data.items()
            if key.lower() not in self.dynamic_fields
        }