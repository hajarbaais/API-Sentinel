
import logging
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class RoleHierarchy:

    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.hierarchy: list[str] = []
        self.role_mapping: dict[str, str] = {}
        self._load()

    def _load(self) -> None:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier de hierarchie de roles introuvable : {self.config_path}"
            )

        content = yaml.safe_load(self.config_path.read_text(encoding="utf-8"))
        self.hierarchy = content.get("role_hierarchy", [])
        self.role_mapping = content.get("role_mapping", {})

        if len(self.hierarchy) < 2:
            logger.warning(
                "Hierarchie de roles trop courte (%d role(s)) - BFLA a "
                "besoin d'au moins 2 niveaux distincts pour etre pertinent.",
                len(self.hierarchy),
            )

    def business_role_of(self, test_role: str) -> str:
        
        if test_role not in self.role_mapping:
            raise ValueError(
                f"Aucun mapping de role trouve pour '{test_role}' dans "
                f"{self.config_path}."
            )
        return self.role_mapping[test_role]

    def is_lower_privilege(self, test_role: str, than_business_role: str) -> bool:
        
        business_role = self.business_role_of(test_role)

        if business_role not in self.hierarchy or than_business_role not in self.hierarchy:
            raise ValueError(
                f"Role inconnu dans la hierarchie : "
                f"'{business_role}' ou '{than_business_role}'."
            )

        return self.hierarchy.index(business_role) > self.hierarchy.index(than_business_role)