"""
Garde-fou de cible autorisee (ENF2 - non-destructivite).

Avant d'envoyer la moindre requete a une cible, le framework doit
s'assurer que cette cible a ete explicitement autorisee. Sans ce
garde-fou, une simple erreur de configuration (accounts.yaml pointant
par erreur vers une cible hors perimetre) declencherait des tests
actifs (creation de fixtures, mass assignment, et a terme SSRF)
contre un systeme non autorise - exactement le risque identifie dans
le cahier des charges (section 10 : "Test de charge/complexite
impactant une cible reelle").

Principe : liste blanche stricte. Une cible absente de l'allowlist
est refusee, pas seulement signalee.
"""

import logging
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urlparse

import yaml

logger = logging.getLogger(__name__)

DEFAULT_ALLOWLIST_PATH = "config/allowlist.yaml"


class TargetNotAuthorizedError(Exception):
    """Levee quand une cible n'est pas (ou plus) explicitement autorisee."""


@dataclass
class AllowedTarget:
    base_url: str
    authorized_by: str
    note: str = ""
    authorized_until: date | None = None

    def covers(self, target: "_ParsedTarget") -> bool:
        entry = urlparse(self.base_url)
        return entry.scheme == target.scheme and entry.netloc == target.netloc

    def is_expired(self) -> bool:
        if self.authorized_until is None:
            return False
        return date.today() > self.authorized_until


class _ParsedTarget:
    """Wrapper leger pour ne parser l'URL testee qu'une seule fois."""

    def __init__(self, url: str):
        parsed = urlparse(url)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc

    def __str__(self) -> str:
        return f"{self.scheme}://{self.netloc}"


class TargetAllowlist:
    """
    Charge la liste des cibles explicitement autorisees (schema + hote
    + port) et verifie qu'une URL donnee y correspond avant d'autoriser
    le framework a lui envoyer la moindre requete.
    """

    def __init__(self, config_path: str = DEFAULT_ALLOWLIST_PATH):
        self.config_path = Path(config_path)
        self.targets: list[AllowedTarget] = self._load()

    def _load(self) -> list[AllowedTarget]:
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier d'allowlist introuvable : {self.config_path}. "
                "Conformement a ENF2, aucune cible ne peut etre testee sans "
                "autorisation explicite - cree ce fichier et declare-y la "
                "cible avant de lancer un scan (voir "
                "config/allowlist.yaml pour le format attendu)."
            )

        content = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        raw_targets = content.get("authorized_targets", [])

        if not raw_targets:
            logger.warning(
                "Allowlist chargee mais vide (%s) - aucune cible ne sera "
                "autorisee tant qu'aucune entree n'y est ajoutee.",
                self.config_path,
            )

        targets = [self._parse_entry(entry) for entry in raw_targets]

        logger.info(
            "Allowlist chargee : %d cible(s) autorisee(s) depuis %s.",
            len(targets), self.config_path,
        )
        return targets

    def _parse_entry(self, entry: dict) -> AllowedTarget:
        return AllowedTarget(
            base_url=entry["base_url"].rstrip("/"),
            authorized_by=entry.get("authorized_by", "inconnu"),
            note=entry.get("note", ""),
            authorized_until=self._parse_date(entry.get("authorized_until")),
        )

    @staticmethod
    def _parse_date(value) -> date | None:
        if value is None:
            return None
        if isinstance(value, date):
            return value
        return datetime.strptime(str(value), "%Y-%m-%d").date()

    def is_allowed(self, url: str) -> bool:
        """True si `url` correspond a une cible autorisee et non expiree."""
        try:
            self.enforce(url)
            return True
        except TargetNotAuthorizedError:
            return False

    def enforce(self, url: str) -> None:
        """
        Leve TargetNotAuthorizedError si `url` ne correspond a aucune
        cible autorisee, ou si toutes les autorisations correspondantes
        ont expire.
        """
        target = _ParsedTarget(url)
        matching = [t for t in self.targets if t.covers(target)]

        if not matching:
            raise TargetNotAuthorizedError(
                f"Cible non autorisee : '{target}'. Ajoute-la explicitement "
                f"a {self.config_path} avant de la tester "
                "(ENF2 - autorisation ecrite obligatoire)."
            )

        still_valid = [t for t in matching if not t.is_expired()]
        if not still_valid:
            expired = matching[0]
            raise TargetNotAuthorizedError(
                f"Autorisation expiree pour '{target}' (valable jusqu'au "
                f"{expired.authorized_until}, autorisee par "
                f"{expired.authorized_by}). Renouvelle l'autorisation dans "
                f"{self.config_path}."
            )

        logger.debug("Cible autorisee : %s", target)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage : python target_allowlist.py <url> [allowlist.yaml]")
        sys.exit(1)

    allowlist_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_ALLOWLIST_PATH
    allowlist = TargetAllowlist(allowlist_path)

    try:
        allowlist.enforce(sys.argv[1])
        print(f"AUTORISE : {sys.argv[1]}")
    except TargetNotAuthorizedError as exc:
        print(f"REFUSE : {exc}")
        sys.exit(1)
