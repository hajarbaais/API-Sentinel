"""
Coffre-fort local pour les secrets du framework (ENF5).

Le cahier des charges (ENF5) exige que les identifiants de test et les
jetons captures soient stockes CHIFFRES au repos (AES-256, cle geree
par un coffre-fort/KMS local ou cloud) - jamais en clair dans un
fichier de configuration versionne ni dans un rapport exporte.

Deux problemes concrets, aujourd'hui non couverts ailleurs dans le
framework, motivent ce module :
  1. `config/accounts_crapi.yaml` (et equivalents) contiennent des mots
     de passe de comptes de test EN CLAIR, verses dans le depot Git.
  2. Rien n'empeche qu'un jeton capture en cours d'execution (Account.token)
     finisse par etre serialise tel quel si un futur module decide de
     mettre en cache une session entre deux executions.

Choix de conception :
  - AES-256-GCM (chiffrement authentifie) via `cryptography.hazmat`,
    et non `Fernet` (qui n'utilise que de l'AES-128) : le cahier des
    charges nomme explicitement "AES-256".
  - La cle ne vit JAMAIS dans le code ni dans un fichier versionne.
    Elle est chargee depuis une variable d'environnement
    (`API_SENTINEL_VAULT_KEY`), ce qui correspond au modele
    "coffre-fort/KMS local ou cloud" : en local un simple export, en
    cloud la meme variable est injectee par le KMS/secrets manager du
    provider (AWS Secrets Manager, GCP Secret Manager, etc.) sans que
    ce module n'ait a savoir lequel.
  - Absence de cle = erreur explicite, jamais de repli silencieux sur
    une cle par defaut : un coffre-fort qui echoue "ouvert" n'en est
    pas un.
  - Chaque secret est chiffre avec un nonce distinct (aleatoire, 96
    bits, recommandation GCM) pour ne jamais reutiliser (cle, nonce)
    deux fois - c'est memorise dans le token de sortie, pas besoin de
    le suivre a part.
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

import yaml
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

VAULT_KEY_ENV_VAR = "API_SENTINEL_VAULT_KEY"
_KEY_SIZE_BYTES = 32  # AES-256 : cle de 256 bits.
_NONCE_SIZE_BYTES = 12  # 96 bits, taille recommandee pour AES-GCM.
_TOKEN_PREFIX = "vault:v1:"  # permet de distinguer une valeur chiffree d'une valeur en clair


class SecretsVaultError(Exception):
    """Erreur de configuration ou d'usage du coffre-fort (cle absente, invalide, etc.)."""


class DecryptionError(SecretsVaultError):
    """
    Le dechiffrement a echoue : mauvaise cle, token corrompu, ou token
    altere. AES-GCM etant authentifie, ceci couvre aussi une
    falsification du texte chiffre (pas seulement une cle erronee).
    """


def generate_key() -> str:
    """
    Genere une nouvelle cle AES-256 aleatoire, encodee en base64 -
    a stocker dans le coffre-fort/KMS choisi (ou en variable
    d'environnement locale), jamais dans un fichier versionne.

    N'ecrit rien sur disque : c'est a l'operateur de la stocker dans
    un canal sur (gestionnaire de secrets, coffre-fort local chiffre),
    exactement comme ENF5 l'exige.
    """
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=256)).decode("ascii")


class SecretsVault:
    """
    Chiffre/dechiffre des secrets individuels (mots de passe, jetons)
    avec AES-256-GCM, et fournit des raccourcis pour chiffrer/dechiffrer
    un fichier de comptes de test complet (le cas d'usage principal du
    framework : `config/accounts_*.yaml`).
    """

    def __init__(self, key: bytes | None = None):
        self._key = key if key is not None else self._load_key_from_env()
        if len(self._key) != _KEY_SIZE_BYTES:
            raise SecretsVaultError(
                f"Cle invalide : {len(self._key)} octet(s) fourni(s), "
                f"{_KEY_SIZE_BYTES} attendus pour de l'AES-256. "
                f"Genere une cle valide avec secrets_vault.generate_key()."
            )
        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def _load_key_from_env() -> bytes:
        encoded = os.environ.get(VAULT_KEY_ENV_VAR)
        if not encoded:
            raise SecretsVaultError(
                f"Variable d'environnement '{VAULT_KEY_ENV_VAR}' absente. "
                "Le coffre-fort ne peut pas demarrer sans cle explicite "
                "(ENF5 : jamais de cle par defaut en dur dans le code). "
                "Genere une cle avec `python -m api_sentinel.security.secrets_vault "
                "generate-key` et exporte-la dans cette variable."
            )
        try:
            return base64.urlsafe_b64decode(encoded)
        except Exception as exc:
            raise SecretsVaultError(
                f"Variable d'environnement '{VAULT_KEY_ENV_VAR}' illisible : "
                f"attendu du base64 valide. ({exc})"
            ) from exc

    def encrypt(self, plaintext: str) -> str:
        """
        Chiffre une chaine en clair et retourne un token autonome
        (nonce + texte chiffre + tag d'authentification, encodes en
        base64), prefixe pour etre reconnaissable sans ambiguite.
        """
        nonce = os.urandom(_NONCE_SIZE_BYTES)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
        token = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        return _TOKEN_PREFIX + token

    def decrypt(self, token: str) -> str:
        """Dechiffre un token produit par `encrypt`. Leve DecryptionError si invalide."""
        if not self.is_encrypted(token):
            raise DecryptionError(
                f"Token sans le prefixe attendu '{_TOKEN_PREFIX}' - "
                "ce n'est probablement pas une valeur chiffree par ce coffre-fort."
            )
        raw = token[len(_TOKEN_PREFIX):]
        try:
            decoded = base64.urlsafe_b64decode(raw)
        except Exception as exc:
            raise DecryptionError(f"Token corrompu (base64 invalide) : {exc}") from exc

        if len(decoded) < _NONCE_SIZE_BYTES:
            raise DecryptionError("Token corrompu (trop court pour contenir un nonce).")

        nonce, ciphertext = decoded[:_NONCE_SIZE_BYTES], decoded[_NONCE_SIZE_BYTES:]
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        except InvalidTag as exc:
            raise DecryptionError(
                "Dechiffrement refuse : cle incorrecte ou donnees alterees "
                "(echec de la verification d'integrite AES-GCM)."
            ) from exc
        return plaintext.decode("utf-8")

    @staticmethod
    def is_encrypted(value: str) -> bool:
        """Permet a un appelant de distinguer une valeur deja chiffree d'une valeur en clair."""
        return isinstance(value, str) and value.startswith(_TOKEN_PREFIX)

    # --- Chiffrement d'un fichier de comptes complet ---
    #
    # Cas d'usage principal (ENF5) : les fichiers config/accounts_*.yaml
    # contiennent aujourd'hui des mots de passe en clair, versionnes
    # dans le depot. Ces methodes permettent de ne jamais committer que
    # la version chiffree.

    def encrypt_accounts_file(self, plaintext_path: str, encrypted_path: str) -> None:
        """
        Lit un fichier de comptes en clair (meme format que
        config/accounts_crapi.yaml) et ecrit une copie ou chaque mot
        de passe est remplace par sa version chiffree. La structure
        (roles, emails, base_url) reste lisible - seul le secret est
        protege, ce qui garde le fichier chiffre utile pour le debug
        sans exposer les identifiants.
        """
        source = Path(plaintext_path)
        if not source.exists():
            raise FileNotFoundError(f"Fichier de comptes introuvable : {source}")

        config = yaml.safe_load(source.read_text(encoding="utf-8"))
        for role, credentials in config.get("accounts", {}).items():
            password = credentials.get("password")
            if password is None:
                continue
            if self.is_encrypted(password):
                logger.info("Mot de passe deja chiffre pour le role '%s', inchange.", role)
                continue
            credentials["password"] = self.encrypt(password)

        destination = Path(encrypted_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )
        logger.info("Fichier de comptes chiffre ecrit : %s", destination)

    def load_accounts_config(self, path: str) -> dict:
        """
        Charge un fichier de comptes et dechiffre a la volee tout mot
        de passe chiffre par ce coffre-fort - un mot de passe deja en
        clair (fichier non encore migre) est laisse tel quel, pour une
        transition progressive sans casser les configurations
        existantes.
        """
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Fichier de comptes introuvable : {config_path}")

        config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
        for role, credentials in config.get("accounts", {}).items():
            password = credentials.get("password")
            if password is not None and self.is_encrypted(password):
                credentials["password"] = self.decrypt(password)
        return config


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2 or sys.argv[1] not in {"generate-key", "encrypt-file"}:
        print(
            "Usage :\n"
            "  python -m api_sentinel.security.secrets_vault generate-key\n"
            "  python -m api_sentinel.security.secrets_vault encrypt-file "
            "<accounts_clair.yaml> <accounts_chiffre.yaml>\n"
            f"      (necessite la variable d'environnement {VAULT_KEY_ENV_VAR})"
        )
        sys.exit(1)

    if sys.argv[1] == "generate-key":
        key = generate_key()
        print(f"Nouvelle cle AES-256 (a stocker hors du depot, ex. {VAULT_KEY_ENV_VAR}) :")
        print(key)
        sys.exit(0)

    if len(sys.argv) != 4:
        print("encrypt-file necessite : <accounts_clair.yaml> <accounts_chiffre.yaml>")
        sys.exit(1)

    vault = SecretsVault()
    vault.encrypt_accounts_file(sys.argv[2], sys.argv[3])
