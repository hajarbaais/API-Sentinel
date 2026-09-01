
import logging

import requests
import yaml
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Account:
    
    role: str             
    email: str
    token: str              
    base_url: str
    verified_business_role: str | None = None  
    def auth_headers(self) -> dict:
       
        return {"Authorization": f"Bearer {self.token}"}

    def __repr__(self):
        return f"Account(role={self.role}, email={self.email})"


class SessionManager:
   
    def __init__(self, config_path: str):
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self.base_url = self.config["base_url"]
        self.login_endpoint = self.config["login_endpoint"]
        self.profile_endpoint = self.config.get("profile_endpoint")
        self.accounts: dict[str, Account] = {}

    def _load_config(self) -> dict:
        
        if not self.config_path.exists():
            raise FileNotFoundError(
                f"Fichier de configuration introuvable : {self.config_path}"
            )

        content = self.config_path.read_text(encoding="utf-8")
        return yaml.safe_load(content)

    def authenticate_all(self) -> dict[str, Account]:
      
        accounts_config = self.config.get("accounts", {})

        if len(accounts_config) < 3:
            raise ValueError(
                "Au moins 3 comptes sont requis (victim, attacker_same_level, "
                "attacker_lower_level) conformement au cahier des charges (EF2)."
            )

        for role, credentials in accounts_config.items():
            account = self._authenticate_one(role, credentials)
            self.accounts[role] = account

        return self.accounts

    def _authenticate_one(self, role: str, credentials: dict) -> Account:
        
        url = f"{self.base_url}{self.login_endpoint}"
        payload = {
            "email": credentials["email"],
            "password": credentials["password"],
        }

        response = requests.post(url, json=payload, timeout=10)

        if response.status_code != 200:
            raise ConnectionError(
                f"Echec d'authentification pour le role '{role}' "
                f"(email: {credentials['email']}). "
                f"Code HTTP recu : {response.status_code}"
            )

        data = response.json()
        token = self._extract_token(data)

        account = Account(
            role=role,
            email=credentials["email"],
            token=token,
            base_url=self.base_url,
        )

        expected_role = credentials.get("expected_role")
        if expected_role:
            self._verify_business_role(account, expected_role)

        return account

    def _extract_token(self, response_data: dict) -> str:
        
        for field_name in ["token", "access_token", "jwt", "accessToken"]:
            if field_name in response_data:
                return response_data[field_name]

        raise KeyError(
            "Impossible de trouver le token dans la reponse de login. "
            f"Champs disponibles : {list(response_data.keys())}. "
            "Adapte _extract_token() au format de l'API cible."
        )

    def _verify_business_role(self, account: Account, expected_role: str) -> None:
        
        if not self.profile_endpoint:
            logger.warning(
                "Aucun profile_endpoint configure - impossible de verifier "
                "le role reel du compte '%s'. Le role declare ('%s') est "
                "suppose correct sans verification.",
                account.role, expected_role,
            )
            return

        url = f"{self.base_url}{self.profile_endpoint}"

        try:
            response = requests.get(url, headers=account.auth_headers(), timeout=10)
        except requests.RequestException as exc:
            logger.warning(
                "Impossible de verifier le role reel du compte '%s' "
                "(erreur reseau : %s).", account.role, exc,
            )
            return

        if response.status_code != 200:
            logger.warning(
                "Impossible de verifier le role reel du compte '%s' "
                "(code %s sur %s).", account.role, response.status_code, url,
            )
            return

        try:
            real_role = response.json().get("role")
        except ValueError:
            logger.warning(
                "Reponse non-JSON recue sur %s, verification de role "
                "impossible pour le compte '%s'.", url, account.role,
            )
            return

        if real_role != expected_role:
            logger.error(
                "INCOHERENCE DE ROLE : le compte '%s' a un role reel "
                "'%s' cote API, different du role attendu '%s' declare "
                "en configuration. Les tests BFLA lies a ce compte "
                "seront non fiables tant que ce n'est pas corrige.",
                account.role, real_role, expected_role,
            )
        else:
            logger.info(
                "Role verifie pour le compte '%s' : '%s' confirme cote API.",
                account.role, real_role,
            )

        account.verified_business_role = real_role

    def get_account(self, role: str) -> Account:
       
        if role not in self.accounts:
            raise ValueError(
                f"Role inconnu ou non authentifie : '{role}'. "
                f"Roles disponibles : {list(self.accounts.keys())}"
            )
        return self.accounts[role]


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    if len(sys.argv) < 2:
        print("Usage : python session_manager.py chemin/vers/accounts.yaml")
        sys.exit(1)

    manager = SessionManager(sys.argv[1])
    accounts = manager.authenticate_all()

    print(f"\n{len(accounts)} compte(s) authentifie(s) :\n")
    for role, account in accounts.items():
        verified = account.verified_business_role or "non verifie"
        print(f"  {role} -> {account.email} (role reel: {verified})")