"""
Tests unitaires cibles du gestionnaire de comptes
(api_sentinel.accounts.session_manager) - deux regressions corrigees
suite a une revue de code :
  1. _extract_token acceptait un token null/vide (verifiait seulement
     la presence de la cle, pas sa valeur).
  2. Une incoherence de role reel vs attendu n'etait que journalisee,
     jamais bloquante - un compte mal etiquete rendait les tests
     BOLA/BFLA lies a ce compte non fiables sans aucun signal fort.

Aucune authentification reelle n'est effectuee : les methodes testees
sont appelees directement sur une instance construite sans passer par
__init__ (meme pattern que test_ssrf_cloud.py), pour ne pas dependre
d'un fichier de config ni d'une cible reseau.
"""

from types import SimpleNamespace

import pytest
import requests

from api_sentinel.accounts.session_manager import (
    Account,
    RoleVerificationError,
    SessionManager,
)


def _bare_manager() -> SessionManager:
    manager = SessionManager.__new__(SessionManager)
    manager.base_url = "http://localhost:8888"
    manager.profile_endpoint = "/auth/me"
    return manager


# --- _extract_token ---

def test_extract_token_from_standard_field():
    manager = _bare_manager()
    assert manager._extract_token({"token": "abc123"}) == "abc123"


def test_extract_token_tries_alternate_field_names():
    manager = _bare_manager()
    assert manager._extract_token({"access_token": "xyz"}) == "xyz"


def test_extract_token_rejects_null_value():
    """Regression : `if field_name in response_data` acceptait
    `{"token": null}` et renvoyait None comme jeton valide."""
    manager = _bare_manager()
    with pytest.raises(KeyError):
        manager._extract_token({"token": None})


def test_extract_token_rejects_empty_string():
    manager = _bare_manager()
    with pytest.raises(KeyError):
        manager._extract_token({"token": ""})


def test_extract_token_falls_through_falsy_field_to_a_valid_one():
    manager = _bare_manager()
    assert manager._extract_token({"token": "", "access_token": "real-token"}) == "real-token"


def test_extract_token_raises_when_nothing_usable():
    manager = _bare_manager()
    with pytest.raises(KeyError):
        manager._extract_token({"unrelated_field": "value"})


# --- _verify_business_role ---

def test_role_mismatch_raises(monkeypatch):
    manager = _bare_manager()
    account = Account(role="attacker_lower_level", email="a@test.com", token="t", base_url=manager.base_url)

    monkeypatch.setattr(
        requests, "get",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"role": "admin"}),
    )

    with pytest.raises(RoleVerificationError):
        manager._verify_business_role(account, expected_role="guest")


def test_role_match_does_not_raise_and_sets_verified_role(monkeypatch):
    manager = _bare_manager()
    account = Account(role="victim", email="v@test.com", token="t", base_url=manager.base_url)

    monkeypatch.setattr(
        requests, "get",
        lambda *a, **k: SimpleNamespace(status_code=200, json=lambda: {"role": "admin"}),
    )

    manager._verify_business_role(account, expected_role="admin")
    assert account.verified_business_role == "admin"


def test_no_profile_endpoint_does_not_raise():
    manager = _bare_manager()
    manager.profile_endpoint = None
    account = Account(role="victim", email="v@test.com", token="t", base_url=manager.base_url)

    # Ne doit pas lever, meme si le role declare est potentiellement faux -
    # documente comme limite (log warning), pas une erreur bloquante,
    # faute de moyen de verifier.
    manager._verify_business_role(account, expected_role="admin")
    assert account.verified_business_role is None
