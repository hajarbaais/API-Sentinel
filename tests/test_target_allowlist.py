"""
Tests unitaires du garde-fou de cible autorisee
(api_sentinel.guardrails.target_allowlist).

Ce module est la derniere ligne de defense avant qu'une requete ne
parte vers une cible (ENF2) : un test non autorise doit toujours etre
refuse, jamais laisse passer par defaut.
"""

import pytest

from api_sentinel.guardrails.target_allowlist import (
    TargetAllowlist,
    TargetNotAuthorizedError,
)

ALLOWLIST_YAML = """
authorized_targets:
  - base_url: "http://localhost:8888"
    authorized_by: "Hajar BAAIS"
    note: "crAPI local"
  - base_url: "http://localhost:9000/"
    authorized_by: "Hajar BAAIS"
    authorized_until: "2020-01-01"
"""


@pytest.fixture
def allowlist(tmp_path):
    config_path = tmp_path / "allowlist.yaml"
    config_path.write_text(ALLOWLIST_YAML, encoding="utf-8")
    return TargetAllowlist(str(config_path))


def test_missing_config_file_fails_closed(tmp_path):
    with pytest.raises(FileNotFoundError):
        TargetAllowlist(str(tmp_path / "does_not_exist.yaml"))


def test_empty_allowlist_refuses_everything(tmp_path):
    config_path = tmp_path / "allowlist.yaml"
    config_path.write_text("authorized_targets: []\n", encoding="utf-8")
    allowlist = TargetAllowlist(str(config_path))

    assert allowlist.is_allowed("http://localhost:8888/anything") is False


def test_listed_target_is_allowed(allowlist):
    assert allowlist.is_allowed("http://localhost:8888/identity/api/auth/login") is True


def test_path_is_irrelevant_only_scheme_and_host_port_matter(allowlist):
    assert allowlist.is_allowed("http://localhost:8888/") is True
    assert allowlist.is_allowed("http://localhost:8888/some/deep/path?x=1") is True


def test_unlisted_host_is_refused(allowlist):
    assert allowlist.is_allowed("http://localhost:9999/") is False


def test_different_scheme_is_refused(allowlist):
    assert allowlist.is_allowed("https://localhost:8888/") is False


def test_different_port_is_refused(allowlist):
    assert allowlist.is_allowed("http://localhost:8887/") is False


def test_trailing_slash_in_config_is_normalized(allowlist):
    # entree configuree avec un slash final ("http://localhost:9000/")
    assert allowlist.is_allowed("http://localhost:9000/foo") is False  # expiree, voir test suivant
    with pytest.raises(TargetNotAuthorizedError, match="expiree"):
        allowlist.enforce("http://localhost:9000/foo")


def test_enforce_raises_with_actionable_message(allowlist):
    with pytest.raises(TargetNotAuthorizedError, match="non autorisee"):
        allowlist.enforce("http://production.example.com/")
