"""
Test cible du CLI (api_sentinel.cli) - regression corrigee suite a une
revue de code : contrairement a BFLA/mass assignment/SSRF (desactivables
et proteges par un try/except FileNotFoundError), le detecteur BOLA
n'a pas de flag --skip-bola. Un --sensitive-fields manquant ou mal
orthographie plantait donc en plein milieu du scan avec une trace peu
lisible, apres avoir deja authentifie les comptes et cree des fixtures.
Le garde-fou verifie desormais ce fichier AVANT tout effet de bord.
"""

import pytest

from api_sentinel.cli import build_parser, run_scan


def test_missing_sensitive_fields_file_fails_fast_before_any_network_call(tmp_path):
    args = build_parser().parse_args([
        "--spec", str(tmp_path / "does-not-exist-spec.json"),
        "--accounts", str(tmp_path / "does-not-exist-accounts.yaml"),
        "--sensitive-fields", str(tmp_path / "does-not-exist-sensitive-fields.yaml"),
    ])

    with pytest.raises(FileNotFoundError, match="sensibles"):
        run_scan(args)
