import base64

import pytest
import yaml

from api_sentinel.security.secrets_vault import (
    DecryptionError,
    SecretsVault,
    SecretsVaultError,
    VAULT_KEY_ENV_VAR,
    generate_key,
)


@pytest.fixture
def vault() -> SecretsVault:
    return SecretsVault(key=base64.urlsafe_b64decode(generate_key()))


def test_generate_key_is_32_bytes_once_decoded():
    key = generate_key()
    assert len(base64.urlsafe_b64decode(key)) == 32


def test_encrypt_then_decrypt_roundtrip(vault):
    token = vault.encrypt("TestPassword123!")
    assert token != "TestPassword123!"
    assert vault.decrypt(token) == "TestPassword123!"


def test_encrypted_token_has_recognizable_prefix(vault):
    token = vault.encrypt("secret")
    assert SecretsVault.is_encrypted(token)
    assert not SecretsVault.is_encrypted("plaintext-password")


def test_two_encryptions_of_same_secret_differ(vault):
    """Nonce aleatoire par appel : deux chiffrements du meme secret ne doivent
    jamais produire le meme token (sinon fuite d'information par comparaison)."""
    assert vault.encrypt("same-secret") != vault.encrypt("same-secret")


def test_decrypt_wrong_key_raises(vault):
    other_vault = SecretsVault(key=base64.urlsafe_b64decode(generate_key()))
    token = vault.encrypt("secret")
    with pytest.raises(DecryptionError):
        other_vault.decrypt(token)


def test_decrypt_tampered_token_raises(vault):
    token = vault.encrypt("secret")
    tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
    with pytest.raises(DecryptionError):
        vault.decrypt(tampered)


def test_decrypt_plaintext_value_raises(vault):
    with pytest.raises(DecryptionError):
        vault.decrypt("not-a-vault-token")


def test_rejects_wrong_key_size():
    with pytest.raises(SecretsVaultError):
        SecretsVault(key=b"too-short")


def test_missing_env_var_raises(monkeypatch):
    monkeypatch.delenv(VAULT_KEY_ENV_VAR, raising=False)
    with pytest.raises(SecretsVaultError):
        SecretsVault()


def test_key_loaded_from_env_var(monkeypatch):
    monkeypatch.setenv(VAULT_KEY_ENV_VAR, generate_key())
    v = SecretsVault()
    assert v.decrypt(v.encrypt("hello")) == "hello"


def test_encrypt_accounts_file_replaces_only_passwords(vault, tmp_path):
    plaintext_path = tmp_path / "accounts.yaml"
    plaintext_path.write_text(
        yaml.safe_dump(
            {
                "base_url": "http://localhost:8888",
                "login_endpoint": "/login",
                "accounts": {
                    "victim": {"email": "victim@test.com", "password": "Password123!"},
                },
            }
        ),
        encoding="utf-8",
    )
    encrypted_path = tmp_path / "accounts_encrypted.yaml"

    vault.encrypt_accounts_file(str(plaintext_path), str(encrypted_path))

    written = yaml.safe_load(encrypted_path.read_text(encoding="utf-8"))
    assert written["base_url"] == "http://localhost:8888"
    assert written["accounts"]["victim"]["email"] == "victim@test.com"
    assert SecretsVault.is_encrypted(written["accounts"]["victim"]["password"])
    assert written["accounts"]["victim"]["password"] != "Password123!"


def test_load_accounts_config_decrypts_encrypted_passwords(vault, tmp_path):
    plaintext_path = tmp_path / "accounts.yaml"
    plaintext_path.write_text(
        yaml.safe_dump(
            {
                "base_url": "http://localhost:8888",
                "login_endpoint": "/login",
                "accounts": {
                    "victim": {"email": "victim@test.com", "password": "Password123!"},
                },
            }
        ),
        encoding="utf-8",
    )
    encrypted_path = tmp_path / "accounts_encrypted.yaml"
    vault.encrypt_accounts_file(str(plaintext_path), str(encrypted_path))

    loaded = vault.load_accounts_config(str(encrypted_path))

    assert loaded["accounts"]["victim"]["password"] == "Password123!"


def test_load_accounts_config_leaves_plaintext_passwords_unchanged(vault, tmp_path):
    """Migration progressive : un fichier pas encore chiffre continue de fonctionner."""
    path = tmp_path / "accounts.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "base_url": "http://localhost:8888",
                "login_endpoint": "/login",
                "accounts": {
                    "victim": {"email": "victim@test.com", "password": "StillPlaintext!"},
                },
            }
        ),
        encoding="utf-8",
    )

    loaded = vault.load_accounts_config(str(path))

    assert loaded["accounts"]["victim"]["password"] == "StillPlaintext!"


def test_encrypt_accounts_file_missing_source_raises(vault, tmp_path):
    with pytest.raises(FileNotFoundError):
        vault.encrypt_accounts_file(str(tmp_path / "nope.yaml"), str(tmp_path / "out.yaml"))
