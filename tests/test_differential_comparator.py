"""
Tests unitaires du comparateur differentiel (api_sentinel.differential.comparator).

C'est la piece qui decide, pour chaque test BOLA, si une reponse
constitue une fuite reelle ou non : elle conditionne directement le
taux de faux positifs revendique dans le memoire (ENF1, ENF6).
"""

import pytest

from api_sentinel.differential.comparator import DifferentialComparator
from api_sentinel.differential.field_sensitivity import FieldSensitivityClassifier
from api_sentinel.differential.noise_filter import NoiseFilter

SENSITIVE_FIELDS_YAML = """
sensitive_fields:
  pii:
    - email
    - nickname
  financial:
    - iban
  secret:
    - password

dynamic_fields:
  - id
  - created_at
"""


@pytest.fixture
def comparator(tmp_path):
    config_path = tmp_path / "sensitive_fields.yaml"
    config_path.write_text(SENSITIVE_FIELDS_YAML, encoding="utf-8")
    sensitivity = FieldSensitivityClassifier(str(config_path))
    noise_filter = NoiseFilter(str(config_path))
    return DifferentialComparator(sensitivity, noise_filter)


# --- Codes HTTP : refus clair vs ambigu ---

@pytest.mark.parametrize("status", [401, 403, 404])
def test_access_denied_is_never_a_leak(comparator, status):
    result = comparator.compare({"email": "victim@test.com"}, {}, status)
    assert result.is_leak is False
    assert result.confidence == 1.0


def test_unexpected_status_is_ambiguous_not_a_leak(comparator):
    result = comparator.compare({"email": "victim@test.com"}, {}, 500)
    assert result.is_leak is False
    assert result.confidence == 0.3


def test_non_dict_attacker_response_is_ambiguous_not_a_leak(comparator):
    result = comparator.compare({"email": "victim@test.com"}, ["unexpected", "list"], 200)
    assert result.is_leak is False
    assert result.confidence == 0.3


def test_non_dict_victim_data_is_ambiguous_not_a_leak(comparator):
    result = comparator.compare(["unexpected"], {"email": "victim@test.com"}, 200)
    assert result.is_leak is False
    assert result.confidence == 0.3


# --- Absence de fuite ---

def test_200_with_no_matching_sensitive_field_is_not_a_leak(comparator):
    victim = {"email": "victim@test.com", "nickname": "vic"}
    attacker = {"email": "attacker@test.com", "nickname": "att"}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is False
    assert result.confidence == 0.5


def test_empty_or_falsy_values_are_never_counted_as_a_leak(comparator):
    victim = {"email": "", "nickname": None}
    attacker = {"email": "", "nickname": None}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is False


def test_zero_value_in_sensitive_field_is_a_leak(comparator):
    """Regression : `False in (None, "", 0)` valait True (False == 0 en
    Python), ce qui faisait ignorer a tort un champ sensible partage a 0."""
    victim = {"iban": 0}
    attacker = {"iban": 0}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is True
    assert "iban" in result.leaked_fields


def test_false_value_in_sensitive_field_is_a_leak(comparator):
    victim = {"iban": False}
    attacker = {"iban": False}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is True
    assert "iban" in result.leaked_fields


def test_non_sensitive_field_collision_is_not_a_leak(comparator):
    # meme id entre victime et attaquant : coincidence normale (compteur
    # sequentiel ou fixture separee), pas une fuite car 'id' n'est pas
    # un champ sensible.
    victim = {"id": 42, "email": "victim@test.com"}
    attacker = {"id": 42, "email": "attacker@test.com"}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is False


# --- Detection de fuite ---

def test_matching_sensitive_field_is_a_leak(comparator):
    victim = {"email": "victim@test.com", "nickname": "vic"}
    attacker = {"email": "victim@test.com", "nickname": "vic"}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is True
    assert set(result.leaked_fields) == {"email", "nickname"}


def test_leak_detected_inside_nested_object(comparator):
    victim = {"profile": {"email": "victim@test.com"}}
    attacker = {"profile": {"email": "victim@test.com"}}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is True
    assert "email" in result.leaked_fields


def test_leak_detected_inside_list_of_objects(comparator):
    victim = {"posts": [{"nickname": "vic"}]}
    attacker = {"posts": [{"nickname": "vic"}]}
    result = comparator.compare(victim, attacker, 200)
    assert result.is_leak is True
    assert "nickname" in result.leaked_fields


def test_same_field_name_at_different_paths_counted_once(comparator):
    victim = {"email": "victim@test.com", "profile": {"email": "victim@test.com"}}
    attacker = {"email": "victim@test.com", "profile": {"email": "victim@test.com"}}
    result = comparator.compare(victim, attacker, 200)
    assert result.leaked_fields.count("email") == 1


# --- Graduation de la confiance ---

def test_confidence_is_maximal_when_a_secret_is_leaked(comparator):
    victim = {"password": "hunter2"}
    attacker = {"password": "hunter2"}
    result = comparator.compare(victim, attacker, 200)
    assert result.confidence == 0.98


def test_confidence_is_high_when_financial_and_pii_both_leak(comparator):
    victim = {"email": "victim@test.com", "iban": "FR7612345678901234567890123"}
    attacker = {"email": "victim@test.com", "iban": "FR7612345678901234567890123"}
    result = comparator.compare(victim, attacker, 200)
    assert result.confidence == 0.95


def test_confidence_is_lower_for_a_single_pii_field(comparator):
    victim = {"email": "victim@test.com"}
    attacker = {"email": "victim@test.com"}
    result = comparator.compare(victim, attacker, 200)
    assert result.confidence == 0.75
