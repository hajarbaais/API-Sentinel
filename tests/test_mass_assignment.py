"""
Tests unitaires cibles du detecteur mass assignment
(api_sentinel.detectors.mass_assignment) - deux regressions corrigees
suite a une revue de code :
  1. _flatten() perdait silencieusement les scalaires imbriques dans
     une liste JSON (seuls les dicts imbriques etaient recurses).
  2. _field_was_accepted() confirmait une injection sans controle
     negatif (baseline) : un champ dont la valeur par defaut cote
     serveur coincidait deja avec la valeur injectee produisait un
     faux positif.
"""

from api_sentinel.detectors.mass_assignment import MassAssignmentDetector


def _bare_detector() -> MassAssignmentDetector:
    return MassAssignmentDetector.__new__(MassAssignmentDetector)


# --- _flatten : scalaires imbriques dans une liste ---

def test_flatten_keeps_scalars_nested_in_a_list():
    detector = _bare_detector()
    flat = detector._flatten({"roles": ["admin", "user"]})
    assert flat == {"roles[0]": "admin", "roles[1]": "user"}


def test_flatten_mixes_dict_and_scalar_list_items():
    detector = _bare_detector()
    flat = detector._flatten({"items": [{"id": 1}, "raw-scalar"]})
    assert flat == {"items[0].id": 1, "items[1]": "raw-scalar"}


def test_flatten_non_dict_input_returns_empty():
    detector = _bare_detector()
    assert detector._flatten("not a dict") == {}


# --- _field_was_accepted : controle negatif (baseline) ---

def test_field_accepted_when_baseline_differs_from_injected_value():
    detector = _bare_detector()
    data = {"role": "admin"}
    baseline = {"role": "user"}
    assert detector._field_was_accepted(data, baseline, "role", "admin") is True


def test_field_not_accepted_when_baseline_already_matches_injected_value():
    """Regression : un champ dont la valeur naturelle (sans injection)
    egale deja la valeur injectee ne doit jamais etre confirme - ce
    n'est pas une preuve que le serveur a accepte notre champ."""
    detector = _bare_detector()
    data = {"verified": False}
    baseline = {"verified": False}
    assert detector._field_was_accepted(data, baseline, "verified", False) is False


def test_field_not_accepted_when_value_does_not_match_injection():
    detector = _bare_detector()
    data = {"role": "user"}
    baseline = {"role": "user"}
    assert detector._field_was_accepted(data, baseline, "role", "admin") is False


def test_field_accepted_when_baseline_is_empty():
    """Baseline non disponible (echec reseau) : on retombe sur la
    simple comparaison, comme avant l'ajout du controle negatif."""
    detector = _bare_detector()
    data = {"role": "admin"}
    assert detector._field_was_accepted(data, {}, "role", "admin") is True
