"""
Tests unitaires de la logique de decision du detecteur de rate
limiting (api_sentinel.detectors.rate_limiting).

Seule la fonction pure is_missing_rate_limit est testee ici : le reste
du detecteur emet de vraies requetes HTTP en rafale, ce qui n'a pas sa
place dans des tests unitaires.
"""

from api_sentinel.detectors.rate_limiting import is_missing_rate_limit


def test_no_429_among_complete_sample_is_missing_rate_limit():
    assert is_missing_rate_limit([200] * 20, expected_count=20) is True


def test_a_single_429_is_enough_to_disprove_missing_rate_limit():
    statuses = [200] * 15 + [429] * 5
    assert is_missing_rate_limit(statuses, expected_count=20) is False


def test_incomplete_sample_due_to_network_error_is_not_conclusive():
    # Le test s'est arrete en cours de route (erreur reseau) : on ne
    # peut rien conclure, ni positif ni negatif.
    statuses = [200] * 7
    assert is_missing_rate_limit(statuses, expected_count=20) is False


def test_empty_sample_is_not_conclusive():
    assert is_missing_rate_limit([], expected_count=20) is False


def test_all_429_is_not_missing_rate_limit():
    assert is_missing_rate_limit([429] * 20, expected_count=20) is False
