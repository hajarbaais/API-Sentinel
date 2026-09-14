import pytest

from api_sentinel.scoring.confidence import ConfidenceLevel, classify, requires_manual_review


def test_classify_high():
    assert classify(0.99) == ConfidenceLevel.HIGH
    assert classify(0.85) == ConfidenceLevel.HIGH


def test_classify_medium():
    assert classify(0.84) == ConfidenceLevel.MEDIUM
    assert classify(0.6) == ConfidenceLevel.MEDIUM


def test_classify_low():
    assert classify(0.59) == ConfidenceLevel.LOW
    assert classify(0.0) == ConfidenceLevel.LOW


def test_classify_out_of_range_raises():
    with pytest.raises(ValueError):
        classify(1.1)
    with pytest.raises(ValueError):
        classify(-0.1)


def test_requires_manual_review_low_confidence():
    assert requires_manual_review(0.4) is True


def test_requires_manual_review_high_confidence():
    assert requires_manual_review(0.9) is False


def test_requires_manual_review_boundary():
    assert requires_manual_review(0.6) is False
    assert requires_manual_review(0.59) is True
