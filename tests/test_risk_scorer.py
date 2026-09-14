from api_sentinel.detectors.base_detector import Finding, OwaspCategory, Severity
from api_sentinel.scoring.risk_scorer import RiskLevel, RiskScorer


def _finding(
    detector="bola",
    category=OwaspCategory.BOLA,
    severity=Severity.CRITICAL,
    confidence=0.9,
    title="Test finding",
) -> Finding:
    return Finding(
        detector=detector,
        owasp_category=category,
        severity=severity,
        confidence=confidence,
        title=title,
        description="desc",
        affected_endpoint="GET /test",
        evidence_test_id="bola-00001",
        victim_role="victim",
        attacker_role="attacker_same_level",
    )


def test_no_findings_gives_zero_score():
    result = RiskScorer().score([])
    assert result.overall_score == 0.0
    assert result.overall_risk_level == RiskLevel.MINIMAL
    assert result.by_category == []


def test_single_critical_high_confidence_dominates_score():
    result = RiskScorer().score([_finding(severity=Severity.CRITICAL, confidence=0.99)])
    assert result.overall_score > 80.0
    assert result.overall_risk_level == RiskLevel.CRITICAL


def test_low_severity_low_confidence_stays_low_risk():
    result = RiskScorer().score([_finding(severity=Severity.LOW, confidence=0.3)])
    assert result.overall_score < 15.0
    assert result.overall_risk_level == RiskLevel.MINIMAL


def test_same_severity_confidence_changes_score():
    """Deux findings CRITICAL identiques sauf en confiance ne doivent pas
    produire le meme score - c'est l'objet meme d'EF5."""
    low_conf = RiskScorer().score([_finding(severity=Severity.CRITICAL, confidence=0.4)])
    high_conf = RiskScorer().score([_finding(severity=Severity.CRITICAL, confidence=0.99)])
    assert low_conf.overall_score < high_conf.overall_score


def test_score_never_exceeds_100_with_many_findings():
    many = [_finding(severity=Severity.CRITICAL, confidence=0.99) for _ in range(20)]
    result = RiskScorer().score(many)
    assert result.overall_score <= 100.0


def test_adding_a_finding_never_decreases_score():
    one = RiskScorer().score([_finding(severity=Severity.MEDIUM, confidence=0.7)])
    two = RiskScorer().score(
        [
            _finding(severity=Severity.MEDIUM, confidence=0.7),
            _finding(severity=Severity.LOW, confidence=0.5),
        ]
    )
    assert two.overall_score >= one.overall_score


def test_categories_are_grouped_independently():
    findings = [
        _finding(category=OwaspCategory.BOLA, severity=Severity.CRITICAL, confidence=0.95),
        _finding(category=OwaspCategory.SSRF, severity=Severity.LOW, confidence=0.3),
    ]
    result = RiskScorer().score(findings)
    categories = {c.category for c in result.by_category}
    assert categories == {OwaspCategory.BOLA, OwaspCategory.SSRF}

    bola_score = next(c for c in result.by_category if c.category == OwaspCategory.BOLA)
    ssrf_score = next(c for c in result.by_category if c.category == OwaspCategory.SSRF)
    assert bola_score.score > ssrf_score.score
    assert bola_score.finding_count == 1
    assert ssrf_score.finding_count == 1


def test_category_with_no_findings_is_absent_not_zero():
    """Une categorie non testee ne doit pas apparaitre a 0 - ce serait
    interprete a tort comme 'testee et saine'."""
    result = RiskScorer().score([_finding(category=OwaspCategory.BOLA)])
    categories = {c.category for c in result.by_category}
    assert OwaspCategory.SSRF not in categories


def test_by_category_sorted_by_score_descending():
    findings = [
        _finding(category=OwaspCategory.SSRF, severity=Severity.LOW, confidence=0.3),
        _finding(category=OwaspCategory.BOLA, severity=Severity.CRITICAL, confidence=0.99),
    ]
    result = RiskScorer().score(findings)
    scores = [c.score for c in result.by_category]
    assert scores == sorted(scores, reverse=True)


def test_low_confidence_findings_flagged_for_manual_review():
    low = _finding(confidence=0.4, title="low confidence finding")
    high = _finding(confidence=0.9, title="high confidence finding")
    result = RiskScorer().score([low, high])
    assert result.findings_requiring_manual_review == [low]


def test_to_dict_is_json_serializable_shape():
    result = RiskScorer().score([_finding(confidence=0.4)])
    payload = result.to_dict()
    assert payload["overall_risk_level"] in {level.value for level in RiskLevel}
    assert payload["by_category"][0]["category"] == OwaspCategory.BOLA.value
    assert len(payload["findings_requiring_manual_review"]) == 1
