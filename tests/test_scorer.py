import pytest
from argus.core.scorer import calculate_score, determine_risk_level, generate_report
from argus.models import AnomalyFlag, Severity, AttackCategory

def test_scorer_math_accumulation():
    # 1 Critical (+40), 1 High (+25) -> Total 65
    flags = [
        AnomalyFlag(severity=Severity.CRITICAL, category=AttackCategory.SQLI, description=""),
        AnomalyFlag(severity=Severity.HIGH, category=AttackCategory.XSS, description="")
    ]
    score = calculate_score(flags)
    assert score == 65
    assert determine_risk_level(score) == "MEDIUM"

def test_scorer_math_capping():
    # 3 Critical (+120) -> Should cap at 100
    flags = [
        AnomalyFlag(severity=Severity.CRITICAL, category=AttackCategory.BOLA, description=""),
        AnomalyFlag(severity=Severity.CRITICAL, category=AttackCategory.SQLI, description=""),
        AnomalyFlag(severity=Severity.CRITICAL, category=AttackCategory.AUTH_BYPASS, description="")
    ]
    score = calculate_score(flags)
    assert score == 100
    assert determine_risk_level(score) == "CRITICAL"

def test_scorer_secure_level():
    # 0 flags -> Score 0 -> SECURE
    flags = []
    score = calculate_score(flags)
    assert score == 0
    assert determine_risk_level(score) == "SECURE"

def test_report_generation():
    flags = [
        AnomalyFlag(severity=Severity.HIGH, category=AttackCategory.XSS, description="")
    ]
    report, risk_level = generate_report(
        target_url="http://test.com",
        total_payloads=10,
        flags=flags
    )
    assert report.overall_risk_score == 25
    assert risk_level == "LOW"
    assert len(report.anomalies_found) == 1
    assert report.payloads_sent == 10
