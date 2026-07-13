# ponytail: removed RiskScorer class wrapper in favor of pure module functions
from typing import List, Tuple
from argus.models import AnomalyFlag, Severity, ScanReport

WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 25,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
}

def calculate_score(flags: List[AnomalyFlag]) -> int:
    """Calculates cumulative risk score capped at 100."""
    return min(sum(WEIGHTS[flag.severity] for flag in flags), 100)

def determine_risk_level(score: int) -> str:
    """Maps score to categorical risk level."""
    if score >= 90:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "SECURE"

def generate_report(target_url: str, total_payloads: int, flags: List[AnomalyFlag]) -> Tuple[ScanReport, str]:
    """Takes raw flags and builds the final structured ScanReport and risk level."""
    score = calculate_score(flags)
    risk_level = determine_risk_level(score)
    recommendations = list({f"Review {f.category.value} vulnerabilities and sanitize inputs." for f in flags})
    
    report = ScanReport(
        endpoint=target_url,
        payloads_sent=total_payloads,
        anomalies_found=flags,
        overall_risk_score=score,
        recommendations=recommendations,
    )
    return report, risk_level
