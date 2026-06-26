from typing import List, Dict, Any
from argus.models import AnomalyFlag, Severity, ScanReport

class RiskScorer:
    """Calculates risk scores based on heuristic anomaly flags."""
    
    # SSOT Scoring weights
    WEIGHTS = {
        Severity.CRITICAL: 40,
        Severity.HIGH: 25,
        Severity.MEDIUM: 10,
        Severity.LOW: 5
    }

    @classmethod
    def calculate_score(cls, flags: List[AnomalyFlag]) -> int:
        """Calculates a cumulative risk score, capped at 100."""
        score = sum(cls.WEIGHTS[flag.severity] for flag in flags)
        return min(score, 100)
        
    @classmethod
    def determine_risk_level(cls, score: int) -> str:
        """Maps an integer score to a categorical risk level."""
        if score >= 90:
            return "CRITICAL"
        elif score >= 70:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "SECURE"
            
    @classmethod
    def generate_report(cls, target_url: str, total_payloads: int, flags: List[AnomalyFlag]):
        """Takes raw flags and builds the final structured ScanReport."""
        score = cls.calculate_score(flags)
        risk_level = cls.determine_risk_level(score)
        
        # Deduplicate flags by combining evidence if needed, but for simplicity we'll just group them
        # Generate recommendations based on categories
        recommendations = list(set([f"Review {f.category.value} vulnerabilities and sanitize inputs." for f in flags]))
        
        return ScanReport(
            endpoint=target_url,
            payloads_sent=total_payloads,
            anomalies_found=flags,
            overall_risk_score=score,
            recommendations=recommendations
            # Note: risk_level is not in the base model, we can return a tuple or just use reporter
        ), risk_level
