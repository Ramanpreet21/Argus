import re
from typing import List, Dict, Any

from argus.models import ResponseSnapshot, AnomalyFlag, Severity, AttackCategory, AttackPayload

class ResponseClassifier:
    """Classifies HTTP responses using 8 deterministic heuristics to detect vulnerabilities."""

    # Common database/framework error keywords
    ERROR_KEYWORDS = [
        r"sql syntax", r"mysql_fetch", r"ora-[0-9]{4}", r"postgresql query failed",
        r"jdbc:mysql", r"sqlite3::", r"unclosed quotation mark", r"java\.sql\.SQLException",
        r"stack trace:", r"syntax error"
    ]
    ERROR_REGEX = re.compile("|".join(ERROR_KEYWORDS), re.IGNORECASE)

    # Sensitive debug headers
    DEBUG_HEADERS = ["x-debug-info", "x-powered-by", "server", "x-aspnet-version"]

    def __init__(self, baseline: ResponseSnapshot):
        self.baseline = baseline

    def classify(self, payload: AttackPayload, response: ResponseSnapshot) -> List[AnomalyFlag]:
        """Runs all 8 heuristics against a payload response compared to the baseline."""
        flags: List[AnomalyFlag] = []

        # 1. Status Code Anomalies
        if self.baseline.status_code != response.status_code:
            # 401/403 -> 200/2xx implies Auth Bypass
            if self.baseline.status_code in [401, 403] and 200 <= response.status_code < 300:
                flags.append(AnomalyFlag(
                    severity=Severity.CRITICAL,
                    category=AttackCategory.AUTH_BYPASS,
                    description=f"Status code changed from {self.baseline.status_code} to {response.status_code}, indicating potential authorization bypass.",
                    evidence={"baseline_status": self.baseline.status_code, "payload_status": response.status_code}
                ))
            # <500 -> 500 implies Server Error (often SQLi or malformed input crash)
            elif self.baseline.status_code < 500 and response.status_code >= 500:
                flags.append(AnomalyFlag(
                    severity=Severity.HIGH,
                    category=payload.category, # Usually inherited from the payload's intent
                    description=f"Server returned a {response.status_code} error, indicating unhandled input.",
                    evidence={"baseline_status": self.baseline.status_code, "payload_status": response.status_code}
                ))

        # 2. Error Message Leakage (SQLi, etc.)
        if self.ERROR_REGEX.search(response.body):
            flags.append(AnomalyFlag(
                severity=Severity.HIGH,
                category=AttackCategory.INFO_DISCLOSURE,
                description="Database or framework error message detected in response body.",
                evidence={"match": "Found SQL/Framework stack trace keywords"}
            ))

        # 3. Timing Anomalies (Time-based SQLi / DoS)
        # 5x latency is our SSOT threshold
        if response.latency_ms > (self.baseline.latency_ms * 5) and response.latency_ms > 2000:
            flags.append(AnomalyFlag(
                severity=Severity.HIGH,
                category=payload.category,
                description=f"Response latency ({response.latency_ms:.0f}ms) is >5x baseline ({self.baseline.latency_ms:.0f}ms).",
                evidence={"baseline_latency": self.baseline.latency_ms, "payload_latency": response.latency_ms}
            ))

        # 4. BOLA (Broken Object Level Authorization) Detection
        # If the body changed significantly but status is still 200, it might be accessing another user
        if payload.category == AttackCategory.BOLA and response.status_code == 200:
            # Simplistic check: If it's a 200 but the body length is significantly different 
            # or the body text doesn't match baseline. In a real scenario, you'd check for user IDs in the JSON.
            if abs(len(response.body) - len(self.baseline.body)) > 10 or response.body != self.baseline.body:
                flags.append(AnomalyFlag(
                    severity=Severity.CRITICAL,
                    category=AttackCategory.BOLA,
                    description="Sequential ID resulted in a successful response with different content than baseline.",
                    evidence={"baseline_length": len(self.baseline.body), "payload_length": len(response.body)}
                ))

        # 5. XSS Reflection
        if payload.category == AttackCategory.XSS:
            # If the exact payload is reflected unescaped in the response body
            if payload.payload_value in response.body:
                flags.append(AnomalyFlag(
                    severity=Severity.HIGH,
                    category=AttackCategory.XSS,
                    description="XSS payload was reflected unescaped in the response body.",
                    evidence={"reflected_payload": payload.payload_value}
                ))

        # 6. Response Body Length Anomalies (Exfiltration)
        # 3x larger = potential exfiltration
        if len(response.body) > (len(self.baseline.body) * 3) and len(response.body) > 500:
            flags.append(AnomalyFlag(
                severity=Severity.MEDIUM,
                category=AttackCategory.INFO_DISCLOSURE,
                description=f"Response body is >3x larger than baseline, indicating potential data exfiltration.",
                evidence={"baseline_length": len(self.baseline.body), "payload_length": len(response.body)}
            ))

        # 7. Debug Headers
        found_debug = []
        # lower keys for case-insensitive match
        resp_headers_lower = {k.lower(): v for k, v in response.headers_dict.items()}
        for header in self.DEBUG_HEADERS:
            if header in resp_headers_lower:
                found_debug.append(f"{header}: {resp_headers_lower[header]}")
        
        if found_debug:
            flags.append(AnomalyFlag(
                severity=Severity.LOW,
                category=AttackCategory.HEADER_ANOMALY,
                description="Sensitive debug or server framework headers exposed.",
                evidence={"headers": found_debug}
            ))

        # 8. HTTP Method Override
        if payload.category == AttackCategory.METHOD_OVERRIDE and response.status_code == 200:
            flags.append(AnomalyFlag(
                severity=Severity.MEDIUM,
                category=AttackCategory.METHOD_OVERRIDE,
                description="Method override header (e.g., X-HTTP-Method-Override: DELETE) succeeded.",
                evidence={"payload_status": 200}
            ))

        return flags
