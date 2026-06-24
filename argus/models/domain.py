from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime

class AttackCategory(str, Enum):
    SQLI = "SQLi"
    XSS = "XSS"
    BOLA = "BOLA"
    AUTH_BYPASS = "AuthBypass"
    RATE_LIMIT_BYPASS = "RateLimitBypass"
    INFO_DISCLOSURE = "InfoDisclosure"
    METHOD_OVERRIDE = "MethodOverride"
    HEADER_ANOMALY = "HeaderAnomaly"

class TargetParam(str, Enum):
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    PATH = "path"

class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class AttackPayload(BaseModel):
    id: str = Field(..., description="Unique identifier for the payload")
    category: AttackCategory = Field(..., description="Category of the attack")
    method: str = Field(default="GET", description="HTTP method to use (GET, POST, etc.)")
    target_param: TargetParam = Field(..., description="Where to inject the payload")
    payload_value: str = Field(..., description="The actual attack payload string")
    description: Optional[str] = Field(default=None, description="Explanation of the payload")

class EndpointConfig(BaseModel):
    base_url: str = Field(..., description="Base URL of the target API")
    endpoint_path: str = Field(..., description="Path of the endpoint to test")
    method: str = Field(default="GET", description="Expected HTTP method")
    auth_header: Optional[str] = Field(default=None, description="Optional authentication header")
    timeout_seconds: float = Field(default=10.0, description="Request timeout in seconds")

class ResponseSnapshot(BaseModel):
    status_code: int = Field(..., description="HTTP status code returned")
    body: str = Field(..., description="First 1000 characters of the response body")
    headers_dict: Dict[str, str] = Field(..., description="Response headers")
    latency_ms: float = Field(..., description="Request latency in milliseconds")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time the response was received")

class AnomalyFlag(BaseModel):
    severity: Severity = Field(..., description="Severity level of the finding")
    category: AttackCategory = Field(..., description="Category of the detected vulnerability")
    description: str = Field(..., description="Human-readable description of the anomaly")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Request/Response details proving the vulnerability")

class ScanReport(BaseModel):
    endpoint: str = Field(..., description="The tested endpoint URL")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Time the scan started")
    payloads_sent: int = Field(default=0, description="Total number of payloads dispatched")
    anomalies_found: List[AnomalyFlag] = Field(default_factory=list, description="List of detected anomalies")
    overall_risk_score: int = Field(default=0, description="Calculated risk score (0-100)")
    recommendations: List[str] = Field(default_factory=list, description="Actionable remediation steps")
