import pytest
from datetime import datetime
from argus.core.classifier import ResponseClassifier
from argus.models import ResponseSnapshot, AttackPayload, AttackCategory, TargetParam, Severity

@pytest.fixture
def baseline_response():
    return ResponseSnapshot(
        status_code=403,
        body="Access Denied",
        headers_dict={"content-type": "text/plain"},
        latency_ms=100.0,
        timestamp=datetime.now()
    )

@pytest.fixture
def classifier(baseline_response):
    return ResponseClassifier(baseline=baseline_response)

def test_auth_bypass_heuristic(classifier):
    payload = AttackPayload(
        id="auth_1",
        category=AttackCategory.AUTH_BYPASS,
        target_param=TargetParam.HEADER,
        payload_value="admin: true"
    )
    # Payload resulted in 200 OK (bypass)
    response = ResponseSnapshot(
        status_code=200,
        body="Welcome Admin",
        headers_dict={},
        latency_ms=120.0
    )
    
    flags = classifier.classify(payload, response)
    
    assert len(flags) > 0
    # The first rule checks 401/403 -> 200
    assert any(f.category == AttackCategory.AUTH_BYPASS for f in flags)
    assert any(f.severity == Severity.CRITICAL for f in flags)

def test_sql_error_leakage_heuristic(classifier):
    payload = AttackPayload(
        id="sqli_1",
        category=AttackCategory.SQLI,
        target_param=TargetParam.QUERY,
        payload_value="' OR 1=1--"
    )
    response = ResponseSnapshot(
        status_code=500,
        body="Fatal error: unclosed quotation mark after character string",
        headers_dict={},
        latency_ms=150.0
    )
    
    flags = classifier.classify(payload, response)
    
    # Should flag 500 error AND the SQL leakage
    assert len(flags) == 2
    assert any(f.category == AttackCategory.INFO_DISCLOSURE for f in flags) # From the regex match
    assert any(f.category == AttackCategory.SQLI for f in flags) # From the 500 status code

def test_timing_anomaly_heuristic(classifier):
    payload = AttackPayload(
        id="sqli_time",
        category=AttackCategory.SQLI,
        target_param=TargetParam.QUERY,
        payload_value="WAITFOR DELAY '0:0:5'"
    )
    # Latency is > 5x baseline (100ms * 5 = 500ms) and > 2000ms
    response = ResponseSnapshot(
        status_code=403,
        body="Access Denied",
        headers_dict={},
        latency_ms=5100.0 
    )
    
    flags = classifier.classify(payload, response)
    
    assert len(flags) == 1
    assert flags[0].category == AttackCategory.SQLI
    assert "Response latency" in flags[0].description

def test_xss_reflection_heuristic(classifier):
    payload = AttackPayload(
        id="xss_1",
        category=AttackCategory.XSS,
        target_param=TargetParam.QUERY,
        payload_value="<script>alert(1)</script>"
    )
    response = ResponseSnapshot(
        status_code=403,
        body="You searched for <script>alert(1)</script>, access denied.",
        headers_dict={},
        latency_ms=100.0
    )
    
    flags = classifier.classify(payload, response)
    
    assert len(flags) == 1
    assert flags[0].category == AttackCategory.XSS
    assert flags[0].severity == Severity.HIGH

def test_debug_headers_heuristic(classifier):
    payload = AttackPayload(
        id="header_test",
        category=AttackCategory.INFO_DISCLOSURE,
        target_param=TargetParam.PATH,
        payload_value="test"
    )
    response = ResponseSnapshot(
        status_code=403,
        body="Access Denied",
        headers_dict={"X-Powered-By": "Express", "Server": "nginx/1.18.0"},
        latency_ms=100.0
    )
    
    flags = classifier.classify(payload, response)
    
    assert len(flags) == 1
    assert flags[0].category == AttackCategory.HEADER_ANOMALY
    assert flags[0].severity == Severity.LOW
    assert len(flags[0].evidence["headers"]) == 2
