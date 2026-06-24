# Argus — API Security Scanner

**Automated fuzzing and anomaly detection for REST APIs.**

Sends attack payloads in parallel, classifies responses for exploitation signals 
(SQLi, XSS, BOLA, auth bypass, timing attacks, info disclosure, method override, header anomalies),
and produces risk-scored JSON reports with remediation guidance.

## Quick Start

```bash
python -m argus scan \
  --base-url https://api.example.com \
  --endpoint /users/{id} \
  --method GET \
  --format table
```

## Architecture & Documentation

- [System Design](docs/01_ARCHITECTURE/00_system_overview.md)
- [Architecture Decisions (ADRs)](docs/02_ADR/)
- [Anomaly Heuristics (8 methods)](docs/04_INTERNALS/00_anomaly_heuristics.md)
- [Risk Scoring Formula](docs/04_INTERNALS/01_risk_scoring_algorithm.md)

## Getting Started

[Full guide →](docs/03_GUIDES/00_getting_started.md)
