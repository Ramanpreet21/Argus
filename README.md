# Argus — Automated API Security & Anomaly Scanner

Argus is a fast, deterministic, asynchronous API security tool designed to bring comprehensive vigilance to REST/HTTP endpoints. Named after Argus Panoptes, the mythological all-seeing giant who kept half his eyes wide open even while resting, this tool maps systemic exposures without horizontal scanning latency. 

By capturing an unattacked baseline ResponseSnapshot and evaluating concurrent mutations against 8 deterministic heuristics, Argus catches logic leaks, input injection flaws, and systemic vulnerabilities safely and concurrently.

---

## Core 5-Stage Pipeline

Argus processes scanning operations down a sequential, zero-dependency engine architecture:


[ 1. LOADER ]  →   [ 2. DISPATCHER ]   →  [ 3. CLASSIFIER ]  →  [ 4. SCORER ]  →  [ 5. REPORTER ]
YAML Payloads      Async HTTP (httpx)     8 Heuristics Loop     Weighted Math      Rich CLI / JSON


1. **Payload Loader:** Parses structured, type-safe attack matrices from a localized configuration layer mapping 5 key OWASP API risk classifications (SQLi, XSS, BOLA, Auth Bypass, Server Misconfigurations).
2. **Async Dispatcher:** Leverages asyncio and httpx to handle baseline capturing and parallelized payload execution with native rate-limit (429) resilience via tenacity.
3. **Anomaly Classifier:** Runs response mutations through 8 rigid behavioral criteria matching structural deviations, error leakage, timing anomalies, and payload reflection.
4. **Risk Scorer:** Processes categorical risk postures (Critical, High, Medium, Low, Secure) using deterministic weighted mathematical severities.
5. **Dual Reporter:** Spits out highly interactive, scannable terminal tables (rich) or structured, machine-readable JSON data ready for CI/CD gates.

---

## Quick Start

Run an end-to-end endpoint assessment right from your terminal environment:

```bash
# Scan using formatted terminal table dashboards
python -m argus scan \
  --base-url [https://api.example.com](https://api.example.com) \
  --endpoint /users/{id} \
  --method GET \
  --format table

# Export data directly to structured JSON for CI/CD pipelines
python -m argus scan \
  --base-url [https://api.example.com](https://api.example.com) \
  --endpoint /users/{id} \
  --method GET \
  --format json \
  --output scan_report.json

```

---

## Architecture & Documentation

Dig deeper into the functional core and design paradigms of the system:

* **[System Design](docs/01_ARCHITECTURE/00_system_overview.md)** — Core pipelines, module breakdowns, and architectural blueprints.
* **[Architecture Decisions (ADRs)](docs/02_ADR/)** — Chronological context log of tech stack definitions and system specifications.
