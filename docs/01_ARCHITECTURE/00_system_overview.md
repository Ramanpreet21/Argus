# System Overview: Argus

Argus is built with a modular architecture:

1. **CLI (typer)**: Handles user input and arguments.
2. **Payload Loader (YAML)**: Loads structured attack payloads.
3. **Async Dispatcher (httpx)**: Sends parallel HTTP requests with retry logic (tenacity).
4. **Response Classifier**: Evaluates responses across 8 heuristic signals.
5. **Risk Scorer**: Computes deterministic risk scores (0-100) based on severity.
6. **Report Generator**: Outputs actionable JSON reports.
