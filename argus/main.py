# ponytail: streamlined CLI entry point using functional core
import asyncio
import time
import logging
from typing import Optional
from pathlib import Path

import typer
import httpx
from rich.console import Console

from argus.models import EndpointConfig, ResponseSnapshot
from argus.payloads.loader import load_payloads
from argus.core import (
    AsyncDispatcher,
    ResponseClassifier,
    generate_report,
    print_table,
    export_json,
)

app = typer.Typer(
    name="argus",
    help="Argus — Automated API Security & Anomaly Scanner",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

@app.callback()
def main():
    """Argus — Automated API Security & Anomaly Scanner"""
    pass

def _parse_auth_header(header: Optional[str]) -> dict:
    """Helper to parse a single 'Key: Value' string into a header dictionary."""
    if header and ":" in header:
        k, v = header.split(":", 1)
        return {k.strip(): v.strip()}
    return {}

async def _fetch_baseline(config: EndpointConfig) -> ResponseSnapshot:
    """Fetches the baseline response for the endpoint without attack payloads."""
    url = f"{config.base_url.rstrip('/')}/{config.endpoint_path.lstrip('/')}"
    headers = _parse_auth_header(config.auth_header)

    start_time = time.time()
    async with httpx.AsyncClient(verify=False) as client:
        response = await client.request(
            method=config.method,
            url=url,
            headers=headers,
            timeout=config.timeout_seconds,
        )
    latency_ms = (time.time() - start_time) * 1000
    body_text = response.text[:1000] if response.text else ""
    return ResponseSnapshot(
        status_code=response.status_code,
        body=body_text,
        headers_dict=dict(response.headers),
        latency_ms=latency_ms,
    )

@app.command("scan")
def scan(
    base_url: str = typer.Option(..., "--base-url", "-u", help="Base URL of the target API (e.g. https://api.example.com)"),
    endpoint: str = typer.Option(..., "--endpoint", "-e", help="Endpoint path to test (e.g. /users/{id})"),
    method: str = typer.Option("GET", "--method", "-m", help="HTTP method to use"),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", "-a", help="Authentication header (e.g. 'Authorization: Bearer xyz')"),
    payloads_file: str = typer.Option("payloads/attacks.yaml", "--payloads", "-p", help="Path to YAML attacks file"),
    output_format: str = typer.Option("table", "--format", "-f", help="Output format: 'table' or 'json'"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="File path to save JSON report"),
    batch_size: int = typer.Option(5, "--batch-size", "-b", help="Number of concurrent requests"),
):
    """Run an automated API security scan against a specified endpoint."""
    console.print(f"[bold cyan]Argus Scanner Initializing...[/bold cyan]")

    # 1. Load Payloads
    try:
        payloads = load_payloads(payloads_file)
    except Exception as e:
        console.print(f"[bold red]Error loading payloads:[/bold red] {e}")
        raise typer.Exit(code=1)

    # 2. Setup Endpoint Config
    config = EndpointConfig(
        base_url=base_url,
        endpoint_path=endpoint,
        method=method.upper(),
        auth_header=auth_header,
    )

    # 3. Run Async Scan Workflow
    async def _run_scan():
        console.print(f"[yellow]Fetching baseline response from target...[/yellow]")
        baseline = await _fetch_baseline(config)
        console.print(f"[green]Baseline captured (Status: {baseline.status_code}, Latency: {baseline.latency_ms:.1f}ms)[/green]")

        dispatcher = AsyncDispatcher(config, batch_size=batch_size)
        console.print(f"[yellow]Dispatching {len(payloads)} payloads concurrently...[/yellow]")
        results = await dispatcher.dispatch_all(payloads)

        classifier = ResponseClassifier(baseline=baseline)
        all_flags = []
        for p in payloads:
            res = results.get(p.id)
            if isinstance(res, ResponseSnapshot):
                flags = classifier.classify(p, res)
                all_flags.extend(flags)

        report, risk_level = generate_report(
            target_url=f"{config.base_url.rstrip('/')}/{config.endpoint_path.lstrip('/')}",
            total_payloads=len(payloads),
            flags=all_flags,
        )
        return report, risk_level

    report, risk_level = asyncio.run(_run_scan())

    # 4. Output Presentation
    if output_format.lower() == "table":
        print_table(report, risk_level)
    elif output_format.lower() == "json":
        console.print(report.model_dump_json(indent=4))

    if output_file:
        export_json(report, output_file)

if __name__ == "__main__":
    app()
