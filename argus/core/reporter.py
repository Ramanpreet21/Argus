# ponytail: removed Reporter class wrapper in favor of direct functions
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from argus.models import ScanReport, Severity

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "SECURE": "bold green",
}

def print_table(report: ScanReport, risk_level: str) -> None:
    """Prints a styled summary dashboard and findings table to the terminal."""
    level_style = RISK_LEVEL_COLORS.get(risk_level, "white")
    summary_text = (
        f"[bold]Target Endpoint:[/bold] {report.endpoint}\n"
        f"[bold]Payloads Sent:[/bold]   {report.payloads_sent}\n"
        f"[bold]Anomalies Found:[/bold] {len(report.anomalies_found)}\n"
        f"[bold]Risk Score:[/bold]      {report.overall_risk_score}/100\n"
        f"[bold]Risk Level:[/bold]      [{level_style}] {risk_level} [/{level_style}]"
    )
    console.print(Panel(summary_text, title="[bold cyan]Argus Scan Summary[/bold cyan]", expand=False))

    if not report.anomalies_found:
        console.print("[bold green]No anomalies detected. Target looks clean![/bold green]\n")
        return

    table = Table(title="Detected Security Anomalies", show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Description", style="white")

    for flag in report.anomalies_found:
        color = SEVERITY_COLORS.get(flag.severity, "white")
        table.add_row(
            f"[{color}]{flag.severity.value}[/{color}]",
            flag.category.value,
            flag.description,
        )
    console.print(table)

def export_json(report: ScanReport, filepath: str | Path) -> None:
    """Exports the full scan report as formatted JSON."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.write(report.model_dump_json(indent=4))
    console.print(f"[green]Successfully exported scan report to {path}[/green]")
