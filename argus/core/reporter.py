import json
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from argus.models import ScanReport

class Reporter:
    """Formats and prints ScanReports to the console or saves them as JSON."""
    
    def __init__(self):
        self.console = Console()

    def print_table(self, report: ScanReport, risk_level: str):
        """Prints a highly polished terminal table using Rich."""
        
        # Color code the risk level
        color_map = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "blue",
            "SECURE": "bold green"
        }
        level_color = color_map.get(risk_level, "white")
        
        # Summary Panel
        summary_text = (
            f"Target URL: [cyan]{report.endpoint}[/cyan]\n"
            f"Payloads Sent: {report.payloads_sent}\n"
            f"Anomalies Detected: {len(report.anomalies_found)}\n"
            f"Risk Score: [{level_color}]{report.overall_risk_score}/100[/{level_color}]\n"
            f"Risk Level: [{level_color}]{risk_level}[/{level_color}]"
        )
        self.console.print(Panel(summary_text, title="Argus Scan Summary", border_style="cyan"))

        if not report.anomalies_found:
            self.console.print("[bold green]No vulnerabilities detected. API is secure against tested payloads.[/bold green]")
            return

        # Detailed Findings Table
        table = Table(title="Detected Anomalies", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=12)
        table.add_column("Category", style="cyan")
        table.add_column("Description")
        
        for flag in report.anomalies_found:
            # Map severity to color for the table
            sev_str = flag.severity.value
            if flag.severity.name == "CRITICAL":
                sev_color = "[bold red]"
            elif flag.severity.name == "HIGH":
                sev_color = "[red]"
            elif flag.severity.name == "MEDIUM":
                sev_color = "[yellow]"
            else:
                sev_color = "[blue]"
                
            table.add_row(
                f"{sev_color}{sev_str}[/]",
                flag.category.value,
                flag.description
            )
            
        self.console.print(table)
        
    def export_json(self, report: ScanReport, filepath: str):
        """Exports the ScanReport to a JSON file."""
        with open(filepath, "w") as f:
            json.dump(report.model_dump(), f, indent=4)
        self.console.print(f"[bold green]Report exported to {filepath}[/bold green]")
