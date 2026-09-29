from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from easm.core.models import SEVERITY_ORDER, ScanResult
from easm.reporting.summary import summarize

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


def render_dashboard(result: ScanResult, console: Console | None = None) -> None:
    """Print the summary dashboard: totals, port distribution, findings by severity."""
    console = console or Console()
    s = summarize(result)

    totals = Table.grid(padding=(0, 2))
    totals.add_row("Subdomains", f"[bold]{s.subdomains}[/] ({s.active_subdomains} active)")
    totals.add_row("Web hosts", f"[bold]{s.web_hosts}[/]")
    totals.add_row("Web services", f"[bold]{s.services}[/]")
    totals.add_row("Findings", f"[bold]{s.total_findings}[/]")
    console.print(Panel(totals, title=f"EASM summary: {s.domain}", expand=False))

    ports = Table(title="Open ports", header_style="bold")
    ports.add_column("Port", justify="right")
    ports.add_column("Hosts", justify="right")
    for port, count in s.port_distribution.items():
        ports.add_row(str(port), str(count))
    if not s.port_distribution:
        ports.add_row("-", "0")
    console.print(ports)

    sev = Table(title="Findings by severity", header_style="bold")
    sev.add_column("Severity")
    sev.add_column("Count", justify="right")
    for name in SEVERITY_ORDER:
        if name == "low" and not s.severity_counts[name]:
            continue  # no check emits "low" yet; keep the table to Critical/High/Medium/Info
        style = SEVERITY_STYLE[name]
        sev.add_row(f"[{style}]{name.upper()}[/]", str(s.severity_counts[name]))
    console.print(sev)

    if result.findings:
        detail = Table(title="Findings", header_style="bold", show_lines=False)
        detail.add_column("Severity")
        detail.add_column("URL", overflow="fold")
        detail.add_column("Evidence", overflow="fold")
        for f in result.findings:
            style = SEVERITY_STYLE[f.severity]
            detail.add_row(f"[{style}]{f.severity.upper()}[/]", escape(f.url), escape(f.evidence))
        console.print(detail)
    for err in result.errors:
        console.print(f"[red]ERROR:[/] {err}")
