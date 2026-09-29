from easm.core.models import SEVERITY_ORDER, ScanResult
from easm.reporting.remediation import remediation_for
from easm.reporting.summary import assets, summarize


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """Render a scan as a Markdown audit report."""
    s = summarize(result)
    out = [
        f"# EASM Report: {s.domain}",
        "",
        f"Scan started {s.started_at}, duration {s.duration_seconds}s.",
        "",
        "## Executive Summary",
        "",
        f"- Overall risk: **{s.risk.upper()}**",
        f"- Subdomains discovered: **{s.subdomains}** ({s.active_subdomains} active)",
        f"- Web services: **{s.services}** on {s.web_hosts} hosts",
        f"- Findings: **{s.total_findings}**",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
        *(f"| {name.capitalize()} | {s.severity_counts[name]} |" for name in SEVERITY_ORDER),
        "",
        "## Discovered Assets",
        "",
        "| Host | Active | IPs | Open ports | Web services |",
        "| --- | --- | --- | --- | --- |",
    ]
    for h in assets(result):
        state = {True: "yes", False: "no", None: "-"}[h.is_active]
        urls = ", ".join(sv.url for sv in h.services) or "-"
        ports = ", ".join(map(str, h.open_ports)) or "-"
        out.append(
            f"| {_cell(h.name)} | {state} | {_cell(', '.join(h.ips) or '-')} | {ports} "
            f"| {_cell(urls)} |"
        )
    out += ["", "## Findings", ""]
    if not result.findings:
        out.append("No exposures were found.")
    for i, f in enumerate(result.findings, 1):
        out += [
            f"### {i}. [{f.severity.upper()}] {f.check}",
            "",
            f"- URL: {f.url}",
            f"- HTTP status: {f.status_code}",
            f"- Evidence: {f.evidence}",
            f"- Remediation: {remediation_for(f.check)}",
            "",
        ]
    if result.errors:
        out += ["## Errors", "", *(f"- {e}" for e in result.errors), ""]
    return "\n".join(out).rstrip() + "\n"
