from collections import Counter

from pydantic import BaseModel

from easm.core.models import SEVERITY_ORDER, ScanResult, Severity, Subdomain


class ReportSummary(BaseModel):
    """Aggregate numbers shared by every report format."""

    domain: str
    started_at: str
    duration_seconds: float
    subdomains: int
    active_subdomains: int
    web_hosts: int
    services: int
    port_distribution: dict[int, int]  # port -> number of hosts with it open
    severity_counts: dict[Severity, int]
    risk: str  # highest severity present, or "none"

    @property
    def total_findings(self) -> int:
        return sum(self.severity_counts.values())


def summarize(result: ScanResult) -> ReportSummary:
    ports = Counter(p for h in result.subdomains for p in h.open_ports)
    severities = Counter(f.severity for f in result.findings)
    counts: dict[Severity, int] = {s: severities.get(s, 0) for s in SEVERITY_ORDER}
    risk = next((s for s in SEVERITY_ORDER if counts[s]), "none")
    return ReportSummary(
        domain=result.domain,
        started_at=result.started_at.strftime("%Y-%m-%d %H:%M UTC"),
        duration_seconds=round((result.finished_at - result.started_at).total_seconds(), 1),
        subdomains=len(result.subdomains),
        active_subdomains=result.active_count,
        web_hosts=sum(1 for h in result.subdomains if h.services),
        services=sum(len(h.services) for h in result.subdomains),
        port_distribution=dict(sorted(ports.items())),
        severity_counts=counts,
        risk=risk,
    )


def assets(result: ScanResult) -> list[Subdomain]:
    """Hosts sorted for display: with web services first, then by name."""
    return sorted(result.subdomains, key=lambda h: (not h.services, h.name))
