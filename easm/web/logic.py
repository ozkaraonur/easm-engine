from collections.abc import Callable
from datetime import UTC, datetime

from pydantic import BaseModel

from easm.core.config import Settings
from easm.core.models import ScanResult, Subdomain
from easm.core.risk import weaknesses
from easm.pipeline import discover_subdomains, probe_exposures
from easm.scanners.services import ServiceScanner
from easm.web.demo import DEMO_DOMAIN, run_demo_scan

ProgressCallback = Callable[[float, str], None]


class ScanOptions(BaseModel):
    """Which modules the dashboard should run."""

    subdomains: bool = True
    ports: bool = True
    exposures: bool = True

    @property
    def needs_services(self) -> bool:
        """Exposure probing needs live web services, so it implies the port/service stage."""
        return self.ports or self.exposures


def open_port_count(result: ScanResult) -> int:
    return sum(len(h.open_ports) for h in result.subdomains)


def port_rows(result: ScanResult) -> list[dict[str, str | int]]:
    """One row per open port (with its web service, if any) for the dashboard table."""
    rows: list[dict[str, str | int]] = []
    for host in sorted(result.subdomains, key=lambda h: h.name):
        by_port = {s.port: s for s in host.services}
        for port in host.open_ports:
            svc = by_port.get(port)
            rows.append(
                {
                    "Host": host.name,
                    "Port": port,
                    "Service": svc.scheme.upper() if svc else "tcp",
                    "Status": (svc.status_code or "-") if svc else "-",
                    "Server": (svc.server or "-") if svc else "-",
                    "Banner": host.banners.get(port, "-"),
                    "Title": (svc.title or "-") if svc else "-",
                }
            )
    return rows


def finding_rows(result: ScanResult) -> list[dict[str, str | int]]:
    return [
        {
            "Severity": f.severity.upper(),
            "URL": f.url,
            "Status": f.status_code,
            "Evidence": f.evidence,
        }
        for f in result.findings
    ]


def weakness_rows(result: ScanResult) -> list[dict[str, str]]:
    return [{"Host": w.host, "Weakness": w.kind, "Detail": w.detail} for w in weaknesses(result)]


async def run_scan(
    domain: str,
    options: ScanOptions,
    settings: Settings,
    progress: ProgressCallback | None = None,
) -> ScanResult:
    """Run the selected modules in sequence, reporting stage-level progress.

    Without subdomain enumeration only the apex domain itself is scanned.
    """

    def report(fraction: float, message: str) -> None:
        if progress:
            progress(fraction, message)

    report(0.05, "Starting scan")
    if domain == DEMO_DOMAIN:  # offline demo: local leaky servers, no real network scan
        result = await run_demo_scan(progress)
        report(1.0, "Scan complete")
        return result
    if options.subdomains:
        report(0.10, "Enumerating subdomains (crt.sh, HackerTarget, DNS wordlist)")
        result = await discover_subdomains(domain, settings)
        hosts = [h for h in result.subdomains if h.is_active]
    else:
        now = datetime.now(UTC)
        result = ScanResult(
            scanner="web",
            domain=domain,
            started_at=now,
            finished_at=now,
            subdomains=[Subdomain(name=domain)],
        )
        hosts = list(result.subdomains)
    report(0.40, f"{len(result.subdomains)} hosts found")

    if options.needs_services:
        report(0.45, "Scanning ports and web services")
        services = await ServiceScanner(settings, hosts=hosts).scan(domain)
        known = {h.name: h for h in services.subdomains}
        result.subdomains = [known.get(h.name, h) for h in result.subdomains]
        result.errors = [*result.errors, *services.errors]
        report(0.70, f"{sum(1 for h in result.subdomains if h.services)} hosts with web services")
        if options.exposures:
            report(0.75, "Probing sensitive files")
            result = await probe_exposures(result, settings)

    result.finished_at = datetime.now(UTC)
    report(1.0, "Scan complete")
    return result
