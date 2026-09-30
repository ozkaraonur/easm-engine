import asyncio
from datetime import UTC, datetime

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ScanResult, Subdomain
from easm.core.resolver import resolve_many
from easm.scanners.crtsh import CrtShScanner
from easm.scanners.dnsbrute import DnsBruteScanner
from easm.scanners.exposures import ExposureScanner
from easm.scanners.hackertarget import HackerTargetScanner
from easm.scanners.services import ServiceScanner


def merge_subdomains(results: list[ScanResult]) -> list[Subdomain]:
    """Union of hosts from several discovery sources, keeping every source's metadata."""
    merged: dict[str, Subdomain] = {}
    for result in results:
        for sub in result.subdomains:
            known = merged.get(sub.name)
            if known is None:
                merged[sub.name] = sub.model_copy(deep=True)
                continue
            known.sources |= sub.sources
            known.issuers |= sub.issuers
            known.first_seen = min(filter(None, (known.first_seen, sub.first_seen)), default=None)
            known.last_seen = max(filter(None, (known.last_seen, sub.last_seen)), default=None)
    return sorted(merged.values(), key=lambda s: s.name)


async def discover_subdomains(domain: str, settings: Settings) -> ScanResult:
    """Run every enabled discovery source concurrently, merge, then check DNS liveness.

    A failing source only adds an error; the other sources still contribute.
    """
    scanners: list[BaseScanner] = [CrtShScanner(settings, resolve=False)]
    if settings.hackertarget_enabled:
        scanners.append(HackerTargetScanner(settings))
    if settings.dns_brute_enabled:
        scanners.append(DnsBruteScanner(settings))
    started = datetime.now(UTC)
    results = await asyncio.gather(*(s.scan(domain) for s in scanners))

    hosts = merge_subdomains(list(results))
    resolved = await resolve_many(
        [h.name for h in hosts], settings.dns_concurrency, settings.dns_timeout
    )
    for host in hosts:
        host.ips = resolved.get(host.name, [])
        host.is_active = bool(host.ips)
    return ScanResult(
        scanner="discovery",
        domain=results[0].domain,
        started_at=started,
        finished_at=datetime.now(UTC),
        subdomains=hosts,
        errors=[e for r in results for e in r.errors],
    )


async def discover_services(domain: str, settings: Settings) -> ScanResult:
    """Milestone 1 -> 2: find active subdomains, then probe their web services."""
    discovery = await discover_subdomains(domain, settings)
    active = [s for s in discovery.subdomains if s.is_active]
    result = await ServiceScanner(settings, hosts=active).scan(discovery.domain)
    result.started_at = discovery.started_at
    result.errors = [*discovery.errors, *result.errors]
    return result


async def probe_exposures(services: ScanResult, settings: Settings) -> ScanResult:
    """Add exposure findings to a services result, keeping hosts without web services."""
    web_hosts = [h for h in services.subdomains if h.services]
    exposed = await ExposureScanner(settings, hosts=web_hosts).scan(services.domain)
    probed = {h.name: h for h in exposed.subdomains}
    return services.model_copy(
        update={
            "scanner": exposed.scanner,
            "finished_at": exposed.finished_at,
            "subdomains": [probed.get(h.name, h) for h in services.subdomains],
            "errors": [*services.errors, *exposed.errors],
        }
    )


async def full_scan(domain: str, settings: Settings) -> ScanResult:
    """Discovery -> services and risky ports -> exposure checks."""
    return await probe_exposures(await discover_services(domain, settings), settings)
