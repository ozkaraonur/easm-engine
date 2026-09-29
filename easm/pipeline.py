from easm.core.config import Settings
from easm.core.models import ScanResult
from easm.scanners.crtsh import CrtShScanner
from easm.scanners.exposures import ExposureScanner
from easm.scanners.services import ServiceScanner


async def discover_services(domain: str, settings: Settings) -> ScanResult:
    """Milestone 1 -> 2: find active subdomains, then probe their web services."""
    discovery = await CrtShScanner(settings).scan(domain)
    active = [s for s in discovery.subdomains if s.is_active]
    result = await ServiceScanner(settings, hosts=active).scan(discovery.domain)
    result.started_at = discovery.started_at
    result.errors = [*discovery.errors, *result.errors]
    return result


async def full_scan(domain: str, settings: Settings) -> ScanResult:
    """Milestone 1 -> 3: crt.sh -> web services -> exposure checks."""
    services = await discover_services(domain, settings)
    web_hosts = [h for h in services.subdomains if h.services]
    result = await ExposureScanner(settings, hosts=web_hosts).scan(services.domain)
    result.started_at = services.started_at
    result.errors = [*services.errors, *result.errors]
    return result
