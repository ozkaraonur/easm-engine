from easm.core.config import Settings
from easm.core.models import ScanResult
from easm.scanners.crtsh import CrtShScanner
from easm.scanners.services import ServiceScanner


async def discover_services(domain: str, settings: Settings) -> ScanResult:
    """Milestone 1 -> 2: find active subdomains, then probe their web services."""
    discovery = await CrtShScanner(settings).scan(domain)
    active = [s for s in discovery.subdomains if s.is_active]
    result = await ServiceScanner(settings, hosts=active).scan(discovery.domain)
    result.started_at = discovery.started_at
    result.errors = [*discovery.errors, *result.errors]
    return result
