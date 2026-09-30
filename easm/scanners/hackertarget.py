from datetime import UTC, datetime

import httpx
from loguru import logger

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ScanResult, Subdomain
from easm.core.utils import is_in_scope, normalize_domain

HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/"


def parse_hostsearch(text: str, domain: str) -> list[Subdomain]:
    """Parse `host,ip` lines into unique in-scope subdomains (the API reports errors as text)."""
    found: dict[str, Subdomain] = {}
    for line in text.splitlines():
        name, _, ip = line.strip().lower().partition(",")
        if not name or " " in name or not is_in_scope(name, domain):
            continue
        sub = found.setdefault(name, Subdomain(name=name, sources={"hackertarget"}))
        if ip and ip not in sub.ips:
            sub.ips.append(ip)
    return sorted(found.values(), key=lambda s: s.name)


class HackerTargetScanner(BaseScanner):
    """Passive subdomain discovery via the HackerTarget host-search API (free tier, rate-limited)."""

    name = "hackertarget"

    def __init__(
        self, settings: Settings | None = None, client: httpx.AsyncClient | None = None
    ) -> None:
        super().__init__(settings)
        self._client = client

    async def scan(self, domain: str) -> ScanResult:
        domain = normalize_domain(domain)
        started = datetime.now(UTC)
        errors: list[str] = []
        subdomains: list[Subdomain] = []
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.settings.http_timeout)
        try:
            resp = await client.get(
                HACKERTARGET_URL,
                params={"q": domain},
                headers={"User-Agent": self.settings.user_agent},
            )
            resp.raise_for_status()
            text = resp.text
            if text.lower().startswith("error") or "api count exceeded" in text.lower():
                errors.append(f"hackertarget: {text.strip()[:100]}")
            else:
                subdomains = parse_hostsearch(text, domain)
        except httpx.HTTPError as exc:
            logger.warning("hackertarget query failed for {}: {!r}", domain, exc)
            errors.append(f"hackertarget: {exc!r}")
        finally:
            if owns_client:
                await client.aclose()
        return ScanResult(
            scanner=self.name,
            domain=domain,
            started_at=started,
            finished_at=datetime.now(UTC),
            subdomains=subdomains,
            errors=errors,
        )
