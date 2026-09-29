import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx
from loguru import logger

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ScanResult, Subdomain
from easm.core.resolver import resolve_many
from easm.core.utils import is_in_scope, normalize_domain

CRTSH_URL = "https://crt.sh/"


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_entries(entries: list[dict[str, Any]], domain: str) -> list[Subdomain]:
    """Collapse raw crt.sh rows into unique, in-scope Subdomain records."""
    found: dict[str, Subdomain] = {}
    for entry in entries:
        first = parse_timestamp(entry.get("not_before"))
        last = parse_timestamp(entry.get("not_after"))
        issuer = entry.get("issuer_name")
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().removeprefix("*.")
            if not name or not is_in_scope(name, domain):
                continue
            sub = found.setdefault(name, Subdomain(name=name, sources={"crtsh"}))
            if first and (sub.first_seen is None or first < sub.first_seen):
                sub.first_seen = first
            if last and (sub.last_seen is None or last > sub.last_seen):
                sub.last_seen = last
            if issuer:
                sub.issuers.add(issuer)
    return sorted(found.values(), key=lambda s: s.name)


class CrtShScanner(BaseScanner):
    """Passive subdomain discovery from Certificate Transparency logs (crt.sh)."""

    name = "crtsh"

    def __init__(
        self,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
        resolve: bool = True,
    ) -> None:
        super().__init__(settings)
        self._client = client
        self._resolve = resolve

    async def scan(self, domain: str) -> ScanResult:
        domain = normalize_domain(domain)
        started = datetime.now(UTC)
        errors: list[str] = []
        subdomains: list[Subdomain] = []

        try:
            entries = await self._fetch(domain)
            subdomains = parse_entries(entries, domain)
            logger.info("crt.sh: {} unique hostnames for {}", len(subdomains), domain)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.error("crt.sh query failed for {}: {!r}", domain, exc)
            errors.append(f"crtsh: {exc!r}")

        if self._resolve and subdomains:
            await self._annotate_dns(subdomains)

        return ScanResult(
            scanner=self.name,
            domain=domain,
            started_at=started,
            finished_at=datetime.now(UTC),
            subdomains=subdomains,
            errors=errors,
        )

    async def _fetch(self, domain: str) -> list[dict[str, Any]]:
        """Query crt.sh with retries (the service is frequently flaky)."""
        params = {"q": f"%.{domain}", "output": "json"}
        headers = {"User-Agent": self.settings.user_agent}
        owns_client = self._client is None
        client = self._client or httpx.AsyncClient(timeout=self.settings.http_timeout)
        last_exc: Exception | None = None
        try:
            for attempt in range(self.settings.http_retries + 1):
                try:
                    resp = await client.get(CRTSH_URL, params=params, headers=headers)
                    resp.raise_for_status()
                    data = resp.json()
                    if not isinstance(data, list):
                        raise TypeError("unexpected crt.sh response shape")
                    return data
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    last_exc = exc
                    logger.warning("crt.sh attempt {} failed: {!r}", attempt + 1, exc)
                    if attempt < self.settings.http_retries:
                        await asyncio.sleep(self.settings.retry_backoff * (attempt + 1))
        finally:
            if owns_client:
                await client.aclose()
        assert last_exc is not None
        raise last_exc

    async def _annotate_dns(self, subdomains: list[Subdomain]) -> None:
        resolved = await resolve_many(
            [s.name for s in subdomains],
            self.settings.dns_concurrency,
            self.settings.dns_timeout,
        )
        for sub in subdomains:
            sub.ips = resolved.get(sub.name, [])
            sub.is_active = bool(sub.ips)
