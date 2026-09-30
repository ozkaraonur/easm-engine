import asyncio
import html
import re
import ssl
from datetime import UTC, datetime

import httpx
from loguru import logger

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ScanResult, Service, Subdomain
from easm.core.portcheck import grab_banner, scan_ports
from easm.core.ports import RISKY_PORTS, port_exposure
from easm.core.utils import normalize_domain

HTTPS_PORTS = frozenset({443, 8443, 9443})
HTTP_PORTS = frozenset({80, 8000, 8008, 8080, 8888})
MAX_BODY_BYTES = 64 * 1024
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(body: str) -> str | None:
    """Return the cleaned <title> text, or None if absent/empty."""
    match = _TITLE_RE.search(body)
    if not match:
        return None
    title = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return title[:200] or None


def build_url(scheme: str, host: str, port: int) -> str:
    default = 443 if scheme == "https" else 80
    return f"{scheme}://{host}/" if port == default else f"{scheme}://{host}:{port}/"


def tls_error_of(exc: BaseException) -> ssl.SSLError | None:
    """Walk the exception chain looking for an SSL error."""
    visited: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in visited:  # chains can be cyclic
        if isinstance(current, ssl.SSLError):
            return current
        visited.add(id(current))
        current = current.__cause__ or current.__context__
    return None


class ServiceScanner(BaseScanner):
    """Detects open web ports and collects basic HTTP(S) info for a set of hosts.

    Hosts come from the constructor (e.g. active subdomains found by another
    scanner, wired together in easm.pipeline); if none are given, only the
    target domain itself is scanned.
    """

    name = "services"

    def __init__(
        self, settings: Settings | None = None, hosts: list[Subdomain] | None = None
    ) -> None:
        super().__init__(settings)
        self._hosts = hosts

    async def scan(self, domain: str) -> ScanResult:
        domain = normalize_domain(domain)
        started = datetime.now(UTC)
        hosts = [h.model_copy(deep=True) for h in (self._hosts or [Subdomain(name=domain)])]
        sem = asyncio.Semaphore(self.settings.service_concurrency)
        headers = {"User-Agent": self.settings.user_agent}
        timeout = self.settings.service_http_timeout

        async with (
            httpx.AsyncClient(timeout=timeout, headers=headers) as secure,
            httpx.AsyncClient(timeout=timeout, headers=headers, verify=False) as insecure,
        ):

            async def _bounded(host: Subdomain) -> None:
                async with sem:
                    await self._scan_host(host, secure, insecure)

            await asyncio.gather(*(_bounded(h) for h in hosts))

        logger.info(
            "services: {} services across {} hosts",
            sum(len(h.services) for h in hosts),
            len(hosts),
        )
        return ScanResult(
            scanner=self.name,
            domain=domain,
            started_at=started,
            finished_at=datetime.now(UTC),
            subdomains=hosts,
        )

    async def _scan_host(
        self, host: Subdomain, secure: httpx.AsyncClient, insecure: httpx.AsyncClient
    ) -> None:
        host.open_ports = await scan_ports(
            host.name, self.settings.service_ports, self.settings.port_timeout
        )
        await self._annotate_risky_ports(host)
        probes = [
            self._probe(
                host.name, port, "https" if port in HTTPS_PORTS else "http", secure, insecure
            )
            for port in host.open_ports
            if port in HTTPS_PORTS or port in HTTP_PORTS
        ]
        host.services = [s for s in await asyncio.gather(*probes) if s is not None]

    async def _annotate_risky_ports(self, host: Subdomain) -> None:
        """Passive banner grab plus a finding for every open non-web risky port."""
        risky = [p for p in host.open_ports if p in RISKY_PORTS]
        banners = await asyncio.gather(
            *(grab_banner(host.name, p, self.settings.port_timeout) for p in risky)
        )
        for port, banner in zip(risky, banners, strict=True):
            if banner:
                host.banners[port] = banner
            if finding := port_exposure(host.name, port, banner):
                host.port_exposures.append(finding)

    async def _probe(
        self,
        host: str,
        port: int,
        scheme: str,
        secure: httpx.AsyncClient,
        insecure: httpx.AsyncClient,
    ) -> Service | None:
        url = build_url(scheme, host, port)
        tls_valid: bool | None = None
        tls_error: str | None = None
        try:
            response, body = await self._get(secure, url)
            tls_valid = True if scheme == "https" else None
        except httpx.HTTPError as exc:
            ssl_exc = tls_error_of(exc) if scheme == "https" else None
            if ssl_exc is None:
                logger.debug("HTTP probe failed for {}: {!r}", url, exc)
                return None
            tls_valid, tls_error = False, str(ssl_exc)
            try:
                response, body = await self._get(insecure, url)
            except httpx.HTTPError as exc2:
                logger.debug("Insecure probe failed for {}: {!r}", url, exc2)
                return None

        return Service(
            port=port,
            scheme="https" if scheme == "https" else "http",
            url=url,
            status_code=response.status_code,
            title=extract_title(body),
            server=response.headers.get("server"),
            tls_valid=tls_valid,
            tls_error=tls_error,
        )

    @staticmethod
    async def _get(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, str]:
        """GET without following redirects; read at most MAX_BODY_BYTES of the body."""
        async with client.stream("GET", url, follow_redirects=False) as resp:
            body = b""
            async for chunk in resp.aiter_bytes():
                body += chunk
                if len(body) >= MAX_BODY_BYTES:
                    break
            return resp, body[:MAX_BODY_BYTES].decode(resp.encoding or "utf-8", errors="replace")
