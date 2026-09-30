import secrets
from datetime import UTC, datetime
from typing import Final

from loguru import logger

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ScanResult, Subdomain
from easm.core.resolver import resolve_host, resolve_many
from easm.core.utils import normalize_domain

WORDLIST: Final[tuple[str, ...]] = (
    "www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "sftp", "ns1", "ns2", "vpn",
    "remote", "api", "app", "apps", "admin", "portal", "dev", "test", "qa", "stage",
    "staging", "uat", "demo", "beta", "old", "new", "blog", "shop", "store", "cdn",
    "static", "assets", "img", "media", "files", "docs", "wiki", "git", "gitlab", "jenkins",
    "ci", "jira", "confluence", "grafana", "kibana", "monitor", "status", "support", "help",
    "crm", "erp", "intranet", "internal", "db", "sql", "mysql", "auth", "sso", "login",
    "secure", "m", "mobile", "ws", "proxy", "gateway", "backup", "cloud", "autodiscover",
)  # fmt: skip


class DnsBruteScanner(BaseScanner):
    """Active subdomain discovery: resolve a small wordlist of common names.

    Skipped when the domain has a wildcard record, since every guess would "resolve".
    """

    name = "dns-brute"

    def __init__(self, settings: Settings | None = None, words: tuple[str, ...] = WORDLIST) -> None:
        super().__init__(settings)
        self._words = words

    async def scan(self, domain: str) -> ScanResult:
        domain = normalize_domain(domain)
        started = datetime.now(UTC)
        errors: list[str] = []
        subdomains: list[Subdomain] = []

        probe = f"easm-{secrets.token_hex(6)}.{domain}"
        if await resolve_host(probe, self.settings.dns_timeout):
            errors.append(f"dns-brute: wildcard DNS on {domain}, skipped")
            logger.info("dns-brute: wildcard record for {}, skipping", domain)
        else:
            resolved = await resolve_many(
                [f"{w}.{domain}" for w in self._words],
                self.settings.dns_concurrency,
                self.settings.dns_timeout,
            )
            subdomains = [
                Subdomain(name=name, sources={"dns-brute"}, ips=ips, is_active=True)
                for name, ips in sorted(resolved.items())
                if ips
            ]
        return ScanResult(
            scanner=self.name,
            domain=domain,
            started_at=started,
            finished_at=datetime.now(UTC),
            subdomains=subdomains,
            errors=errors,
        )
