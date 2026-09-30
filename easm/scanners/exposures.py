import asyncio
import hashlib
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
from loguru import logger

from easm.core.base import BaseScanner
from easm.core.config import Settings
from easm.core.models import ExposureFinding, ScanResult, Service, Severity, Subdomain

MAX_BODY_BYTES = 64 * 1024
_ENV_LINE_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(\S.*)$", re.MULTILINE)
_ROBOTS_RE = re.compile(
    r"^\s*(user-agent|disallow|allow|sitemap)\s*:", re.IGNORECASE | re.MULTILINE
)
_ZIP_MAGIC = b"PK\x03\x04"


@dataclass(frozen=True)
class Probe:
    """A raw HTTP response reduced to what the validators need."""

    status: int
    body: bytes
    content_type: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class Check:
    """One exposure check: a path plus a validator returning evidence or None."""

    id: str
    path: str
    severity: Severity
    validate: Callable[[Probe], str | None]


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:200].lower()
    return head.startswith(("<!doctype html", "<html", "<head", "<body")) or "<html" in head


def validate_git_head(probe: Probe) -> str | None:
    first = probe.text.strip().splitlines()[0] if probe.text.strip() else ""
    if re.fullmatch(r"ref:\s*refs/\S+", first):
        return f"repository HEAD readable: {first}"
    return None


def validate_env(probe: Probe) -> str | None:
    text = probe.text
    if _looks_like_html(text):
        return None
    entries = _ENV_LINE_RE.findall(text)
    if not entries:
        return None
    keys = ", ".join(f"{k}=***" for k, _ in entries[:5])  # values are never reported
    more = f" (+{len(entries) - 5} more)" if len(entries) > 5 else ""
    return f"{len(entries)} KEY=VALUE entries: {keys}{more}"


def validate_robots(probe: Probe) -> str | None:
    if _looks_like_html(probe.text):
        return None
    hits = _ROBOTS_RE.findall(probe.text)
    return f"{len(hits)} robots directives" if hits else None


def validate_security_txt(probe: Probe) -> str | None:
    if _looks_like_html(probe.text):
        return None
    match = re.search(r"^\s*contact\s*:\s*(\S.*)$", probe.text, re.IGNORECASE | re.MULTILINE)
    return f"security contact published: {match.group(1).strip()[:100]}" if match else None


def validate_backup_zip(probe: Probe) -> str | None:
    if probe.body.startswith(_ZIP_MAGIC):
        return "ZIP archive signature (PK\\x03\\x04) in response body"
    return None


def validate_web_config(probe: Probe) -> str | None:
    if re.search(r"<configuration[\s>]", probe.text, re.IGNORECASE):
        return "IIS/ASP.NET <configuration> XML readable"
    return None


def _plain(probe: Probe) -> str | None:
    """Body text, or None when the response is an HTML page (usually a soft-404/login)."""
    return None if _looks_like_html(probe.text) else probe.text


def _regex_validator(pattern: str, evidence: str, flags: int = 0) -> Callable[[Probe], str | None]:
    """Non-HTML body that matches `pattern` -> fixed evidence text (never echoes content)."""
    compiled = re.compile(pattern, flags)

    def validate(probe: Probe) -> str | None:
        text = _plain(probe)
        return evidence if text is not None and compiled.search(text) else None

    return validate


def _magic_validator(magic: bytes, evidence: str) -> Callable[[Probe], str | None]:
    return lambda probe: evidence if probe.body.startswith(magic) else None


def _contains_validator(needle: str, evidence: str) -> Callable[[Probe], str | None]:
    return lambda probe: evidence if needle in probe.text else None


def validate_phpinfo(probe: Probe) -> str | None:
    if re.search(r"<title>\s*phpinfo\(\)|PHP Version\s*</?(?:td|h1)", probe.text, re.IGNORECASE):
        return "phpinfo() page discloses PHP configuration and environment"
    return None


def validate_dir_listing(probe: Probe) -> str | None:
    if re.search(r"<title>\s*Index of /", probe.text, re.IGNORECASE):
        return "directory listing enabled"
    return None


def validate_phpmyadmin(probe: Probe) -> str | None:
    if re.search(r"<title>[^<]*phpMyAdmin", probe.text, re.IGNORECASE):
        return "phpMyAdmin login page reachable"
    return None


def validate_swagger(probe: Probe) -> str | None:
    if re.search(r'"(?:swagger|openapi)"\s*:\s*"[23]', probe.text):
        return "OpenAPI/Swagger definition publicly readable"
    return None


def validate_actuator_env(probe: Probe) -> str | None:
    if '"propertySources"' in probe.text or '"activeProfiles"' in probe.text:
        return "Spring Boot actuator /env readable (configuration and secrets metadata)"
    return None


_DUMP_RE = r"(?:CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS)\s"
_HTPASSWD_RE = r"^[\w.@-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\})"
_SQLITE = b"SQLite format 3"
_SQL_DUMP = _regex_validator(_DUMP_RE, "SQL dump readable")

CHECKS: tuple[Check, ...] = (
    Check("git-head", "/.git/HEAD", "critical", validate_git_head),
    Check("env-file", "/.env", "critical", validate_env),
    Check(
        "git-config",
        "/.git/config",
        "critical",
        _regex_validator(r"^\[core\]", "git config readable", re.MULTILINE),
    ),
    Check(
        "ssh-private-key",
        "/.ssh/id_rsa",
        "critical",
        _regex_validator(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key material readable"),
    ),
    Check(
        "aws-credentials",
        "/.aws/credentials",
        "critical",
        _regex_validator(r"aws_access_key_id\s*=", "AWS credentials file readable (values hidden)"),
    ),
    Check(
        "wp-config-backup",
        "/wp-config.php.bak",
        "critical",
        _regex_validator(r"DB_PASSWORD", "WordPress config backup readable (values hidden)"),
    ),
    Check("sql-dump", "/dump.sql", "critical", _SQL_DUMP),
    Check("database-sql", "/database.sql", "critical", _SQL_DUMP),
    Check("backup-sql", "/backup.sql", "critical", _SQL_DUMP),
    Check("backup-zip", "/backup.zip", "high", validate_backup_zip),
    Check(
        "backup-targz",
        "/backup.tar.gz",
        "high",
        _magic_validator(b"\x1f\x8b", "gzip archive signature in response body"),
    ),
    Check(
        "htpasswd",
        "/.htpasswd",
        "high",
        _regex_validator(_HTPASSWD_RE, "htpasswd credential hashes readable", re.MULTILINE),
    ),
    Check(
        "sqlite-database",
        "/db.sqlite3",
        "high",
        _magic_validator(_SQLITE, "SQLite database file downloadable"),
    ),
    Check(
        "svn-database",
        "/.svn/wc.db",
        "high",
        _magic_validator(_SQLITE, "Subversion working-copy database readable"),
    ),
    Check("actuator-env", "/actuator/env", "high", validate_actuator_env),
    Check(
        "npmrc",
        "/.npmrc",
        "high",
        _regex_validator(r"_authToken\s*=", "npm auth token file readable (values hidden)"),
    ),
    Check("phpinfo", "/phpinfo.php", "medium", validate_phpinfo),
    Check("phpinfo-info", "/info.php", "medium", validate_phpinfo),
    Check(
        "server-status",
        "/server-status",
        "medium",
        _contains_validator("Apache Server Status", "Apache mod_status page readable"),
    ),
    Check("dir-listing", "/backup/", "medium", validate_dir_listing),
    Check("dir-listing-uploads", "/uploads/", "medium", validate_dir_listing),
    Check("phpmyadmin", "/phpmyadmin/", "medium", validate_phpmyadmin),
    Check("web-config", "/web.config", "medium", validate_web_config),
    Check(
        "ds-store",
        "/.DS_Store",
        "low",
        _magic_validator(b"\x00\x00\x00\x01Bud1", "macOS .DS_Store leaks directory contents"),
    ),
    Check("swagger", "/swagger.json", "low", validate_swagger),
    Check("robots-txt", "/robots.txt", "info", validate_robots),
    Check("security-txt", "/.well-known/security.txt", "info", validate_security_txt),
)


@dataclass(frozen=True)
class Baseline:
    """How a service answers a path that cannot exist (soft-404 fingerprint)."""

    status: int
    length: int
    digest: str

    @property
    def is_soft_404(self) -> bool:
        return self.status == 200


def _digest(body: bytes, token: str) -> str:
    """Hash of the body with the probe token removed (pages often echo the URL)."""
    text = body.decode("utf-8", errors="replace").replace(token, "")
    return hashlib.sha256(text.encode()).hexdigest()


def matches_baseline(baseline: Baseline | None, probe: Probe, token: str) -> bool:
    """True if the response is just the server's catch-all page for unknown paths."""
    if baseline is None or not baseline.is_soft_404 or probe.status != baseline.status:
        return False
    if _digest(probe.body, token) == baseline.digest:
        return True
    # Dynamic catch-all pages differ slightly per request: allow 5% size drift, but only
    # for large pages so that short real files (e.g. .git/HEAD) are never swallowed.
    tolerance = baseline.length // 20 if baseline.length >= 512 else 0
    return abs(len(probe.body) - baseline.length) <= tolerance


class ExposureScanner(BaseScanner):
    """Looks for exposed sensitive files on the web services of a set of hosts.

    Services come from the constructor (wired by easm.pipeline / the CLI). Each
    service is first fingerprinted with a random non-existent path; responses
    that look like that catch-all page are discarded, and every finding must
    additionally pass a content validator, so soft-404s never become findings.
    """

    name = "exposures"

    def __init__(
        self,
        settings: Settings | None = None,
        hosts: list[Subdomain] | None = None,
        checks: tuple[Check, ...] = CHECKS,
    ) -> None:
        super().__init__(settings)
        self._hosts = hosts or []
        self._checks = checks

    async def scan(self, domain: str) -> ScanResult:
        domain = domain.strip().lower()
        started = datetime.now(UTC)
        hosts = [h.model_copy(deep=True) for h in self._hosts]
        sem = asyncio.Semaphore(self.settings.exposure_concurrency)

        async with httpx.AsyncClient(
            timeout=self.settings.exposure_http_timeout,
            headers={"User-Agent": self.settings.user_agent},
            verify=False,  # TLS validity is reported by the services scanner
        ) as client:
            services = [s for h in hosts for s in h.services]
            await asyncio.gather(*(self._scan_service(s, client, sem) for s in services))

        result = ScanResult(
            scanner=self.name,
            domain=domain,
            started_at=started,
            finished_at=datetime.now(UTC),
            subdomains=hosts,
        )
        logger.info(
            "exposures: {} findings across {} services", len(result.findings), len(services)
        )
        return result

    async def _scan_service(
        self,
        service: Service,
        client: httpx.AsyncClient,
        sem: asyncio.Semaphore,
    ) -> None:
        base = service.url.rstrip("/")
        token = f"easm-probe-404-test-{secrets.token_hex(6)}"
        baseline = await self._baseline(client, base, token, sem)

        async def run(check: Check) -> ExposureFinding | None:
            probe = await self._fetch(client, base + check.path, sem)
            if probe is None or probe.status != 200:
                return None
            if matches_baseline(baseline, probe, token):
                return None
            evidence = check.validate(probe)
            if evidence is None:
                return None
            return ExposureFinding(
                check=check.id,
                url=base + check.path,
                path=check.path,
                severity=check.severity,
                evidence=evidence,
                status_code=probe.status,
            )

        # No baseline (request failed) -> rely on the content validators alone.
        found = await asyncio.gather(*(run(c) for c in self._checks))
        service.exposures = [f for f in found if f is not None]

    async def _baseline(
        self, client: httpx.AsyncClient, base: str, token: str, sem: asyncio.Semaphore
    ) -> Baseline | None:
        probe = await self._fetch(client, f"{base}/{token}", sem)
        if probe is None:
            return None
        return Baseline(probe.status, len(probe.body), _digest(probe.body, token))

    @staticmethod
    async def _fetch(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> Probe | None:
        """GET without redirects, reading at most MAX_BODY_BYTES; None on network error."""
        async with sem:
            try:
                async with client.stream("GET", url, follow_redirects=False) as resp:
                    body = b""
                    async for chunk in resp.aiter_bytes():
                        body += chunk
                        if len(body) >= MAX_BODY_BYTES:
                            break
                    return Probe(
                        resp.status_code,
                        body[:MAX_BODY_BYTES],
                        resp.headers.get("content-type", ""),
                    )
            except httpx.HTTPError as exc:
                logger.debug("exposure request failed for {}: {!r}", url, exc)
                return None
