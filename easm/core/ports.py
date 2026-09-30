from dataclasses import dataclass
from typing import Final

from easm.core.models import ExposureFinding, Severity

WEB_PORTS: Final[tuple[int, ...]] = (80, 443, 8080, 8443)


@dataclass(frozen=True)
class RiskyPort:
    """A non-web service that should rarely be reachable from the internet."""

    service: str
    severity: Severity
    remediation: str


_DB = "Do not expose databases to the internet: bind to a private interface or firewall the port."
_REMOTE = "Restrict remote administration to a VPN or allow-listed addresses and enforce MFA."

RISKY_PORTS: Final[dict[int, RiskyPort]] = {
    21: RiskyPort("FTP", "medium", "Replace FTP with SFTP/FTPS and restrict access by address."),
    22: RiskyPort("SSH", "low", "Allow SSH only from trusted addresses; disable password logins."),
    23: RiskyPort("Telnet", "high", "Disable Telnet (cleartext) and use SSH behind a VPN."),
    25: RiskyPort("SMTP", "low", "Ensure the mail server is not an open relay; require TLS/auth."),
    445: RiskyPort(
        "SMB", "critical", "Never expose SMB to the internet; block it at the firewall."
    ),
    1433: RiskyPort("MSSQL", "high", _DB),
    3306: RiskyPort("MySQL", "high", _DB),
    3389: RiskyPort("RDP", "critical", _REMOTE),
    5432: RiskyPort("PostgreSQL", "high", _DB),
    5900: RiskyPort("VNC", "high", _REMOTE),
    6379: RiskyPort("Redis", "critical", _DB + " Redis has no authentication by default."),
    9200: RiskyPort("Elasticsearch", "high", _DB),
    27017: RiskyPort("MongoDB", "critical", _DB),
}
PORT_CHECK_PREFIX: Final = "open-port-"

DEFAULT_SCAN_PORTS: Final[tuple[int, ...]] = (*WEB_PORTS, *RISKY_PORTS)


def port_exposure(host: str, port: int, banner: str | None) -> ExposureFinding | None:
    """Finding for an open risky port (None for ports that are not risky)."""
    risky = RISKY_PORTS.get(port)
    if risky is None:
        return None
    evidence = f"{risky.service} reachable from the internet"
    if banner:
        evidence += f", banner: {banner}"
    return ExposureFinding(
        check=f"{PORT_CHECK_PREFIX}{port}",
        url=f"tcp://{host}:{port}",
        path="",
        severity=risky.severity,
        evidence=evidence,
        status_code=0,
    )


def port_remediation(check: str) -> str | None:
    """Remediation text for an `open-port-N` check id, or None for other checks."""
    if not check.startswith(PORT_CHECK_PREFIX):
        return None
    try:
        risky = RISKY_PORTS.get(int(check.removeprefix(PORT_CHECK_PREFIX)))
    except ValueError:
        return None
    return risky.remediation if risky else None
