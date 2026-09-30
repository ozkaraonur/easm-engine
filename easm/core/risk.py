import re
from typing import Final, NamedTuple

from easm.core.models import ScanResult, Severity

SEVERITY_WEIGHTS: Final[dict[Severity, int]] = {
    "critical": 40,
    "high": 20,
    "medium": 8,
    "low": 2,
    "info": 0,
}
TLS_WEIGHT: Final = 10
OUTDATED_WEIGHT: Final = 5

# (product regex, predicate on the captured version tuple) for end-of-life server software.
_OUTDATED: Final[tuple[tuple[re.Pattern[str], int, int], ...]] = (
    (re.compile(r"apache/(\d+)\.(\d+)", re.IGNORECASE), 2, 4),  # Apache < 2.4
    (re.compile(r"nginx/(\d+)\.(\d+)", re.IGNORECASE), 1, 18),  # nginx < 1.18
    (re.compile(r"microsoft-iis/(\d+)\.(\d+)", re.IGNORECASE), 10, 0),  # IIS < 10
    (re.compile(r"php/(\d+)\.(\d+)", re.IGNORECASE), 8, 0),  # PHP < 8.0
)


class Weakness(NamedTuple):
    host: str
    kind: str
    detail: str


def outdated_server(server: str | None) -> bool:
    """True if a Server header names software older than a known end-of-life threshold."""
    if not server:
        return False
    for pattern, major_min, minor_min in _OUTDATED:
        for match in pattern.finditer(server):
            if (int(match[1]), int(match[2])) < (major_min, minor_min):
                return True
    return False


def weaknesses(result: ScanResult) -> list[Weakness]:
    """Non-file weaknesses found on web services: invalid TLS and outdated server software."""
    found: list[Weakness] = []
    for host in result.subdomains:
        for svc in host.services:
            if svc.tls_valid is False:
                found.append(Weakness(host.name, "Invalid TLS", svc.tls_error or svc.url))
            if outdated_server(svc.server):
                found.append(Weakness(host.name, "Outdated server", svc.server or ""))
    return found


def risk_score(result: ScanResult) -> int:
    """0 (clean) to 100 (critical): findings, invalid TLS and outdated software, capped."""
    score = sum(SEVERITY_WEIGHTS[f.severity] for f in result.findings)
    for weakness in weaknesses(result):
        score += TLS_WEIGHT if weakness.kind == "Invalid TLS" else OUTDATED_WEIGHT
    return min(100, score)


def risk_label(score: int) -> str:
    for threshold, label in ((70, "Critical"), (40, "High"), (15, "Medium"), (1, "Low")):
        if score >= threshold:
            return label
    return "Clean"
