from datetime import UTC, datetime

from easm.core.models import ScanResult, Service, Subdomain
from easm.core.ports import port_exposure
from easm.core.risk import outdated_server, risk_score, weaknesses

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _result(*hosts: Subdomain) -> ScanResult:
    return ScanResult(
        scanner="t", domain="example.com", started_at=NOW, finished_at=NOW, subdomains=list(hosts)
    )


def _svc(server: str | None, tls_valid: bool | None = None) -> Service:
    return Service(
        port=443,
        scheme="https",
        url="https://a/",
        server=server,
        tls_valid=tls_valid,
        tls_error="expired" if tls_valid is False else None,
    )


def test_outdated_server() -> None:
    assert outdated_server("Apache/2.2.15 (CentOS)")
    assert outdated_server("nginx/1.14.0")
    assert outdated_server("Microsoft-IIS/8.5")
    assert outdated_server("Apache/2.4.58 PHP/5.6.40")
    assert not outdated_server("nginx/1.25.3")
    assert not outdated_server("Apache/2.4.58")
    assert not outdated_server("cloudflare")
    assert not outdated_server(None)


def test_weaknesses_and_score() -> None:
    host = Subdomain(
        name="a.example.com",
        services=[_svc("nginx/1.14.0", tls_valid=False), _svc("nginx/1.25.0", tls_valid=True)],
    )
    kinds = [w.kind for w in weaknesses(_result(host))]
    assert kinds == ["Invalid TLS", "Outdated server"]
    assert risk_score(_result(host)) == 15  # 10 (TLS) + 5 (outdated)


def test_risky_port_findings_count_toward_score() -> None:
    finding = port_exposure("db.example.com", 3389, None)
    assert finding
    host = Subdomain(name="db.example.com", open_ports=[3389], port_exposures=[finding])
    result = _result(host)
    assert [f.check for f in result.findings] == ["open-port-3389"]
    assert risk_score(result) == 40
