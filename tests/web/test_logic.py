from datetime import UTC, datetime

import pytest
from pytest import MonkeyPatch

from easm.core.config import Settings
from easm.core.models import ExposureFinding, ScanResult, Service, Subdomain
from easm.core.risk import risk_label, risk_score
from easm.scanners.exposures import ExposureScanner
from easm.scanners.services import ServiceScanner
from easm.web import logic
from easm.web.logic import (
    ScanOptions,
    finding_rows,
    open_port_count,
    port_rows,
    run_scan,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _finding(severity: str = "critical") -> ExposureFinding:
    return ExposureFinding.model_validate(
        {
            "check": "env-file",
            "url": "https://www.example.com/.env",
            "path": "/.env",
            "severity": severity,
            "evidence": "1 KEY=***",
            "status_code": 200,
        }
    )


def _result(*findings: ExposureFinding, name: str = "www.example.com") -> ScanResult:
    svc = Service(
        port=443,
        scheme="https",
        url="https://www.example.com/",
        status_code=200,
        server="nginx",
        exposures=list(findings),
    )
    host = Subdomain(name=name, is_active=True, open_ports=[80, 443], services=[svc])
    return ScanResult(
        scanner="t", domain="example.com", started_at=NOW, finished_at=NOW, subdomains=[host]
    )


def test_risk_score_and_label() -> None:
    assert risk_score(_result()) == 0
    assert risk_label(0) == "Clean"
    assert risk_score(_result(_finding("critical"), _finding("high"))) == 60
    assert risk_score(_result(*[_finding("critical")] * 5)) == 100
    assert risk_label(100) == "Critical"
    assert risk_label(20) == "Medium"


def test_tables() -> None:
    result = _result(_finding())
    assert open_port_count(result) == 2
    rows = port_rows(result)
    assert [r["Port"] for r in rows] == [80, 443]
    assert rows[0]["Service"] == "tcp"
    assert rows[1]["Server"] == "nginx"
    assert finding_rows(result)[0]["Severity"] == "CRITICAL"


def test_options_imply_services() -> None:
    assert ScanOptions(ports=False, exposures=True).needs_services
    assert not ScanOptions(ports=False, exposures=False).needs_services


@pytest.fixture
def mock_scanners(monkeypatch: MonkeyPatch) -> list[str]:
    calls: list[str] = []
    full = _result(_finding())  # ExposureScanner result

    async def discover(domain: str, settings: Settings) -> ScanResult:
        calls.append("discover")
        return ScanResult(
            scanner="discovery",
            domain=domain,
            started_at=NOW,
            finished_at=NOW,
            subdomains=[Subdomain(name="www.example.com", is_active=True)],
        )

    async def services(self: ServiceScanner, domain: str) -> ScanResult:
        calls.append("services")
        assert self._hosts
        return _result(_finding(), name=self._hosts[0].name)

    async def exposures(self: ExposureScanner, domain: str) -> ScanResult:
        calls.append("exposures")
        return full

    monkeypatch.setattr(logic, "discover_subdomains", discover)
    monkeypatch.setattr(ServiceScanner, "scan", services)
    monkeypatch.setattr(ExposureScanner, "scan", exposures)
    return calls


async def test_run_scan_all_modules(mock_scanners: list[str]) -> None:
    updates: list[tuple[float, str]] = []
    result = await run_scan(
        "example.com", ScanOptions(), Settings(), lambda f, m: updates.append((f, m))
    )
    assert mock_scanners == ["discover", "services", "exposures"]
    assert len(result.findings) == 1
    fractions = [f for f, _ in updates]
    assert fractions == sorted(fractions) and fractions[-1] == 1.0


async def test_run_scan_skips_unselected(mock_scanners: list[str]) -> None:
    opts = ScanOptions(subdomains=False, ports=True, exposures=False)
    result = await run_scan("example.com", opts, Settings())
    assert mock_scanners == ["services"]
    assert result.findings[0].check == "env-file"


async def test_demo_scan_finds_many_exposures() -> None:
    from easm.web.demo import DEMO_DOMAIN

    result = await run_scan(DEMO_DOMAIN, ScanOptions(), Settings())
    checks = {f.check for f in result.findings}
    assert {"git-head", "env-file", "backup-zip", "web-config", "robots-txt"} <= checks
    assert {"open-port-3389", "open-port-6379", "open-port-22"} <= checks
    assert risk_score(result) == 100
    assert len(result.subdomains) >= 6
