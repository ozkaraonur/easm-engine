from datetime import UTC, datetime

import pytest

from easm import pipeline
from easm.core.config import Settings
from easm.core.models import ExposureFinding, ScanResult, Service, Subdomain
from easm.scanners.crtsh import CrtShScanner
from easm.scanners.dnsbrute import DnsBruteScanner
from easm.scanners.exposures import ExposureScanner
from easm.scanners.hackertarget import HackerTargetScanner

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _res(scanner: str, *subs: Subdomain, errors: list[str] | None = None) -> ScanResult:
    return ScanResult(
        scanner=scanner,
        domain="example.com",
        started_at=NOW,
        finished_at=NOW,
        subdomains=list(subs),
        errors=errors or [],
    )


def test_merge_subdomains_unions_sources_and_metadata() -> None:
    crt = Subdomain(name="www.example.com", sources={"crtsh"}, first_seen=NOW, issuers={"LE"})
    ht = Subdomain(name="www.example.com", sources={"hackertarget"})
    only_dns = Subdomain(name="vpn.example.com", sources={"dns-brute"})
    merged = pipeline.merge_subdomains([_res("a", crt), _res("b", ht, only_dns)])
    assert [s.name for s in merged] == ["vpn.example.com", "www.example.com"]
    assert merged[1].sources == {"crtsh", "hackertarget"}
    assert merged[1].first_seen == NOW and merged[1].issuers == {"LE"}


async def _no_dns(names: list[str], concurrency: int, timeout: float) -> dict[str, list[str]]:
    return {"www.example.com": ["1.1.1.1"]}


async def test_discover_subdomains_merges_sources_and_survives_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def crtsh(self: CrtShScanner, domain: str) -> ScanResult:
        return _res("crtsh", errors=["crtsh: timeout"])  # crt.sh is down

    async def ht(self: HackerTargetScanner, domain: str) -> ScanResult:
        return _res("ht", Subdomain(name="www.example.com", sources={"hackertarget"}))

    async def brute(self: DnsBruteScanner, domain: str) -> ScanResult:
        return _res("brute", Subdomain(name="vpn.example.com", sources={"dns-brute"}))

    monkeypatch.setattr(CrtShScanner, "scan", crtsh)
    monkeypatch.setattr(HackerTargetScanner, "scan", ht)
    monkeypatch.setattr(DnsBruteScanner, "scan", brute)
    monkeypatch.setattr(pipeline, "resolve_many", _no_dns)

    result = await pipeline.discover_subdomains("example.com", Settings())
    assert {s.name: s.is_active for s in result.subdomains} == {
        "vpn.example.com": False,
        "www.example.com": True,
    }
    assert result.errors == ["crtsh: timeout"]


async def test_discover_respects_disabled_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    async def crtsh(self: CrtShScanner, domain: str) -> ScanResult:
        return _res("crtsh")

    async def boom(self: object, domain: str) -> ScanResult:
        raise AssertionError("disabled source must not run")

    monkeypatch.setattr(CrtShScanner, "scan", crtsh)
    monkeypatch.setattr(HackerTargetScanner, "scan", boom)
    monkeypatch.setattr(DnsBruteScanner, "scan", boom)
    monkeypatch.setattr(pipeline, "resolve_many", _no_dns)
    settings = Settings(hackertarget_enabled=False, dns_brute_enabled=False)
    await pipeline.discover_subdomains("example.com", settings)


async def test_probe_exposures_keeps_hosts_without_web_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = ExposureFinding(
        check="env-file",
        url="https://w/.env",
        path="/.env",
        severity="critical",
        evidence="x",
        status_code=200,
    )

    async def scan(self: ExposureScanner, domain: str) -> ScanResult:
        host = self._hosts[0].model_copy(deep=True)
        host.services[0].exposures = [finding]
        return _res("exposures", host)

    monkeypatch.setattr(ExposureScanner, "scan", scan)
    web = Subdomain(
        name="w.example.com", services=[Service(port=443, scheme="https", url="https://w/")]
    )
    mail = Subdomain(name="mail.example.com", open_ports=[25])
    result = await pipeline.probe_exposures(_res("services", web, mail), Settings())
    assert [h.name for h in result.subdomains] == ["w.example.com", "mail.example.com"]
    assert len(result.findings) == 1
