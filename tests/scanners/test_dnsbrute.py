import pytest

from easm.core.config import Settings
from easm.scanners import dnsbrute
from easm.scanners.dnsbrute import DnsBruteScanner

LIVE = {"www.example.com": ["1.1.1.1"], "vpn.example.com": ["2.2.2.2"]}


@pytest.fixture
def fake_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def resolve_many(
        names: list[str], concurrency: int, timeout: float
    ) -> dict[str, list[str]]:
        return {n: LIVE.get(n, []) for n in names}

    async def resolve_host(name: str, timeout: float = 5.0) -> list[str]:
        return []  # no wildcard

    monkeypatch.setattr(dnsbrute, "resolve_many", resolve_many)
    monkeypatch.setattr(dnsbrute, "resolve_host", resolve_host)


async def test_finds_only_resolving_names(fake_dns: None) -> None:
    result = await DnsBruteScanner(Settings(), words=("www", "vpn", "nope")).scan("example.com")
    assert [s.name for s in result.subdomains] == ["vpn.example.com", "www.example.com"]
    assert all(s.is_active and s.sources == {"dns-brute"} for s in result.subdomains)


async def test_wildcard_dns_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    async def wildcard(name: str, timeout: float = 5.0) -> list[str]:
        return ["9.9.9.9"]

    monkeypatch.setattr(dnsbrute, "resolve_host", wildcard)
    result = await DnsBruteScanner(Settings(), words=("www",)).scan("example.com")
    assert result.subdomains == []
    assert "wildcard" in result.errors[0]
