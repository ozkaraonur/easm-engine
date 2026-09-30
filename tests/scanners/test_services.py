import asyncio
import ssl

import httpx
import pytest
import respx

from easm.core.config import Settings
from easm.core.models import Subdomain
from easm.core.portcheck import check_port, scan_ports
from easm.scanners import services as services_mod
from easm.scanners.services import ServiceScanner, build_url, extract_title, tls_error_of


def test_extract_title() -> None:
    assert extract_title("<html><TITLE>\n Hello &amp;  World </TITLE>") == "Hello & World"
    assert extract_title("<html></html>") is None
    assert extract_title("<title>  </title>") is None


def test_build_url() -> None:
    assert build_url("https", "a.com", 443) == "https://a.com/"
    assert build_url("http", "a.com", 8080) == "http://a.com:8080/"


async def test_port_check_against_local_server() -> None:
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = server.sockets[0].getsockname()[1]
    async with server:
        assert await check_port("127.0.0.1", open_port, timeout=1)
    # server closed -> port now refuses connections
    assert not await check_port("127.0.0.1", open_port, timeout=1)
    assert await scan_ports("127.0.0.1", [open_port], timeout=1) == []


@pytest.fixture
def fake_open_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _scan(host: str, ports: list[int], timeout: float = 3.0) -> list[int]:
        return [p for p in ports if p in (80, 443)]

    monkeypatch.setattr(services_mod, "scan_ports", _scan)


def _scanner() -> ServiceScanner:
    return ServiceScanner(Settings(), hosts=[Subdomain(name="www.example.com", is_active=True)])


@respx.mock
async def test_scan_collects_http_and_https_info(fake_open_ports: None) -> None:
    respx.get("http://www.example.com/").mock(
        return_value=httpx.Response(301, headers={"Server": "nginx"}, text="<title>Moved</title>")
    )
    respx.get("https://www.example.com/").mock(
        return_value=httpx.Response(
            200, headers={"Server": "cloudflare"}, html="<title>Example Domain</title>"
        )
    )
    result = await _scanner().scan("example.com")
    host = result.subdomains[0]
    assert host.open_ports == [80, 443]
    by_port = {s.port: s for s in host.services}
    assert by_port[80].status_code == 301 and by_port[80].tls_valid is None
    assert by_port[443].title == "Example Domain"
    assert by_port[443].server == "cloudflare"
    assert by_port[443].tls_valid is True


def test_tls_error_of_walks_chain_and_survives_cycles() -> None:
    inner = ssl.SSLCertVerificationError("expired")
    outer = httpx.ConnectError("tls")
    outer.__cause__ = inner
    assert tls_error_of(outer) is inner
    assert tls_error_of(httpx.ConnectError("refused")) is None
    a, b = RuntimeError("a"), RuntimeError("b")
    a.__cause__, b.__cause__ = b, a
    assert tls_error_of(a) is None  # must terminate


async def test_invalid_certificate_is_flagged_and_still_probed(
    fake_open_ports: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    https_calls: list[httpx.AsyncClient] = []

    async def fake_get(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response, str]:
        if url.startswith("https"):
            https_calls.append(client)
        if url.startswith("https") and len(https_calls) == 1:  # verifying client goes first
            raise httpx.ConnectError("tls") from ssl.SSLCertVerificationError("expired")
        return httpx.Response(200), "<title>Bad</title>"

    monkeypatch.setattr(ServiceScanner, "_get", staticmethod(fake_get))
    result = await _scanner().scan("example.com")
    https = next(s for s in result.subdomains[0].services if s.scheme == "https")
    assert https.tls_valid is False
    assert https.tls_error is not None and "expired" in https.tls_error
    assert https.title == "Bad"
    assert https_calls[0] is not https_calls[1]  # retried with the non-verifying client


@respx.mock
async def test_unreachable_web_service_is_skipped(fake_open_ports: None) -> None:
    respx.get("http://www.example.com/").mock(side_effect=httpx.ConnectTimeout("t"))
    respx.get("https://www.example.com/").mock(side_effect=httpx.ConnectError("refused"))
    result = await _scanner().scan("example.com")
    assert result.subdomains[0].open_ports == [80, 443]
    assert result.subdomains[0].services == []


async def test_input_hosts_are_not_mutated(fake_open_ports: None) -> None:
    host = Subdomain(name="www.example.com")
    with respx.mock:
        respx.get(url__regex=r".*").mock(return_value=httpx.Response(200))
        await ServiceScanner(Settings(), hosts=[host]).scan("example.com")
    assert host.open_ports == [] and host.services == []


async def test_risky_ports_get_banner_and_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _scan(host: str, ports: list[int], timeout: float = 3.0) -> list[int]:
        return [22, 3389]

    async def _banner(host: str, port: int, timeout: float = 3.0) -> str | None:
        return "SSH-2.0-OpenSSH_7.4" if port == 22 else None

    monkeypatch.setattr(services_mod, "scan_ports", _scan)
    monkeypatch.setattr(services_mod, "grab_banner", _banner)
    result = await _scanner().scan("example.com")
    host = result.subdomains[0]
    assert host.banners == {22: "SSH-2.0-OpenSSH_7.4"}
    assert {f.check: f.severity for f in host.port_exposures} == {
        "open-port-22": "low",
        "open-port-3389": "critical",
    }
    assert "SSH-2.0-OpenSSH_7.4" in host.port_exposures[0].evidence
