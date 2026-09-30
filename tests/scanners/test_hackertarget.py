import httpx
import respx

from easm.core.config import Settings
from easm.scanners.hackertarget import HACKERTARGET_URL, HackerTargetScanner, parse_hostsearch


def test_parse_hostsearch_filters_scope_and_noise() -> None:
    text = (
        "www.example.com,1.2.3.4\napi.example.com,5.6.7.8\n"
        "WWW.example.com,1.2.3.4\nevil.com,9.9.9.9\n"
    )
    subs = parse_hostsearch(text, "example.com")
    assert [s.name for s in subs] == ["api.example.com", "www.example.com"]
    assert subs[1].ips == ["1.2.3.4"] and subs[1].sources == {"hackertarget"}
    assert parse_hostsearch("error check your search parameter", "example.com") == []


@respx.mock
async def test_scan_success() -> None:
    respx.get(HACKERTARGET_URL).mock(
        return_value=httpx.Response(200, text="dev.example.com,1.1.1.1\n")
    )
    result = await HackerTargetScanner(Settings()).scan("example.com")
    assert [s.name for s in result.subdomains] == ["dev.example.com"]
    assert not result.errors


@respx.mock
async def test_scan_rate_limited_and_network_error() -> None:
    route = respx.get(HACKERTARGET_URL).mock(
        return_value=httpx.Response(200, text="API count exceeded - Increase Quota")
    )
    limited = await HackerTargetScanner(Settings()).scan("example.com")
    assert limited.subdomains == [] and "hackertarget" in limited.errors[0]

    route.mock(side_effect=httpx.ConnectTimeout("t"))
    failed = await HackerTargetScanner(Settings()).scan("example.com")
    assert failed.subdomains == [] and failed.errors
