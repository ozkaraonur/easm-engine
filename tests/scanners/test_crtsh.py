import httpx
import pytest
import respx

from easm.core.config import Settings
from easm.core.utils import normalize_domain
from easm.scanners.crtsh import CRTSH_URL, CrtShScanner, parse_entries

SAMPLE = [
    {
        "name_value": "example.com\n*.example.com\nwww.example.com",
        "not_before": "2024-01-01T00:00:00",
        "not_after": "2024-04-01T00:00:00",
        "issuer_name": "C=US, O=LetsEncrypt, CN=R3",
    },
    {
        "name_value": "api.example.com\nevil.other.org",
        "not_before": "2023-06-01T00:00:00",
        "not_after": "2023-09-01T00:00:00",
        "issuer_name": "C=US, O=DigiCert",
    },
    {
        "name_value": "WWW.Example.com",
        "not_before": "2022-01-01T00:00:00",
        "not_after": "2025-01-01T00:00:00",
        "issuer_name": "X",
    },
]


def test_normalize_domain() -> None:
    assert normalize_domain("https://Example.COM:443/path") == "example.com"
    with pytest.raises(ValueError):
        normalize_domain("not a domain")


def test_parse_entries_dedupes_and_scopes() -> None:
    subs = {s.name: s for s in parse_entries(SAMPLE, "example.com")}
    assert set(subs) == {"example.com", "www.example.com", "api.example.com"}
    www = subs["www.example.com"]
    assert www.first_seen is not None and www.first_seen.year == 2022
    assert www.last_seen is not None and www.last_seen.year == 2025
    assert len(www.issuers) == 2


@respx.mock
async def test_scan_success() -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(200, json=SAMPLE))
    async with httpx.AsyncClient() as client:
        result = await CrtShScanner(client=client, resolve=False).scan("example.com")
    assert [s.name for s in result.subdomains] == [
        "api.example.com",
        "example.com",
        "www.example.com",
    ]
    assert result.errors == []


@respx.mock
async def test_scan_failure_returns_error_not_exception() -> None:
    respx.get(CRTSH_URL).mock(return_value=httpx.Response(503))
    settings = Settings(http_retries=1, retry_backoff=0)
    async with httpx.AsyncClient() as client:
        result = await CrtShScanner(settings, client=client, resolve=False).scan("example.com")
    assert result.subdomains == []
    assert len(result.errors) == 1
