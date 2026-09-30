import httpx
import respx

from easm.core.config import Settings
from easm.core.models import Service, Subdomain
from easm.scanners.exposures import (
    Baseline,
    ExposureScanner,
    Probe,
    matches_baseline,
    validate_backup_zip,
    validate_env,
    validate_git_head,
    validate_robots,
)

BASE = "https://www.example.com"
SOFT_404_HTML = "<html><title>Oops</title><body>" + "Page not found. " * 60 + "</body></html>"


def _scanner() -> ExposureScanner:
    host = Subdomain(
        name="www.example.com",
        services=[Service(port=443, scheme="https", url=f"{BASE}/", status_code=200)],
    )
    return ExposureScanner(Settings(), hosts=[host])


def _probe(text: str | bytes, status: int = 200) -> Probe:
    body = text.encode() if isinstance(text, str) else text
    return Probe(status, body, "text/plain")


def test_validators() -> None:
    assert validate_git_head(_probe("ref: refs/heads/main\n"))
    assert validate_git_head(_probe("<html>ref: refs/</html>")) is None
    evidence = validate_env(_probe("DB_PASSWORD=hunter2\nAPI_KEY=abc\n"))
    assert evidence and "DB_PASSWORD=***" in evidence and "hunter2" not in evidence
    assert validate_env(_probe("<!doctype html><html>a=b</html>")) is None
    assert validate_env(_probe("just some text")) is None
    assert validate_robots(_probe("User-agent: *\nDisallow: /admin"))
    assert validate_robots(_probe("<html>nope</html>")) is None
    assert validate_backup_zip(_probe(b"PK\x03\x04rest"))
    assert validate_backup_zip(_probe("<html>not a zip</html>")) is None


def test_matches_baseline() -> None:
    body = SOFT_404_HTML.encode()
    base = Baseline(200, len(body), "x")
    assert matches_baseline(base, _probe(body + b"1234"), "tok")  # near-equal size
    assert not matches_baseline(base, _probe(b"ref: refs/heads/main\n"), "tok")
    assert not matches_baseline(Baseline(404, 10, "x"), _probe(body), "tok")  # real 404s
    assert not matches_baseline(None, _probe(body), "tok")


@respx.mock
async def test_detects_real_exposures_on_normal_404_server() -> None:
    respx.get(url__regex=rf"{BASE}/easm-probe-404-test-.*").mock(return_value=httpx.Response(404))
    respx.get(f"{BASE}/.git/HEAD").mock(return_value=httpx.Response(200, text="ref: refs/heads/x"))
    respx.get(f"{BASE}/.env").mock(return_value=httpx.Response(200, text="SECRET_KEY=abc123\n"))
    respx.get(f"{BASE}/backup.zip").mock(return_value=httpx.Response(200, content=b"PK\x03\x04zz"))
    respx.get(f"{BASE}/robots.txt").mock(return_value=httpx.Response(200, text="Disallow: /a"))
    respx.get(f"{BASE}/web.config").mock(return_value=httpx.Response(404))
    respx.get(f"{BASE}/.well-known/security.txt").mock(return_value=httpx.Response(403))
    respx.get(url__regex=rf"{BASE}/.*").mock(return_value=httpx.Response(404))

    result = await _scanner().scan("example.com")
    by_check = {f.check: f for f in result.findings}
    assert set(by_check) == {"git-head", "env-file", "backup-zip", "robots-txt"}
    assert by_check["git-head"].severity == "critical"
    assert "abc123" not in by_check["env-file"].evidence  # secret values are redacted
    assert [f.severity for f in result.findings][:2] == ["critical", "critical"]  # sorted


@respx.mock
async def test_soft_404_catch_all_yields_no_false_positives() -> None:
    # Every path (including the random probe) returns the same 200 page.
    respx.get(url__regex=rf"{BASE}/.*").mock(return_value=httpx.Response(200, html=SOFT_404_HTML))
    result = await _scanner().scan("example.com")
    assert result.findings == []


@respx.mock
async def test_real_file_found_behind_soft_404_server() -> None:
    # first matching route wins, so the specific one is registered first
    respx.get(f"{BASE}/.git/HEAD").mock(
        return_value=httpx.Response(200, text="ref: refs/heads/main\n")
    )
    respx.get(url__regex=rf"{BASE}/.*").mock(return_value=httpx.Response(200, html=SOFT_404_HTML))
    result = await _scanner().scan("example.com")
    assert [f.check for f in result.findings] == ["git-head"]  # short real file not swallowed


@respx.mock
async def test_html_catch_all_with_env_like_text_is_rejected() -> None:
    # Different size from the baseline, so only the content validator can save us.
    respx.get(url__regex=rf"{BASE}/easm-probe-404-test-.*").mock(
        return_value=httpx.Response(200, html=SOFT_404_HTML)
    )
    respx.get(f"{BASE}/.env").mock(
        return_value=httpx.Response(200, html="<html><body>a=b</body></html>")
    )
    respx.get(url__regex=rf"{BASE}/(?!easm|\.env).*").mock(return_value=httpx.Response(404))
    assert (await _scanner().scan("example.com")).findings == []


@respx.mock
async def test_network_errors_do_not_crash_and_inputs_not_mutated() -> None:
    respx.get(url__regex=rf"{BASE}/.*").mock(side_effect=httpx.ConnectTimeout("t"))
    scanner = _scanner()
    result = await scanner.scan("example.com")
    assert result.findings == []
    assert scanner._hosts[0].services[0].exposures == []
