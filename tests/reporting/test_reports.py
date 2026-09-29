from datetime import UTC, datetime, timedelta
from io import StringIO

from rich.console import Console

from easm.core.models import ExposureFinding, ScanResult, Service, Subdomain
from easm.reporting import render_dashboard, render_html, render_markdown, summarize

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _result() -> ScanResult:
    critical = ExposureFinding(
        check="env-file",
        url="https://www.example.com/.env",
        path="/.env",
        severity="critical",
        evidence="1 KEY=VALUE entries: <script>alert(1)</script>=***",
        status_code=200,
    )
    info = ExposureFinding(
        check="robots-txt",
        url="https://www.example.com/robots.txt",
        path="/robots.txt",
        severity="info",
        evidence="2 robots directives",
        status_code=200,
    )
    web = Subdomain(
        name="www.example.com",
        is_active=True,
        ips=["1.2.3.4"],
        open_ports=[80, 443],
        services=[
            Service(
                port=443,
                scheme="https",
                url="https://www.example.com/",
                exposures=[info, critical],
            )
        ],
    )
    return ScanResult(
        scanner="exposures",
        domain="example.com",
        started_at=T0,
        finished_at=T0 + timedelta(seconds=12),
        subdomains=[web, Subdomain(name="old.example.com", is_active=False, open_ports=[80])],
        errors=["crt.sh timeout"],
    )


def test_summary_numbers() -> None:
    s = summarize(_result())
    assert (s.subdomains, s.active_subdomains, s.services, s.web_hosts) == (2, 1, 1, 1)
    assert s.port_distribution == {80: 2, 443: 1}
    assert s.severity_counts["critical"] == 1 and s.severity_counts["high"] == 0
    assert s.risk == "critical" and s.total_findings == 2 and s.duration_seconds == 12.0


def test_markdown_contains_sections_and_fields() -> None:
    md = render_markdown(_result())
    for expected in (
        "# EASM Report: example.com",
        "## Executive Summary",
        "Overall risk: **CRITICAL**",
        "## Discovered Assets",
        "| www.example.com | yes | 1.2.3.4 | 80, 443 |",
        "[CRITICAL] env-file",
        "https://www.example.com/.env",
        "Remediation:",
        "Rotate",
        "crt.sh timeout",
    ):
        assert expected in md
    assert md.index("[CRITICAL]") < md.index("[INFO]")  # most severe first


def test_html_is_self_contained_and_escapes_evidence() -> None:
    page = render_html(_result())
    assert page.startswith("<!DOCTYPE html>")
    assert "<style>" in page
    assert "<script" not in page and "&lt;script&gt;" in page  # evidence is escaped
    assert 'src="' not in page and 'rel="stylesheet"' not in page  # no external assets
    for expected in (
        "Executive Summary",
        "Discovered Assets",
        "env-file",
        "Remediation",
        "1.2.3.4",
    ):
        assert expected in page


def test_empty_result_reports_cleanly() -> None:
    empty = ScanResult(scanner="x", domain="example.com", started_at=T0, finished_at=T0)
    assert "No exposures were found." in render_html(empty)
    assert "No exposures were found." in render_markdown(empty)
    assert summarize(empty).risk == "none"


def test_dashboard_renders_severity_table() -> None:
    buf = StringIO()
    render_dashboard(_result(), Console(file=buf, width=120, color_system=None))
    out = buf.getvalue()
    for expected in ("example.com", "CRITICAL", "HIGH", "MEDIUM", "INFO", "443", "crt.sh timeout"):
        assert expected in out
