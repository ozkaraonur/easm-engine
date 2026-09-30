import asyncio
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from loguru import logger

from easm.core.config import Settings
from easm.core.models import ScanResult, Service, Subdomain
from easm.core.utils import normalize_domain
from easm.pipeline import discover_services, full_scan
from easm.reporting import render_dashboard, render_html, render_markdown
from easm.scanners.crtsh import CrtShScanner
from easm.scanners.exposures import ExposureScanner

app = typer.Typer(help="EASM engine: external attack surface discovery.", no_args_is_help=True)


def _print_table(result: ScanResult) -> None:
    typer.echo(
        f"{result.domain}: {len(result.subdomains)} subdomains, {result.active_count} active"
    )
    for sub in result.subdomains:
        state = {True: "active", False: "inactive", None: "-"}[sub.is_active]
        typer.echo(f"  {sub.name:<50} {state:<9} {','.join(sub.ips)}")
    for err in result.errors:
        typer.echo(f"  ERROR: {err}", err=True)


def _print_services(result: ScanResult) -> None:
    hosts = [s for s in result.subdomains if s.open_ports]
    total = sum(len(s.services) for s in hosts)
    typer.echo(f"{result.domain}: {len(hosts)} hosts with open ports, {total} web services")
    for sub in hosts:
        typer.echo(f"  {sub.name}  ports={','.join(map(str, sub.open_ports))}")
        for svc in sub.services:
            tls = {True: "tls-ok", False: "tls-INVALID", None: ""}[svc.tls_valid]
            typer.echo(
                f"    {svc.url:<45} {svc.status_code or '-':<4} {tls:<11} "
                f"server={svc.server or '-'} title={svc.title or '-'!r}"
            )
    for err in result.errors:
        typer.echo(f"  ERROR: {err}", err=True)


def _print_findings(result: ScanResult) -> None:
    findings = result.findings
    typer.echo(f"{result.domain}: {len(findings)} exposure findings")
    for f in findings:
        typer.echo(f"  [{f.severity.upper():<8}] {f.url}  ({f.status_code})  {f.evidence}")
    for err in result.errors:
        typer.echo(f"  ERROR: {err}", err=True)


def _parse_ports(value: str) -> list[int]:
    try:
        ports = [int(p) for p in value.split(",") if p.strip()]
    except ValueError as exc:
        raise typer.BadParameter("ports must be comma-separated integers") from exc
    if not ports or any(not 0 < p < 65536 for p in ports):
        raise typer.BadParameter("ports must be within 1-65535")
    return ports


@app.callback()
def main() -> None:
    """EASM engine."""


@app.command()
def subdomains(
    domain: Annotated[str, typer.Argument(help="Target domain, e.g. example.com")],
    resolve: Annotated[
        bool, typer.Option("--resolve/--no-resolve", help="DNS-check each host")
    ] = True,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write full result to this file")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Discover subdomains via Certificate Transparency (crt.sh)."""
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "WARNING")
    try:
        target = normalize_domain(domain)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    result = asyncio.run(CrtShScanner(Settings(), resolve=resolve).scan(target))
    _print_table(result)
    if json_out:
        json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"Saved: {json_out}")
    if result.errors:
        raise typer.Exit(1)


@app.command()
def services(
    domain: Annotated[str, typer.Argument(help="Target domain, e.g. example.com")],
    ports: Annotated[
        str | None, typer.Option("--ports", help="Comma-separated ports (default 80,443,8080,8443)")
    ] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write full result to this file")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Discover active subdomains, then detect open web ports and HTTP(S) services."""
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "WARNING")
    try:
        target = normalize_domain(domain)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    settings = Settings()
    if ports:
        settings.service_ports = _parse_ports(ports)
    result = asyncio.run(discover_services(target, settings))
    _print_services(result)
    if json_out:
        json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"Saved: {json_out}")
    if result.errors:
        raise typer.Exit(1)


def _setup_logging(verbose: bool) -> None:
    logger.remove()
    logger.add(sys.stderr, level="DEBUG" if verbose else "WARNING")


def _finish(result: ScanResult, json_out: Path | None) -> None:
    if json_out:
        json_out.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        typer.echo(f"Saved: {json_out}")
    if result.errors:
        raise typer.Exit(1)


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="Target domain, e.g. example.com")],
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write full result to this file")
    ] = None,
    html_out: Annotated[
        Path | None, typer.Option("--html", help="Write an HTML audit report to this file")
    ] = None,
    markdown_out: Annotated[
        Path | None, typer.Option("--markdown", help="Write a Markdown report to this file")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Full pipeline: subdomains (crt.sh) -> web services -> exposure checks."""
    _setup_logging(verbose)
    try:
        target = normalize_domain(domain)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(2) from exc

    result = asyncio.run(full_scan(target, Settings()))
    render_dashboard(result)
    if html_out:
        html_out.write_text(render_html(result), encoding="utf-8")
        typer.echo(f"Saved: {html_out}")
    if markdown_out:
        markdown_out.write_text(render_markdown(result), encoding="utf-8")
        typer.echo(f"Saved: {markdown_out}")
    _finish(result, json_out)


@app.command()
def exposures(
    url: Annotated[str, typer.Argument(help="Target base URL, e.g. https://example.com")],
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write full result to this file")
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run only the exposure checks against a single URL."""
    _setup_logging(verbose)
    parts = urlsplit(url if "://" in url else f"https://{url}")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        typer.echo(f"Invalid URL: {url!r}", err=True)
        raise typer.Exit(2)
    scheme = "https" if parts.scheme == "https" else "http"
    host = Subdomain(
        name=parts.hostname,
        services=[
            Service(
                port=parts.port or (443 if scheme == "https" else 80),
                scheme=scheme,
                url=f"{scheme}://{parts.netloc}/",
            )
        ],
    )
    result = asyncio.run(ExposureScanner(Settings(), hosts=[host]).scan(parts.hostname))
    _print_findings(result)
    _finish(result, json_out)


@app.command()
def web(
    port: Annotated[int, typer.Option("--port", help="Port for the web dashboard")] = 8501,
    host: Annotated[str, typer.Option("--host", help="Address to bind")] = "127.0.0.1",
) -> None:
    """Launch the Streamlit web dashboard."""
    if find_spec("streamlit") is None:
        typer.echo("Streamlit is not installed: pip install streamlit", err=True)
        raise typer.Exit(2)
    script = Path(__file__).parent / "web" / "app.py"
    cmd = [sys.executable, "-m", "streamlit", "run", str(script)]
    cmd += ["--server.port", str(port), "--server.address", host]
    raise typer.Exit(subprocess.call(cmd))


app.command("ui", hidden=True)(web)


if __name__ == "__main__":
    app()
