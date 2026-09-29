import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer
from loguru import logger

from easm.core.config import Settings
from easm.core.models import ScanResult
from easm.core.utils import normalize_domain
from easm.pipeline import discover_services
from easm.scanners.crtsh import CrtShScanner

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


if __name__ == "__main__":
    app()
