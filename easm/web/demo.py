"""Offline demo target: throwaway local servers that leak files on purpose.

The exposure findings are produced by the real ExposureScanner against 127.0.0.1;
only the hostnames, IPs and DNS/port data are synthetic.
"""

import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Final

from easm.core.config import Settings
from easm.core.models import ScanResult, Service, Subdomain
from easm.core.ports import port_exposure
from easm.scanners.exposures import ExposureScanner

DEMO_DOMAIN: Final = "demo.easm.test"

_ENV = b"DB_PASSWORD=hunter2\nAPI_KEY=demo-not-a-real-key\nAWS_SECRET=demo\nJWT_SECRET=demo\n"
_ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
_SECURITY = b"Contact: mailto:security@demo.easm.test\n"
_GIT = b"ref: refs/heads/main\n"
_ZIP = b"PK\x03\x04" + b"\x00" * 64
_WEBCONFIG = b'<?xml version="1.0"?><configuration><connectionStrings/></configuration>'

# host -> (server header, leaked files)
_HOSTS: Final[dict[str, tuple[str, dict[str, bytes]]]] = {
    f"www.{DEMO_DOMAIN}": (
        "nginx/1.24.0",
        {"/robots.txt": _ROBOTS, "/.well-known/security.txt": _SECURITY},
    ),
    f"dev.{DEMO_DOMAIN}": (
        "Apache/2.4.29",
        {"/.git/HEAD": _GIT, "/.env": _ENV, "/robots.txt": _ROBOTS},
    ),
    f"staging.{DEMO_DOMAIN}": ("nginx/1.14.0", {"/.env": _ENV, "/backup.zip": _ZIP}),
    f"admin.{DEMO_DOMAIN}": (
        "Microsoft-IIS/8.5",
        {"/web.config": _WEBCONFIG, "/.git/HEAD": _GIT, "/backup.zip": _ZIP},
    ),
    f"api.{DEMO_DOMAIN}": ("gunicorn/21.2", {"/robots.txt": _ROBOTS}),
}
_MAIL: Final = f"mail.{DEMO_DOMAIN}"
# Sample data: risky ports per host with their (synthetic) banners.
_RISKY: Final[dict[str, dict[int, str | None]]] = {
    f"dev.{DEMO_DOMAIN}": {22: "SSH-2.0-OpenSSH_7.4", 6379: None},
    f"staging.{DEMO_DOMAIN}": {22: "SSH-2.0-OpenSSH_7.4", 3306: "5.7.31-log"},
    f"admin.{DEMO_DOMAIN}": {3389: None, 445: None},
    f"api.{DEMO_DOMAIN}": {9200: None},
    _MAIL: {25: "220 mail.demo.easm.test ESMTP Postfix", 21: "220 FTP server ready"},
}


def _add_risky_ports(host: Subdomain) -> None:
    for port, banner in _RISKY.get(host.name, {}).items():
        host.open_ports = sorted({*host.open_ports, port})
        if banner:
            host.banners[port] = banner
        if finding := port_exposure(host.name, port, banner):
            host.port_exposures.append(finding)


def _server(server_header: str, files: dict[str, bytes]) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = files.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Server", server_header)
            self.end_headers()
            self.wfile.write(body if body is not None else b"not found")

        def log_message(self, format: str, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


async def run_demo_scan(progress: Callable[[float, str], None] | None = None) -> ScanResult:
    started = datetime.now(UTC)
    servers: list[ThreadingHTTPServer] = []
    hosts: list[Subdomain] = []
    try:
        for i, (name, (server_header, files)) in enumerate(_HOSTS.items(), start=10):
            srv = _server(server_header, files)
            servers.append(srv)
            port = srv.server_address[1]
            hosts.append(
                Subdomain(
                    name=name,
                    is_active=True,
                    ips=[f"203.0.113.{i}"],
                    open_ports=[80, 443],
                    services=[
                        Service(
                            port=port,
                            scheme="http",
                            url=f"http://127.0.0.1:{port}/",
                            status_code=200,
                            server=server_header,
                            title=name.split(".")[0].capitalize(),
                        )
                    ],
                )
            )
        hosts.append(Subdomain(name=_MAIL, is_active=True, ips=["203.0.113.50"], open_ports=[587]))
        hosts.append(Subdomain(name=f"old.{DEMO_DOMAIN}", is_active=False))
        for host in hosts:
            _add_risky_ports(host)
        if progress:
            progress(0.5, "Probing sensitive files")
        exposed = await ExposureScanner(Settings(), hosts=[h for h in hosts if h.services]).scan(
            DEMO_DOMAIN
        )
    finally:
        for srv in servers:
            srv.shutdown()
            srv.server_close()
    by_name = {h.name: h for h in exposed.subdomains}
    return ScanResult(
        scanner="demo",
        domain=DEMO_DOMAIN,
        started_at=started,
        finished_at=datetime.now(UTC),
        subdomains=[by_name.get(h.name, h) for h in hosts],
        errors=exposed.errors,
    )
