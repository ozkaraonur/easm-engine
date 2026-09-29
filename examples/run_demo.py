"""Offline demo: scan a throwaway local web server and write sample reports.

    python examples/run_demo.py [--out-dir output]

No internet access is needed. A deliberately leaky HTTP server is started on
127.0.0.1, scanned with the real ExposureScanner, and the result is rendered
through the same reporting code the `easm scan` command uses.
"""

import argparse
import asyncio
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loguru import logger

from easm.core.config import Settings
from easm.core.models import Service, Subdomain
from easm.reporting import render_dashboard, render_html, render_markdown
from easm.scanners.exposures import ExposureScanner

FILES = {
    "/.git/HEAD": b"ref: refs/heads/main\n",
    "/.env": b"DB_PASSWORD=hunter2\nAPI_KEY=demo-not-a-real-key\n",
    "/robots.txt": b"User-agent: *\nDisallow: /admin\n",
}


class LeakyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = FILES.get(self.path)
        self.send_response(200 if body is not None else 404)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(body if body is not None else b"not found")

    def log_message(self, format: str, *args: object) -> None:
        pass


async def run(out_dir: Path) -> None:
    logger.remove()
    logger.add(sys.stderr, level="WARNING")
    server = ThreadingHTTPServer(("127.0.0.1", 0), LeakyHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        host = Subdomain(
            name="demo.example.test",
            is_active=True,
            ips=["127.0.0.1"],
            open_ports=[port],
            services=[
                Service(port=port, scheme="http", url=f"http://127.0.0.1:{port}/", status_code=200)
            ],
        )
        result = await ExposureScanner(Settings(), hosts=[host]).scan("example.test")
    finally:
        server.shutdown()
        server.server_close()

    render_dashboard(result)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "demo-report.html").write_text(render_html(result), encoding="utf-8")
    (out_dir / "demo-report.md").write_text(render_markdown(result), encoding="utf-8")
    print(f"Saved: {out_dir / 'demo-report.html'}\nSaved: {out_dir / 'demo-report.md'}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])  # type: ignore[union-attr]
    parser.add_argument("--out-dir", type=Path, default=Path("output"))
    asyncio.run(run(parser.parse_args().out_dir))


if __name__ == "__main__":
    main()
