import asyncio

from easm.core.config import Settings
from easm.core.portcheck import grab_banner
from easm.core.ports import DEFAULT_SCAN_PORTS, RISKY_PORTS, port_exposure, port_remediation
from easm.reporting.remediation import remediation_for


def test_default_ports_include_web_and_risky() -> None:
    assert {80, 443, 8080, 8443} <= set(DEFAULT_SCAN_PORTS)
    assert {22, 3306, 3389, 6379, 27017} <= set(Settings().service_ports)


def test_port_exposure() -> None:
    finding = port_exposure("db.example.com", 3306, "5.7.31")
    assert finding
    assert finding.check == "open-port-3306"
    assert finding.url == "tcp://db.example.com:3306"
    assert finding.severity == "high"
    assert "banner: 5.7.31" in finding.evidence
    assert port_exposure("www.example.com", 443, None) is None
    assert RISKY_PORTS[3389].severity == "critical"


def test_port_remediation() -> None:
    assert "VPN" in remediation_for("open-port-3389")
    assert port_remediation("open-port-999") is None
    assert port_remediation("open-port-x") is None
    assert remediation_for("phpinfo").startswith("Delete phpinfo")


async def test_grab_banner_reads_greeting() -> None:
    async def greet(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"SSH-2.0-OpenSSH_8.9\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(greet, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert await grab_banner("127.0.0.1", port, timeout=1) == "SSH-2.0-OpenSSH_8.9"


async def test_grab_banner_silent_or_closed() -> None:
    async def silent(_: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await asyncio.sleep(0.3)
        writer.close()

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        assert await grab_banner("127.0.0.1", port, timeout=0.1) is None
    assert await grab_banner("127.0.0.1", port, timeout=0.5) is None  # now closed
