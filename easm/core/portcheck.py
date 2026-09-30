import asyncio

from loguru import logger


async def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """Lightweight TCP connect check; True if the port accepts connections."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError) as exc:
        logger.debug("{}:{} closed/filtered: {!r}", host, port, exc)
        return False
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return True


async def scan_ports(host: str, ports: list[int], timeout: float = 3.0) -> list[int]:
    """Check all ports on a host concurrently; return the open ones, sorted."""
    results = await asyncio.gather(*(check_port(host, p, timeout) for p in ports))
    return sorted(p for p, is_open in zip(ports, results, strict=True) if is_open)


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    """Passively read the greeting a service sends on connect (SSH, FTP, SMTP, MySQL...).

    Nothing is sent, so silent protocols (RDP, Redis, HTTP) simply return None.
    """
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, TimeoutError):
        return None
    try:
        data = await asyncio.wait_for(reader.read(256), min(timeout, 2.0))
    except (OSError, TimeoutError):
        data = b""
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    text = "".join(c if c.isprintable() else " " for c in data.decode("latin-1")).strip()
    return " ".join(text.split())[:100] or None
