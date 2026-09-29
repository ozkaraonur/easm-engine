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
