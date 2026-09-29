import asyncio
import socket

from loguru import logger


async def resolve_host(hostname: str, timeout: float = 5.0) -> list[str]:
    """Resolve A/AAAA records via the system resolver; empty list if unresolvable."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM), timeout
        )
    except (socket.gaierror, TimeoutError, OSError) as exc:
        logger.debug("DNS miss for {}: {}", hostname, exc)
        return []
    return sorted({str(info[4][0]) for info in infos})


async def resolve_many(
    hostnames: list[str], concurrency: int = 50, timeout: float = 5.0
) -> dict[str, list[str]]:
    """Resolve many hostnames concurrently, bounded by a semaphore."""
    sem = asyncio.Semaphore(concurrency)

    async def _one(host: str) -> tuple[str, list[str]]:
        async with sem:
            return host, await resolve_host(host, timeout)

    return dict(await asyncio.gather(*(_one(h) for h in hostnames)))
