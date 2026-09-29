# EASM Engine — Claude Context

Modular External Attack Surface Management (EASM) and asset discovery engine.
Keep responses and diffs short; don't re-read files you already have in context.

## Architecture
- Python 3.11+ (use modern syntax: `X | None`, `list[str]`, `match`, `TaskGroup`)
- Async I/O: `asyncio` + `httpx.AsyncClient` (never `requests` or blocking calls in scanners)
- Data models & config: `pydantic` v2 (`BaseModel`, `pydantic-settings` for config)
- CLI: `typer`
- Logging: `loguru` (`from loguru import logger`); no `print()` outside the CLI layer

## Directory Layout
```
easm/
  core/        # Pydantic models, config/settings, BaseScanner, shared utils (http client, rate limiting)
  scanners/    # One file per independent scanner module (e.g. subdomains.py, dns.py)
  cli.py       # Typer entrypoint; wiring only, no business logic
tests/         # pytest + pytest-asyncio; mirrors easm/ structure
```

## Standards
- Type hints are mandatory on every function, method and attribute; code must pass `mypy --strict`.
- Single Responsibility: small, focused functions; one scanner = one concern.
- No global mutable state; pass config/clients via constructor (dependency injection).
- Share one `httpx.AsyncClient` per run; always set timeouts; respect concurrency limits (`asyncio.Semaphore`).
- Handle network errors inside the scanner; log them and return partial results instead of crashing the run.
- Formatting/linting: `ruff format` + `ruff check`.

## Scanner Rules
- Every scanner subclasses `easm.core.base.BaseScanner`.
- Input: a target domain (`str`, validated/normalized in core).
- Output: a standard Pydantic model (e.g. `ScanResult`) defined in `easm/core/models.py` — never raw dicts.
- Required interface (async): `async def scan(self, domain: str) -> ScanResult`.
- Each scanner declares a unique `name` class attribute and must be runnable in isolation.
- Scanners must not import each other; composition happens in the orchestrator/CLI.
- Every new scanner gets a test in `tests/scanners/` with HTTP mocked (`respx`); no real network calls in tests.

## Commands
- Install: `pip install -r requirements.txt`
- Test: `pytest -q`
- Lint/type: `ruff check . && mypy easm`
- Run: `python -m easm.cli --help`

## Scope & Ethics
Only scan assets you own or are explicitly authorized to test.
