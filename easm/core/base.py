from abc import ABC, abstractmethod

from easm.core.config import Settings
from easm.core.models import ScanResult


class BaseScanner(ABC):
    """Contract every scanner implements: domain in, ScanResult out."""

    name: str

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings()

    @abstractmethod
    async def scan(self, domain: str) -> ScanResult:
        """Run the scan against a target domain."""
