from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Service(BaseModel):
    """An HTTP(S) service answering on a host:port."""

    port: int
    scheme: Literal["http", "https"]
    url: str
    status_code: int | None = None
    title: str | None = None
    server: str | None = None
    tls_valid: bool | None = None  # None for plain HTTP
    tls_error: str | None = None


class Subdomain(BaseModel):
    """A discovered hostname belonging to the target domain."""

    name: str
    sources: set[str] = Field(default_factory=set)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    issuers: set[str] = Field(default_factory=set)
    is_active: bool | None = None  # None = not checked
    ips: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Standard output of every scanner."""

    scanner: str
    domain: str
    started_at: datetime
    finished_at: datetime
    subdomains: list[Subdomain] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @property
    def active_count(self) -> int:
        return sum(1 for s in self.subdomains if s.is_active)
