from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from easm.core.ports import DEFAULT_SCAN_PORTS


class Settings(BaseSettings):
    """Runtime configuration; override via EASM_* environment variables."""

    model_config = SettingsConfigDict(env_prefix="EASM_")

    http_timeout: float = Field(default=30.0, gt=0)
    http_retries: int = Field(default=3, ge=0)
    retry_backoff: float = Field(default=2.0, ge=0)
    dns_concurrency: int = Field(default=50, ge=1)
    dns_timeout: float = Field(default=5.0, gt=0)
    service_ports: list[int] = Field(default=list(DEFAULT_SCAN_PORTS))
    port_timeout: float = Field(default=3.0, gt=0)
    service_concurrency: int = Field(default=20, ge=1)
    service_http_timeout: float = Field(default=10.0, gt=0)
    hackertarget_enabled: bool = True
    dns_brute_enabled: bool = True
    user_agent: str = "easm-engine/0.1"
    exposure_concurrency: int = Field(default=20, ge=1)
    exposure_http_timeout: float = Field(default=10.0, gt=0)
