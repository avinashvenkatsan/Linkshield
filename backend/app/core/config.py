from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_env: str = "development"
    app_name: str = "LinkShield"
    app_version: str = "0.1.0"
    log_level: str = "INFO"

    frontend_origin: str = "http://localhost:5173"
    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    public_api_base_url: str = "http://localhost:8000"

    database_url: str = ""

    google_safe_browsing_api_key: str = ""
    virustotal_api_key: str = ""
    external_intel_enabled: bool = True

    rate_limit_scan_per_minute: int = 10
    rate_limit_read_per_minute: int = 60

    outbound_timeout_seconds: float = 5.0
    outbound_max_redirects: int = 5
    outbound_max_response_bytes: int = 65536
    outbound_connect_timeout_seconds: float = 3.0

    default_scan_ttl_hours: int = 24
    persisted_scan_ttl_days: int = 30
    stats_enabled: bool = True

    rdap_enabled: bool = True
    rdap_base_url: str = "https://rdap.org/domain"

    session_cookie_name: str = "ls_client"
    session_cookie_secure: bool = False

    allowed_ports: List[int] = Field(default_factory=lambda: [80, 443])

    @field_validator("frontend_origin")
    @classmethod
    def strip_origin(cls, value: str) -> str:
        return value.strip()

    @property
    def cors_origins(self) -> List[str]:
        return [part.strip() for part in self.frontend_origin.split(",") if part.strip()]

    @property
    def database_enabled(self) -> bool:
        return bool(self.database_url.strip())

    @property
    def gsb_configured(self) -> bool:
        return bool(self.google_safe_browsing_api_key.strip())

    @property
    def virustotal_configured(self) -> bool:
        return bool(self.virustotal_api_key.strip())

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
