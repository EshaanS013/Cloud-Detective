from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Cloud Detective"
    environment: str = "local"
    database_url: str = (
        "postgresql+psycopg://cloud_detective:cloud_detective_local@localhost:5432/"
        "cloud_detective"
    )
    log_level: str = "INFO"
    response_mode: Literal["dry_run", "enforce"] = "dry_run"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    baseline_warmup_hours: int = 24
    rules_path: Path = Path("rules")
    auth_enabled: bool = False
    cognito_user_pool_id: str | None = None
    cognito_app_client_id: str | None = None
    aws_region: str = "ap-southeast-2"
    database_secret_arn: str | None = None
    database_host: str | None = None
    database_port: int = 5432
    database_name: str = "cloud_detective"
    queue_url: str | None = None
    response_queue_url: str | None = None
    poll_wait_seconds: int = 20


@lru_cache
def get_settings() -> Settings:
    return Settings()
