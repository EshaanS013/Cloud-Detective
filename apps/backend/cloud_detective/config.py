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


@lru_cache
def get_settings() -> Settings:
    return Settings()
