"""Spork-IDS Application Configuration."""
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Spork-IDS Configuration Settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Server settings
    SPORK_HOST: str = "127.0.0.1"
    SPORK_PORT: int = 8000
    SPORK_DEBUG: bool = False
    SPORK_ENV: str = "development"

    # Database settings
    SPORK_DATABASE_URL: str = "sqlite:///./data/spork.db"

    # Security settings
    SPORK_API_KEY: Optional[str] = None
    SPORK_SECRET_KEY: str = "spork-ids-dev-secret-change-in-production"

    # CORS settings (list of allowed origins)
    SPORK_CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:5173",
            "http://localhost:8000",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:8000",
        ]
    )

    # External CrowdSec Integration (Optional)
    CROWDSEC_ENABLED: bool = False
    CROWDSEC_LAPI_URL: str = "http://localhost:8080"
    CROWDSEC_API_KEY: Optional[str] = None
    CROWDSEC_MACHINE_ID: Optional[str] = None


settings = Settings()
