"""
Application settings loaded from .env via pydantic-settings.
All secrets are sourced from environment variables — never hardcoded.
"""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Firebase
    firebase_credentials_json: str = ""
    firebase_storage_bucket: str = ""
    firestore_database_name: str = "(default)"

    # API Keys (Frontend ↔ Backend auth)
    admin_api_key: str = ""
    employee_api_key: str = ""

    # Encryption
    master_key_seed: str = ""

    # App
    app_name: str = "ClockHash HRM Salary Slip API"
    debug: bool = False


@lru_cache()
def get_settings() -> Settings:
    """
    Returns cached settings instance.
    Uses lru_cache so .env is only read once at startup.
    """
    return Settings()
