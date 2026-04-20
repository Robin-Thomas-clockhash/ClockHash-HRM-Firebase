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
        extra="ignore",
    )

    # Firebase
    firebase_credentials_json_type: str = "service_account"
    firebase_credentials_json_project_id: str = ""
    firebase_credentials_json_private_key_id: str = ""
    firebase_credentials_json_private_key: str = ""
    firebase_credentials_json_client_email: str = ""
    firebase_credentials_json_client_id: str = ""
    firebase_credentials_json_auth_uri: str = "https://accounts.google.com/o/oauth2/auth"
    firebase_credentials_json_token_uri: str = "https://oauth2.googleapis.com/token"
    firebase_credentials_json_auth_provider_x509_cert_url: str = "https://www.googleapis.com/oauth2/v1/certs"
    firebase_credentials_json_client_x509_cert_url: str = ""
    firebase_credentials_json_universe_domain: str = "googleapis.com"
    firebase_storage_bucket: str = ""
    firestore_database_name: str = "(default)"

    # API Keys (Frontend ↔ Backend auth)
    admin_api_key: str = ""
    employee_api_key: str = ""

    # Encryption
    master_key_seed: str = ""

    # Email (Gmail SMTP via App Password)
    smtp_user: str = "noreply@clockhash.com"
    smtp_password: str = ""  # Set via SMTP_PASSWORD env var

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
