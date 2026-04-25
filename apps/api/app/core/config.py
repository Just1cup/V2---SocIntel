from pathlib import Path

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


UNSAFE_SECRET_VALUES = {"", "change-me", "changeme", "secret", "password"}
REPO_ROOT = Path(__file__).resolve().parents[4]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(REPO_ROOT / ".env", ".env"), env_file_encoding="utf-8", extra="ignore")

    app_name: str = "SOCINTEL API"
    environment: str = "development"
    api_v1_prefix: str = "/api/v1"
    expose_api_docs: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    database_url: str = "postgresql+psycopg://socintel:socintel@localhost:5432/socintel_v2"
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None
    legacy_backend_path: str | None = None
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    auth_cookie_name: str = "socintel_access_token"
    auth_cookie_secure: bool = False
    auth_cookie_samesite: str = "lax"
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 300
    taxii_request_timeout_seconds: float = 20.0
    taxii_cache_ttl_seconds: int = 600
    taxii_mitre_base_url: str = "https://attack-taxii.mitre.org"
    taxii_mitre_api_root: str = "/api/v21"

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]

    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, value: str) -> str:
        if value != "HS256":
            raise ValueError("JWT_ALGORITHM must be HS256.")
        return value

    @model_validator(mode="after")
    def validate_secrets(self) -> "Settings":
        if self.jwt_secret.strip().lower() in UNSAFE_SECRET_VALUES or len(self.jwt_secret) < 32:
            raise ValueError("JWT_SECRET must be a strong random value of at least 32 characters.")
        return self


settings = Settings()
