import os
from typing import List, Union

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # API Configuration
    api_v1_prefix: str = Field(default="/api/v1")
    api_title: str = Field(default="ReviewMyPortfolio API")
    api_version: str = Field(default="1.0.0")
    port: int = Field(default=8000)
    log_level: str = Field(default="INFO")

    # Database
    database_url: str = Field(
        default="postgresql://postgres:postgres@localhost:5432/reviewmyportfolio"
    )

    # Redis
    redis_url: str = Field(default="redis://localhost:6379")

    # Supabase
    supabase_url: str
    supabase_anon_key: str
    supabase_service_key: str
    # Note: Supabase manages all JWT tokens (signing, validation, expiration)
    # No custom JWT configuration needed

    # Google OAuth
    google_client_id: str = Field(default="")
    google_client_secret: str = Field(default="")
    google_redirect_uri: str = Field(default="")

    # OpenAI
    openai_api_key: str = Field(default="")

    # Environment (for conditional validation)
    environment: str = Field(default="development", env="ENVIRONMENT")

    # PII Encryption (for portfolio ownership verification)
    pii_encryption_key: str = Field(default="")
    pii_hash_salt: str = Field(
        default="dev-constant-salt-do-not-use-in-production-8a7f3c2e1b9d4f6a",
        env="PII_HASH_SALT"
    )

    @model_validator(mode="after")
    def validate_production_pii_salt(self):
        """Ensure PII_HASH_SALT is set from environment in production"""
        if self.environment == "production":
            # Check if PII_HASH_SALT was explicitly set via environment
            env_salt = os.getenv("PII_HASH_SALT")
            if not env_salt or env_salt == "dev-constant-salt-do-not-use-in-production-8a7f3c2e1b9d4f6a":
                raise ValueError(
                    "PII_HASH_SALT must be explicitly set via environment variable in production. "
                    "Generate one with: openssl rand -hex 32"
                )
        return self

    # Frontend
    frontend_url: str = Field(default="http://localhost:3000")

    # CORS
    cors_origins: Union[str, List[str]] = Field(default="http://localhost:3000")
    cors_allow_credentials: bool = Field(default=True)

    # Rate Limiting
    rate_limit_requests: int = Field(default=100)
    rate_limit_period: int = Field(default=60)

    # Auth-specific rate limiting
    rate_limit_auth_requests: int = Field(default=5)
    rate_limit_auth_period: int = Field(default=60)

    # ClamAV Configuration
    clamav_host: str = Field(default="clamav")
    clamav_port: int = Field(default=3310)
    clamav_enabled: bool = Field(default=True)

    # Sentry (optional — disabled if empty)
    sentry_dsn: str = Field(default="")

    # TrueData Market Data (placeholder — enable when subscription is active)
    truedata_api_key: str = Field(default="")
    truedata_base_url: str = Field(default="https://api.truedata.in")

    # AWS SES Email
    aws_access_key_id: str = Field(default="")
    aws_secret_access_key: str = Field(default="")
    aws_ses_region: str = Field(default="ap-south-1")
    email_from: str = Field(default="noreply@reviewmyportfolio.in")

    # API Access Control Secrets
    internal_api_secret: str = Field(default="", env="INTERNAL_API_SECRET")
    proxy_api_secret: str = Field(default="", env="PROXY_API_SECRET")

    # Internal API URL — used by RQ workers to call back to the API service.
    # Railway prod:  http://<api-service-name>.railway.internal:8000
    #   (Railway injects private DNS; use the exact service name from the Railway dashboard)
    #   e.g.  INTERNAL_API_URL=http://api.railway.internal:8000
    # Local dev:     http://api:8000  (Docker Compose service name)
    # Never use the public Railway domain here — that adds TLS overhead and
    # leaves the callback path exposed on the internet.
    internal_api_url: str = Field(default="http://localhost:8000", env="INTERNAL_API_URL")

    @model_validator(mode="after")
    def validate_production_pii_encryption_key(self):
        """Ensure PII_ENCRYPTION_KEY is explicitly set in production (not falling back to service key)"""
        if self.environment == "production":
            env_key = os.getenv("PII_ENCRYPTION_KEY")
            if not env_key:
                raise ValueError(
                    "PII_ENCRYPTION_KEY must be explicitly set via environment variable in production. "
                    "Generate one with: openssl rand -hex 32"
                )
        return self

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v):
        if isinstance(v, str):
            # Handle comma-separated string
            return [origin.strip() for origin in v.split(",")]
        return v

    @field_validator("cors_origins", mode="after")
    @classmethod
    def ensure_cors_is_list(cls, v):
        if isinstance(v, str):
            return [v]
        return v


settings = Settings()
