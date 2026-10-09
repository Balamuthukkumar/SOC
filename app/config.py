from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

DEV_SECRET = "dev-secret-key-change-me-0123456789abcdef"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SOC Platform"
    environment: str = "development"
    secret_key: str = DEV_SECRET
    access_token_minutes: int = 60
    database_url: str = "sqlite+aiosqlite:///./soc.db"
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:8000"]
    # Seeds sample assets/devices plus a walkthrough alert+case, all marked is_synthetic=True (see app/seed.py).
    # Synthetic rows never appear on the dashboard, in /alerts/, /events/ or /cases/, or in MITRE coverage —
    # see the `is_synthetic` filtering in routers/alerts.py, routers/events.py and routers/cases.py.
    seed_demo: bool = True
    scheduler_enabled: bool = True

    nvd_api_key: str | None = None
    feed_interval_hours: int = 6
    mailgun_api_key: str | None = None
    mailgun_domain: str | None = None
    from_email: str = "alerts@example.com"
    slack_webhook_url: str | None = None
    generic_webhook_url: str | None = None

    github_client_id: str | None = None
    github_client_secret: str | None = None
    github_redirect_uri: str = "http://localhost:8000/api/v1/auth/github/callback"
    frontend_url: str = "/app/"

    ai_provider: str = "anthropic"
    ai_base_url: str | None = None
    ai_api_key: str | None = None
    anthropic_api_key: str | None = None
    ai_default_model: str = "claude-sonnet-5-5"

    @property
    def async_database_url(self) -> str:
        url = self.database_url
        for prefix, repl in (
            ("sqlite:///", "sqlite+aiosqlite:///"),
            ("postgresql://", "postgresql+asyncpg://"),
            ("postgres://", "postgresql+asyncpg://"),
        ):
            if url.startswith(prefix):
                return repl + url[len(prefix):]
        return url


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if s.environment == "production" and s.secret_key == DEV_SECRET:
        raise RuntimeError("SECRET_KEY must be set in production")
    return s


settings = get_settings()
