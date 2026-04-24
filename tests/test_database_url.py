"""roadmap#87 — DATABASE_URL 부분 env 조립 동작 검증."""

from app.core.config import Settings


def _settings(**overrides) -> Settings:
    base = dict(JWT_SECRET="x" * 48, JWT_REFRESH_SECRET="y" * 48)
    base.update(overrides)
    return Settings(**base)


def test_database_url_assembled_from_parts():
    s = _settings(
        POSTGRES_HOST="db",
        POSTGRES_PORT=6543,
        POSTGRES_USER="alice",
        POSTGRES_PASSWORD="s3cret",
        POSTGRES_DB="album",
    )
    assert s.database_url == "postgresql+asyncpg://alice:s3cret@db:6543/album"


def test_database_url_explicit_overrides_parts():
    s = _settings(
        POSTGRES_PASSWORD="ignored",
        DATABASE_URL="postgresql+asyncpg://u:p@h:1/d",
    )
    assert s.database_url == "postgresql+asyncpg://u:p@h:1/d"
