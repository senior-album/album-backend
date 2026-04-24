"""
Alembic environment — 앱 Settings 에서 DB URL 을 끌어오고, models.Base.metadata 를
target 으로 등록해서 `alembic revision --autogenerate` 가 모델 변경을 감지하게 한다.

공식 async 템플릿 기반. 앱은 asyncpg 를 쓰고, alembic 은 마이그레이션 돌때만
잠깐 async engine 을 띄워 `run_sync` 로 sync-style 마이그레이션 훅을 돌린다.
"""

import asyncio
import os
import sys
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# app 패키지를 import path 에 추가 (prepend_sys_path=. 덕분에 보통 자동이지만 명시)
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from app.core.config import get_settings  # noqa: E402
from app.models.models import Base  # noqa: E402

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Settings 의 database_url 을 런타임에 주입 — alembic.ini 의 placeholder 를
# 덮어씌운다. 덕분에 ini 에 secret 을 하드코딩하지 않아도 된다.
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.database_url)

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# autogenerate 가 감지할 메타데이터
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """오프라인 모드 — 실제 DB 에 연결하지 않고 SQL 스크립트만 생성."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """async engine 을 띄워 connection 을 받아 sync 마이그레이션 훅을 돌린다."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """온라인 모드 — 실제 DB 에 연결해서 마이그레이션 적용."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
