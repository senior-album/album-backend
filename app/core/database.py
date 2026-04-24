"""
데이터베이스 연결 및 세션 관리
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool
import logging

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class Database:
    _engine = None
    _session_local = None

    @classmethod
    async def initialize(cls):
        """
        엔진과 세션 팩토리만 초기화. 스키마 생성/마이그레이션은 컨테이너 기동
        스크립트가 `alembic upgrade head` 로 처리한다 (Dockerfile CMD 참조).
        """
        settings = get_settings()

        cls._engine = create_async_engine(
            settings.database_url,
            echo=settings.DEBUG,
            poolclass=NullPool,
        )

        cls._session_local = async_sessionmaker(
            cls._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        logger.info("Database initialized (migrations managed by Alembic)")

    @classmethod
    async def close(cls):
        if cls._engine:
            await cls._engine.dispose()
            logger.info("Database connection closed")

    @classmethod
    async def get_session(cls) -> AsyncGenerator[AsyncSession, None]:
        """FastAPI Depends용 async generator"""
        if cls._session_local is None:
            raise RuntimeError("Database not initialized")

        async with cls._session_local() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()

    @classmethod
    @asynccontextmanager
    async def session_scope(cls):
        """백그라운드 워커 등에서 사용하는 context manager 버전"""
        if cls._session_local is None:
            raise RuntimeError("Database not initialized")

        async with cls._session_local() as session:
            try:
                yield session
                await session.commit()
            except Exception as e:
                await session.rollback()
                logger.error(f"Database session error: {e}")
                raise
            finally:
                await session.close()


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in Database.get_session():
        yield session
