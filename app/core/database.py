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

        # 테이블 자동 생성
        await cls.create_tables()
        logger.info("Database initialized")

    @classmethod
    async def create_tables(cls):
        from app.models.models import Base
        settings = get_settings()

        async with cls._engine.begin() as conn:
            if settings.DDL_AUTO == "create-drop":
                await conn.run_sync(Base.metadata.drop_all)
                logger.warning("DDL_AUTO=create-drop: All tables dropped!")
                await conn.run_sync(Base.metadata.create_all)
                logger.info("All tables re-created from scratch")
            elif settings.DDL_AUTO == "create":
                await conn.run_sync(Base.metadata.create_all)
                logger.info("Database tables created/verified")
                # 기존 테이블에 누락된 컬럼 자동 추가
                await cls._add_missing_columns(conn)
            else:
                logger.info("DDL_AUTO=none: Skipping table creation (use Alembic)")

    @classmethod
    async def _add_missing_columns(cls, conn):
        """
        DDL_AUTO=create는 CREATE TABLE IF NOT EXISTS만 실행하므로
        기존 테이블에 새로 추가된 컬럼이 반영되지 않는다.
        여기서 누락된 컬럼을 ALTER TABLE로 추가한다.
        """
        from sqlalchemy import text

        # (테이블명, 컬럼명, SQL 타입, 기본값)
        columns_to_ensure = [
            # photos 테이블
            ("photos", "is_public", "BOOLEAN", "FALSE"),
            ("photos", "published_by", "VARCHAR(36)", "NULL"),
            ("photos", "published_at", "TIMESTAMP", "NULL"),
            ("photos", "processing_status", "VARCHAR(50)", "'pending'"),
            ("photos", "upload_source", "VARCHAR(50)", "NULL"),
            ("photos", "uploaded_by", "VARCHAR(36)", "NULL"),
            # photo_shares 테이블
            ("photo_shares", "expires_at", "TIMESTAMP", "NULL"),
            # invitations 테이블 — 이메일 초대 추가 (d3004bc)
            ("invitations", "email", "VARCHAR(255)", "NULL"),
            # users 테이블 — OTP 게이트 (e81db45)
            ("users", "phone_verified_at", "TIMESTAMP", "NULL"),
        ]

        for table, column, col_type, default in columns_to_ensure:
            try:
                check = await conn.execute(text(
                    f"SELECT column_name FROM information_schema.columns "
                    f"WHERE table_name = '{table}' AND column_name = '{column}'"
                ))
                if check.fetchone() is None:
                    if default is None:
                        continue  # PK 등은 스킵 (테이블 자체가 없으면 create_all이 처리)
                    default_clause = f"DEFAULT {default}" if default != "NULL" else ""
                    sql = f"ALTER TABLE {table} ADD COLUMN {column} {col_type} {default_clause}"
                    await conn.execute(text(sql))
                    logger.info(f"[migration] Added column {table}.{column} ({col_type})")
            except Exception as e:
                logger.warning(f"[migration] Could not add {table}.{column}: {e}")

        # NOT NULL → NULL 로 완화된 컬럼 (모델 기준). 이미 NULLABLE 면 PG 는 NOTICE 만 내고 no-op.
        # (테이블명, 컬럼명)
        drop_not_null = [
            # d3004bc — 이메일 초대, 시설코드 요청으로 phone/resident_id 모두 optional 이 됨
            ("invitations", "phone"),
            ("guardians", "resident_id"),
        ]
        for table, column in drop_not_null:
            try:
                await conn.execute(text(
                    f"ALTER TABLE {table} ALTER COLUMN {column} DROP NOT NULL"
                ))
                logger.info(f"[migration] Dropped NOT NULL on {table}.{column}")
            except Exception as e:
                logger.warning(f"[migration] Could not drop NOT NULL on {table}.{column}: {e}")

        # 기존 사진 중 is_public이 NULL인 것들을 FALSE로 설정
        try:
            await conn.execute(text(
                "UPDATE photos SET is_public = FALSE WHERE is_public IS NULL"
            ))
            logger.info("[migration] Updated NULL is_public values to FALSE")
        except Exception:
            pass


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
