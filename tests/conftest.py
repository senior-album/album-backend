"""
pytest 설정 및 공유 피크스처
"""

import pytest
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db
from app.models.models import Base


@pytest.fixture
async def test_db():
    """테스트 데이터베이스 세션"""
    # 메모리 SQLite 사용
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with TestingSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    yield TestingSessionLocal

    await engine.dispose()


@pytest.fixture
def client():
    """테스트 클라이언트"""
    return TestClient(app)


@pytest.fixture
def auth_headers():
    """테스트용 인증 헤더"""
    # 테스트용 JWT 토큰
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJyb2xlIjoic3RhZmYifQ.test"

    return {
        "Authorization": f"Bearer {test_token}"
    }
