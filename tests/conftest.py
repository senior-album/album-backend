"""
pytest 설정 및 공유 피크스처

T-124: 무거운 의존성(app.main → 라우터 → ML 패키지)은 fixture 내부에서 lazy
import 한다. 모듈 로드 시 끌어오면 순수 단위 테스트(예: test_security_unit)
까지 ML 스택을 짊어져야 해서 collection 단계가 분 단위로 느려지거나 일부
환경(Windows + albumentations/dlib)에서 segfault 까지 난다.
"""

import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from app.models.models import Base


@pytest.fixture
async def test_db():
    """테스트 데이터베이스 세션 (legacy fixture — 신규 테스트는 integration_db 권장)"""
    from app.main import app
    from app.core.database import get_db

    # 메모리 SQLite 사용
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    TestingSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with TestingSessionLocal() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    try:
        yield TestingSessionLocal
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()


# ---------------------------------------------------------------------------
# 통합 테스트 인프라 (T-124 PR A)
# ---------------------------------------------------------------------------


@pytest.fixture
async def integration_db():
    """
    인메모리 SQLite + `Database.get_db` dependency override.

    `StaticPool` 로 모든 connection 이 같은 in-memory DB 를 공유하게 한다 —
    그래야 route handler 가 만든 데이터를 테스트 코드 세션에서도 볼 수 있다
    (sqlite `:memory:` 는 connection 마다 별도 DB 라 StaticPool 없으면 격리됨).

    yields: `(SessionLocal, async_session)` 튜플.
      - SessionLocal: 테스트가 추가 세션을 열고 싶을 때
      - async_session: seed/assert 용으로 즉시 쓸 수 있는 한 개 세션

    `app.main` 의 lifespan 은 거치지 않으므로 `Database._session_local` 은 여전히
    None — 하지만 dep_override 가 `get_db` 를 가로채기에 endpoint 는 정상 동작.
    """
    from app.core.database import get_db
    from app.main import app

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def _override():
        # `Database.get_session` 의 동작을 그대로 흉내내야 한다 — 일부 route 는
        # 명시적 `db.commit()` 을 안 하고 wrapper 의 yield-후-commit 에 의존
        # (예: register_admin). auto-commit 안 하면 테스트 코드 세션이 빈 DB 만
        # 보게 돼서 "0 rows" 실패.
        async with SessionLocal() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = _override
    try:
        async with SessionLocal() as session:
            yield SessionLocal, session
    finally:
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()


@pytest.fixture
async def integration_client(integration_db):
    """
    httpx.AsyncClient + ASGITransport 로 FastAPI 앱에 직접 ASGI 호출.

    실제 lifespan / Redis / OpenSearch / MinIO 는 거치지 않는다 — 호출자가
    필요하면 monkeypatch 로 추가 stub. `integration_db` 가 자동으로 의존성
    먼저 set 되어 endpoint 의 `get_db` 가 동작.

    base_url 을 `https://` 로 둬야 한다 — `set_auth_cookie` 가 prod 환경
    (`DEBUG=False`) 에선 `Secure` 플래그를 박아 발급하는데, http 로 받으면
    httpx 가 다음 요청에 그 쿠키를 안 보내서 모든 후속 호출이 401. ASGITransport
    는 실제 TLS 를 안 하지만 scheme 만 https 면 쿠키 jar 가 정상 동작.
    """
    from httpx import ASGITransport, AsyncClient

    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="https://test") as client:
        yield client


@pytest.fixture
def client():
    """동기 TestClient (legacy 호환). 신규 테스트는 integration_client 권장."""
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


@pytest.fixture
def auth_headers():
    """테스트용 인증 헤더"""
    # 테스트용 JWT 토큰
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJyb2xlIjoic3RhZmYifQ.test"

    return {
        "Authorization": f"Bearer {test_token}"
    }
