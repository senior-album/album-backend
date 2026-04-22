"""
/facilities/search 엔드포인트 테스트
"""

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_search_requires_min_query_length(client):
    """q 파라미터가 2자 미만이면 422 반환 (pydantic Query 검증)"""
    response = client.get("/facilities/search", params={"q": "a"})
    assert response.status_code == 422


def test_search_requires_q_param(client):
    """q 파라미터 누락 시 422 반환"""
    response = client.get("/facilities/search")
    assert response.status_code == 422


def test_search_is_unauthenticated(client):
    """회원가입 전 단계에서 호출되므로 인증 없이 접근 가능해야 함"""
    response = client.get("/facilities/search", params={"q": "행복"})
    # DB 연결 실패로 500 날 수 있으나, 401/403 은 안 나야 함
    assert response.status_code not in (401, 403)


def test_search_limit_cap(client):
    """limit 은 20 을 초과할 수 없음"""
    response = client.get("/facilities/search", params={"q": "행복", "limit": 100})
    assert response.status_code == 422
