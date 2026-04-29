"""
/facilities/search 엔드포인트 테스트

T-124: integration_client fixture 로 lifespan 우회 + DB dep override.
회원가입 전 시설 피커용이라 인증 불필요.
"""

import pytest


@pytest.mark.asyncio
async def test_search_requires_min_query_length(integration_client):
    """q 파라미터가 2자 미만이면 422 반환 (pydantic Query 검증)"""
    resp = await integration_client.get("/facilities/search", params={"q": "a"})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_requires_q_param(integration_client):
    """q 파라미터 누락 시 422 반환"""
    resp = await integration_client.get("/facilities/search")
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_search_is_unauthenticated(integration_client):
    """회원가입 전 단계에서 호출되므로 인증 없이 접근 가능해야 함."""
    resp = await integration_client.get("/facilities/search", params={"q": "행복"})
    # 빈 DB 라 결과는 [] 지만 200 으로 통과해야 한다.
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_search_limit_cap(integration_client):
    """limit 은 20 을 초과할 수 없음"""
    resp = await integration_client.get(
        "/facilities/search", params={"q": "행복", "limit": 100}
    )
    assert resp.status_code == 422
