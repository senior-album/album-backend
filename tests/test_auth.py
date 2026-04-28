"""
인증 API 통합 테스트 (스모크 — endpoint 가 dep 풀고 validation 까지 도달하는지).

T-124: integration_client fixture 로 lifespan 우회. 풀 통합 테스트
(register → login → refresh → logout 플로우) 는 다음 PR 에서 빌드.
"""

import pytest


@pytest.mark.asyncio
async def test_register_guardian_rejects_empty_body(integration_client):
    """body 누락 시 pydantic 422."""
    resp = await integration_client.post("/auth/register/guardian", json={})
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_register_guardian_requires_password(integration_client):
    """password 누락 시 pydantic 422 — 필수 필드 검증이 dep_override 환경에서도 동작."""
    resp = await integration_client.post(
        "/auth/register/guardian",
        json={"email": "g@example.com", "name": "Guardian"},
    )
    assert resp.status_code == 422
    body = resp.json()
    assert any("password" in str(err.get("loc", [])) for err in body.get("detail", []))


@pytest.mark.asyncio
async def test_get_me_requires_auth(integration_client):
    """토큰 없이 /auth/me 접근 → 401/403."""
    resp = await integration_client.get("/auth/me")
    assert resp.status_code in (401, 403)
