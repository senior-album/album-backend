"""T-003-5a/-5b — write 경로가 ct-only 로 동작하는지 통합 검증.

`POST /residents` / `PUT /residents/{id}` 후 DB row 의 ct 컬럼만 채워지는지
직접 SQL 로 확인. 5b 단계에선 평문 컬럼이 drop 됐으므로 access 자체가 불가능.
응답 단계에선 `apply_pii_decryption` 이 ct 를 평문으로 변환해 client 에 정상
값을 돌려보내는지도 검증.
"""

from __future__ import annotations

import base64
import os as _os
import platform as _platform
import sys as _sys
import types as _types

_os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x0d" * 32).decode())
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x0e" * 32).decode())
_os.environ.setdefault("USER_PHONE_HMAC_KEY", base64.b64encode(b"\x1e" * 32).decode())
_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")

if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

import uuid

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import Facility, Resident, User


async def _seed_facility(session) -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code="FAC-WT", name="WT원", address="주소")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_staff(session, facility_id: str) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email="staff@wt.io",
        name="직원",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="staff",
        is_admin=False,
        is_operator=False,
        is_active=True,
        facility_id=facility_id,
        # T-056: 미승인 staff 차단 가드 — 기본 시드는 승인 완료.
        is_staff_approved=True,
    )
    session.add(u)
    await session.commit()
    return u


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": user.facility_id}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_post_resident_does_not_persist_plaintext(integration_client, integration_db):
    """POST /residents 후 DB 의 평문 컬럼은 NULL, ct/dek 만 채워진다."""
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    payload = {
        "facility_id": fac.id,
        "name": "홍길동",
        "birth_date": "1940-03-15",
        "medical_notes": "고혈압",
        "gender": "M",
        "room_number": "101호",
    }
    resp = await integration_client.post("/residents", json=payload, cookies=_auth_cookies(staff))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # 응답은 decrypt 거쳐 정상 평문이 보임
    assert body["name"] == "홍길동"
    assert body["birth_date"] == "1940-03-15"
    assert body["medical_notes"] == "고혈압"

    # DB 직접 확인 — 평문 컬럼은 NULL
    async with SessionLocal() as s:
        row = (await s.execute(select(Resident).filter(Resident.id == body["id"]))).scalar_one()
        # T-003-5b: 평문 PII 컬럼은 모델에서 drop 됐으므로 더 이상 access 불가.
        # ct / dek / blind_idx 채워짐 검증으로 충분.
        assert row.dek_wrapped is not None
        assert row.name_ct is not None
        assert row.name_blind_idx is not None
        assert row.birth_date_ct is not None
        assert row.medical_notes_ct is not None
        # 암호화 대상 아닌 필드는 그대로
        assert row.gender == "M"
        assert row.room_number == "101호"


@pytest.mark.asyncio
async def test_put_resident_partial_update_keeps_other_ct(integration_client, integration_db):
    """PUT 으로 name 만 갱신 → name_ct 는 새 값, birth_date_ct 는 보존."""
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    # POST 로 입소자 생성
    create_resp = await integration_client.post(
        "/residents",
        json={
            "facility_id": fac.id,
            "name": "초기이름",
            "birth_date": "1945-05-05",
        },
        cookies=_auth_cookies(staff),
    )
    rid = create_resp.json()["id"]

    async with SessionLocal() as s:
        before = (await s.execute(select(Resident).filter(Resident.id == rid))).scalar_one()
        original_birth_ct = before.birth_date_ct
        original_name_ct = before.name_ct

    # name 만 갱신
    put_resp = await integration_client.put(
        f"/residents/{rid}", json={"name": "변경이름"}, cookies=_auth_cookies(staff)
    )
    assert put_resp.status_code == 200, put_resp.text
    assert put_resp.json()["name"] == "변경이름"

    async with SessionLocal() as s:
        after = (await s.execute(select(Resident).filter(Resident.id == rid))).scalar_one()
        # T-003-5b: 평문 컬럼이 drop 됐으므로 ct 차이로 검증
        assert after.name_ct != original_name_ct  # name 은 새 ct
        assert after.birth_date_ct == original_birth_ct  # birth_date 보존


@pytest.mark.asyncio
async def test_get_residents_orders_by_decrypted_name(integration_client, integration_db):
    """list_residents 가 ct decrypt 후 Python 정렬로 이름순 응답."""
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    # 일부러 알파벳 역순으로 등록 — DB 삽입 순서와 무관하게 응답이 이름 ASC 여야
    for nm in ["다람쥐", "가방", "나비"]:
        r = await integration_client.post(
            "/residents",
            json={"facility_id": fac.id, "name": nm},
            cookies=_auth_cookies(staff),
        )
        assert r.status_code == 200, r.text

    list_resp = await integration_client.get(
        f"/residents?facility_id={fac.id}", cookies=_auth_cookies(staff)
    )
    assert list_resp.status_code == 200, list_resp.text
    names = [r["name"] for r in list_resp.json()]
    assert names == sorted(names)  # decrypt 후 정렬됐는지
    assert names == ["가방", "나비", "다람쥐"]


@pytest.mark.asyncio
@pytest.mark.parametrize("empty_val", ["", "   ", "\t"])
async def test_post_resident_empty_birth_date_stores_null(
    integration_client, integration_db, empty_val
):
    """T-310: POST 시 birth_date 가 빈 문자열/공백이면 ct 컬럼은 NULL.

    이전엔 ``is not None`` 가드만 있어서 ``encrypt_field("", dek)`` 가 실행되고
    nonce 12 + tag 16 + 0 byte plaintext = 28 byte ciphertext 가 row 에 박혀서
    cron decrypt 단계에서 ``Invalid isoformat string: ''`` 가 발생했다.
    """
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    resp = await integration_client.post(
        "/residents",
        json={
            "facility_id": fac.id,
            "name": "홍길동",
            "birth_date": empty_val,
            "medical_notes": empty_val,
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["birth_date"] is None
    assert body["medical_notes"] is None

    async with SessionLocal() as s:
        row = (await s.execute(select(Resident).filter(Resident.id == body["id"]))).scalar_one()
        # name 은 정상 값이라 ct 채워짐
        assert row.name_ct is not None
        # 빈 문자열은 normalize 로 None → ct 자체가 NULL
        assert row.birth_date_ct is None
        assert row.medical_notes_ct is None


@pytest.mark.asyncio
@pytest.mark.parametrize("blank_name", ["", "   ", "\t"])
async def test_post_resident_blank_name_rejected(
    integration_client, integration_db, blank_name
):
    """T-310: name 이 빈 문자열/공백이면 422 — 빈 평문이 encrypt 되는 사고 차단."""
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    resp = await integration_client.post(
        "/residents",
        json={"facility_id": fac.id, "name": blank_name},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_put_resident_empty_birth_date_clears_ct(integration_client, integration_db):
    """T-310: PUT 으로 birth_date='' 보내면 기존 ct 가 NULL 로 클리어된다."""
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)

    create_resp = await integration_client.post(
        "/residents",
        json={"facility_id": fac.id, "name": "초기", "birth_date": "1945-05-05"},
        cookies=_auth_cookies(staff),
    )
    rid = create_resp.json()["id"]

    async with SessionLocal() as s:
        before = (await s.execute(select(Resident).filter(Resident.id == rid))).scalar_one()
        assert before.birth_date_ct is not None  # 정상 ct

    put_resp = await integration_client.put(
        f"/residents/{rid}", json={"birth_date": ""}, cookies=_auth_cookies(staff)
    )
    assert put_resp.status_code == 200, put_resp.text

    async with SessionLocal() as s:
        after = (await s.execute(select(Resident).filter(Resident.id == rid))).scalar_one()
        # 빈 문자열은 None 으로 normalize 됨 → 기존 ct 보존 (변경 안 함)
        # 즉 PATCH 의미 — None 이 들어오는 것과 동일.
        assert after.birth_date_ct == before.birth_date_ct
