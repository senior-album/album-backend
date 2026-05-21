"""T-325: 같은 시설 내 동일 파일 (SHA-256 일치) 중복 업로드 차단 통합 테스트.

dup check 정책:
- 같은 시설 (`facility_id`) 안에서만 hash 비교 — 다른 시설은 격리.
- 한 batch 안 중복도 잡힘 (`duplicate_in_batch`) — 첫 한 장만 업로드, 나머지 skip.
- DB 에 기존 사진이면 `duplicate_in_facility` — `existing_photo_id` 반환.
- 신규 사진은 `Photo.file_hash` 채워서 저장.

업로드 응답 추가 필드:
- `duplicates: [{filename, file_hash, existing_photo_id?, duplicate_of_filename?, reason}]`
- `message` 가 "M장 업로드, 중복 N장 건너뜀" 형태로 부분 성공 반영.
"""

from __future__ import annotations

import hashlib
from io import BytesIO

import pytest
from PIL import Image as PILImage
from sqlalchemy import select

from app.models.models import Photo


# 기존 통합 테스트의 fake_storage / staff_session 픽스처를 그대로 활용한다 —
# pytest 가 같은 패키지의 fixture 를 모듈 간에 공유하지 않으므로 conftest 가 아닌
# 직접 import (테스트 모듈 함수는 보통 import 되지 않지만 pytest fixture 자체는
# 모듈 함수라 재사용 위해선 import 하면 됨).
from tests.test_photos_upload_integration import (  # noqa: F401  (fixture re-export)
    fake_storage,
    staff_session,
    _jpeg_bytes,
)


def _file_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.mark.asyncio
async def test_upload_first_time_records_file_hash(
    staff_session, fake_storage, integration_db
):
    """신규 업로드 시 Photo.file_hash 가 채워진다."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    data = _jpeg_bytes()
    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("a.jpg", data, "image/jpeg"))],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["photos"]) == 1
    assert body["duplicates"] == []

    async with SessionLocal() as s:
        photo = (await s.execute(select(Photo))).scalars().one()
        assert photo.file_hash == _file_hash(data)


@pytest.mark.asyncio
async def test_upload_same_file_twice_second_is_duplicate(
    staff_session, fake_storage, integration_db
):
    """이미 같은 시설에 같은 hash 의 사진이 있으면 두 번째는 reject + 기존 id 반환."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    data = _jpeg_bytes()
    resp1 = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("first.jpg", data, "image/jpeg"))],
    )
    assert resp1.status_code == 200
    first_id = resp1.json()["photos"][0]["id"]

    resp2 = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("second.jpg", data, "image/jpeg"))],
    )
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert body2["photos"] == []
    assert len(body2["duplicates"]) == 1
    dup = body2["duplicates"][0]
    assert dup["filename"] == "second.jpg"
    assert dup["file_hash"] == _file_hash(data)
    assert dup["existing_photo_id"] == first_id
    assert dup["reason"] == "duplicate_in_facility"

    # DB 에는 row 가 여전히 한 개.
    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        assert len(photos) == 1


@pytest.mark.asyncio
async def test_upload_batch_with_internal_duplicates(
    staff_session, fake_storage, integration_db
):
    """한 batch 안에 같은 파일이 두 번 들어와도 한 장만 업로드, 나머지는 dup."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    same = _jpeg_bytes()
    other = _jpeg_bytes(color=(40, 200, 40))
    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("first.jpg", same, "image/jpeg")),
            ("files", ("clone.jpg", same, "image/jpeg")),
            ("files", ("other.jpg", other, "image/jpeg")),
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["photos"]) == 2  # first + other
    assert len(body["duplicates"]) == 1
    dup = body["duplicates"][0]
    assert dup["filename"] == "clone.jpg"
    assert dup["reason"] == "duplicate_in_batch"
    assert dup["duplicate_of_filename"] == "first.jpg"

    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        assert len(photos) == 2
        hashes = {p.file_hash for p in photos}
        assert hashes == {_file_hash(same), _file_hash(other)}


@pytest.mark.asyncio
async def test_upload_all_duplicates_returns_empty_photos(
    staff_session, fake_storage, integration_db
):
    """전부 기존 시설 사진과 중복이면 photos[] 는 비어있고 메시지가 안내."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    data = _jpeg_bytes()
    # seed
    await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("seed.jpg", data, "image/jpeg"))],
    )

    # 같은 파일 두 번 재시도
    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("retry1.jpg", data, "image/jpeg")),
            ("files", ("retry2.jpg", data, "image/jpeg")),
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["photos"] == []
    assert body["jobs"] == []
    assert len(body["duplicates"]) == 2
    assert "이미 업로드된" in body["message"]


@pytest.mark.asyncio
async def test_upload_partial_success_message(
    staff_session, fake_storage, integration_db
):
    """일부 중복 + 일부 신규일 때 message 가 두 건수 다 반영."""
    client, facility_id, _ = staff_session

    seed_data = _jpeg_bytes()
    await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("seed.jpg", seed_data, "image/jpeg"))],
    )

    new_data = _jpeg_bytes(color=(10, 10, 200))
    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("dup.jpg", seed_data, "image/jpeg")),  # dup
            ("files", ("new.jpg", new_data, "image/jpeg")),  # new
        ],
    )
    body = resp.json()
    assert len(body["photos"]) == 1
    assert len(body["duplicates"]) == 1
    assert "1장의 사진" in body["message"]
    assert "건너뜀" in body["message"]


@pytest.mark.asyncio
async def test_different_facilities_can_have_same_hash(
    integration_client, fake_storage, integration_db
):
    """시설 격리 — 다른 시설의 같은 hash 사진은 dup 으로 안 잡힘."""
    SessionLocal, session = integration_db

    # 두 개 시설 + staff 각각
    payload_a = {
        "email": "a@dup.io",
        "password": "PassA12345!",
        "name": "A",
        "phone": "010-1111-1111",
        "facilityName": "A시설",
        "facilityAddress": "어딘가",
        "facilityPhone": "02-1111-1111",
    }
    payload_b = {
        "email": "b@dup.io",
        "password": "PassB12345!",
        "name": "B",
        "phone": "010-2222-2222",
        "facilityName": "B시설",
        "facilityAddress": "어딘가",
        "facilityPhone": "02-2222-2222",
    }
    resp_a = await integration_client.post("/auth/register/admin", json=payload_a)
    resp_b = await integration_client.post("/auth/register/admin", json=payload_b)
    fac_a = resp_a.json()["facility"]["id"]
    fac_b = resp_b.json()["facility"]["id"]

    data = _jpeg_bytes()

    # A 시설에 업로드 — 같은 client 의 마지막 쿠키 = B 시설 staff. 다시 A 로 로그인.
    login_a = await integration_client.post(
        "/auth/login", json={"email": "a@dup.io", "password": "PassA12345!"}
    )
    assert login_a.status_code == 200
    resp1 = await integration_client.post(
        f"/photos/upload?facility_id={fac_a}",
        files=[("files", ("same.jpg", data, "image/jpeg"))],
    )
    assert resp1.status_code == 200
    assert len(resp1.json()["photos"]) == 1

    # B 시설 staff 로 전환 후 같은 hash 의 사진 업로드.
    login_b = await integration_client.post(
        "/auth/login", json={"email": "b@dup.io", "password": "PassB12345!"}
    )
    assert login_b.status_code == 200
    resp2 = await integration_client.post(
        f"/photos/upload?facility_id={fac_b}",
        files=[("files", ("same.jpg", data, "image/jpeg"))],
    )
    assert resp2.status_code == 200
    body2 = resp2.json()
    assert len(body2["photos"]) == 1
    assert body2["duplicates"] == []

    # DB: 같은 hash 가 두 시설에 각각 한 행씩.
    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        hashes_by_fac = {(p.facility_id, p.file_hash) for p in photos}
        assert (fac_a, _file_hash(data)) in hashes_by_fac
        assert (fac_b, _file_hash(data)) in hashes_by_fac
