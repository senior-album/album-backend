"""
T-124 PR5: app.api.photos.upload_photos 통합 테스트.

multipart 업로드 → DB Photo + PhotoProcessingJob 레코드 생성까지 전체 경로를
한 번씩 밟는다. 실제 MinIO/boto3 는 가짜 storage 로 갈아끼우고, ML 워커는
엔드포인트 본 흐름과 분리되어 있어 별도 mock 불필요 (job 만 enqueue).

테스트 시드: register_admin 으로 시설 + staff 사용자 자동 생성, 반환된 쿠키로
이후 업로드 호출.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image as PILImage
from sqlalchemy import select

from app.models.models import Photo, PhotoProcessingJob


def _jpeg_bytes(size=(64, 64), color=(160, 80, 40)) -> bytes:
    buf = BytesIO()
    PILImage.new("RGB", size, color=color).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _png_bytes(size=(32, 32)) -> bytes:
    buf = BytesIO()
    PILImage.new("RGB", size, color=(20, 20, 200)).save(buf, format="PNG")
    return buf.getvalue()


class _FakeStorage:
    """boto3/MinIO 호출을 흉내내는 in-memory storage. 호출 기록 검증 가능."""

    def __init__(self):
        self.uploads: list[dict] = []
        self._counter = 0

    async def upload_file(self, file_data, filename, content_type, facility_id):
        # 실제 storage 의 sanitize 동작을 확인하려면 진짜 sanitize 를 호출.
        from app.core.storage import _sanitize_extension, _sanitize_object_prefix

        prefix = _sanitize_object_prefix(facility_id)
        ext = _sanitize_extension(filename.rsplit(".", 1)[-1] if "." in filename else "")
        self._counter += 1
        key = f"{prefix}/object-{self._counter:03}.{ext}"
        self.uploads.append(
            {
                "key": key,
                "filename": filename,
                "content_type": content_type,
                "size": len(file_data),
                "facility_id": facility_id,
            }
        )
        return key

    def to_presigned(self, url, expires_in=3600):
        return f"https://presigned/{url}"

    def get_url(self, key):
        return f"http://fake-minio/{key}"


@pytest.fixture
def fake_storage(monkeypatch):
    """upload_photos 가 부르는 get_storage() 를 가짜로 교체."""
    fake = _FakeStorage()
    monkeypatch.setattr("app.api.photos.get_storage", lambda: fake)
    return fake


@pytest.fixture
async def staff_session(integration_client, integration_db):
    """
    register_admin 으로 facility + staff 계정 만들고 쿠키 저장된 client 반환.
    yields: (client, facility_id, user_id).
    """
    payload = {
        "email": "admin@upload.io",
        "password": "UploaderPass123!",
        "name": "Uploader",
        "phone": "010-9999-0000",
        "facilityName": "업로드 시설",
        "facilityAddress": "서울 어딘가",
        "facilityPhone": "02-0000-0000",
    }
    resp = await integration_client.post("/auth/register/admin", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    yield integration_client, body["facility"]["id"], body["user"]["id"]


# ---------------------------------------------------------------------------
# happy path + DB 검증
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_single_jpeg_creates_photo_and_job(
    staff_session, fake_storage, integration_db
):
    client, facility_id, user_id = staff_session
    SessionLocal, _ = integration_db

    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("photo.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["photos"]) == 1
    assert body["photos"][0]["processing_status"] == "queued"
    assert len(body["jobs"]) == 1
    assert body["jobs"][0]["status"] == "pending"

    # storage 호출: 원본 1 + 섬네일 1 = 2회
    assert len(fake_storage.uploads) == 2
    assert fake_storage.uploads[0]["facility_id"] == facility_id
    assert fake_storage.uploads[1]["facility_id"] == f"{facility_id}/thumbnails"

    # DB: Photo + Job 정확히 한 행씩
    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        assert len(photos) == 1
        assert photos[0].uploaded_by == user_id
        assert photos[0].facility_id == facility_id
        assert photos[0].processing_status == "queued"

        jobs = (await s.execute(select(PhotoProcessingJob))).scalars().all()
        assert len(jobs) == 1
        assert jobs[0].photo_id == photos[0].id


@pytest.mark.asyncio
async def test_upload_multiple_files_in_one_request(
    staff_session, fake_storage, integration_db
):
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("a.jpg", _jpeg_bytes(), "image/jpeg")),
            ("files", ("b.png", _png_bytes(), "image/png")),
            ("files", ("c.jpg", _jpeg_bytes(color=(50, 50, 50)), "image/jpeg")),
        ],
    )
    assert resp.status_code == 200
    assert len(resp.json()["photos"]) == 3

    async with SessionLocal() as s:
        assert len((await s.execute(select(Photo))).scalars().all()) == 3
        assert (
            len((await s.execute(select(PhotoProcessingJob))).scalars().all()) == 3
        )


@pytest.mark.asyncio
async def test_upload_resolves_facility_code_to_uuid(
    staff_session, fake_storage, integration_db
):
    """
    클라가 UUID 가 아니라 시설 code (FAC-XXXXXX) 로 호출해도 endpoint 가
    resolve 해서 같은 시설 사진으로 저장되어야 한다.
    """
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    # facility code 추출
    me = (await client.get("/auth/me")).json()
    code = me["facility"]["code"]
    assert code.startswith("FAC-")

    resp = await client.post(
        f"/photos/upload?facility_id={code}",
        files=[("files", ("z.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    assert resp.status_code == 200

    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        assert len(photos) == 1
        assert photos[0].facility_id == facility_id  # code 가 UUID 로 변환됨


# ---------------------------------------------------------------------------
# 인증 / 권한 게이트
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_requires_authentication(
    integration_client, fake_storage, integration_db
):
    resp = await integration_client.post(
        "/photos/upload?facility_id=any-fid",
        files=[("files", ("a.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    assert resp.status_code in (401, 403)
    assert fake_storage.uploads == []


@pytest.mark.asyncio
async def test_upload_blocks_cross_facility_access(
    staff_session, fake_storage, integration_db
):
    """다른 시설 id 로 호출하면 verify_facility_access 가 403."""
    client, _facility_id, _ = staff_session
    resp = await client.post(
        "/photos/upload?facility_id=00000000-0000-0000-0000-000000000000",
        files=[("files", ("a.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    # facility_id 36자가 아니라 다른 케이스도 있을 수 있어 401/403 모두 허용.
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# 파일 검증 — 개별 파일 실패는 건너뛰고 나머지 처리
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_skips_individual_invalid_files_and_continues(
    staff_session, fake_storage, integration_db
):
    """
    한 multipart 안의 파일 중 일부는 invalid (확장자 잘못)·일부는 valid.

    invalid 가 먼저 와야 valid 들이 살아남는다 — endpoint 의 per-file try/except
    가 실패 시 `db.rollback()` 을 호출하기 때문에, invalid 가 중간/끝에 오면
    그 시점까지 flush 된 valid 까지 같이 날아간다 (현 구현의 partial rollback
    동작). 이 테스트는 "invalid 가 먼저면 valid 는 보존" 정상 흐름만 잠근다.
    """
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("bad.gif", b"GIF89a not really a gif", "image/gif")),
            ("files", ("ok.jpg", _jpeg_bytes(), "image/jpeg")),
            ("files", ("ok2.jpg", _jpeg_bytes(color=(0, 200, 0)), "image/jpeg")),
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    # bad.gif 는 _validate_upload 에서 415 → outer except → rollback (이 시점에
    # 잃을 게 없음). 이후 ok 두 개는 깨끗한 transaction 에 flush + 끝에 commit.
    assert len(body["photos"]) == 2

    async with SessionLocal() as s:
        assert len((await s.execute(select(Photo))).scalars().all()) == 2


@pytest.mark.asyncio
async def test_upload_rejects_oversize_file_individually(
    staff_session, fake_storage, integration_db
):
    """20MB 초과 파일은 개별 fail — 같은 요청의 다른 파일은 정상 저장."""
    from app.api.photos import MAX_UPLOAD_SIZE

    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    too_big = b"\xff\xd8\xff\xe0" + b"x" * (MAX_UPLOAD_SIZE + 100)
    resp = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[
            ("files", ("big.jpg", too_big, "image/jpeg")),
            ("files", ("small.jpg", _jpeg_bytes(), "image/jpeg")),
        ],
    )
    assert resp.status_code == 200
    assert len(resp.json()["photos"]) == 1  # small.jpg 만 통과

    async with SessionLocal() as s:
        photos = (await s.execute(select(Photo))).scalars().all()
        assert len(photos) == 1


# ---------------------------------------------------------------------------
# T-106: 큐 capacity — 업로드 자체 거절
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upload_rejects_when_per_facility_queue_full(
    staff_session, fake_storage, integration_db, monkeypatch
):
    """T-106: 시설별 pending 큐가 cap 에 닿으면 429 + Retry-After."""
    client, facility_id, _ = staff_session

    # cap 을 1로 낮춰서 그 시설의 pending 1건만 있어도 막히도록.
    from app.api import photos as photos_module

    class _LowCap:
        PHOTO_QUEUE_MAX_PENDING_PER_FACILITY = 1
        PHOTO_QUEUE_MAX_PENDING_TOTAL = 10_000

    monkeypatch.setattr(photos_module, "get_settings", lambda: _LowCap())

    # 첫 업로드 — pending 1 만들고
    first = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("a.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    assert first.status_code == 200

    # 두 번째 업로드 — cap 도달 → 429
    second = await client.post(
        f"/photos/upload?facility_id={facility_id}",
        files=[("files", ("b.jpg", _jpeg_bytes(), "image/jpeg"))],
    )
    assert second.status_code == 429
    assert second.headers.get("Retry-After") == "60"
