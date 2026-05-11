"""
T-314: 사진 삭제 통합 테스트.

`_delete_photo` 가 photo_audit_logs / photo_processing_jobs 의 photo_id FK
(NOT NULL, ON DELETE 미지정) 행을 cleanup 안 해서 단건 / 다중 모두 항상
IntegrityError → 500 이던 회귀. 이 테스트는 upload → delete → 모든 FK 행이
정리됐는지 잠근다.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from PIL import Image as PILImage
from sqlalchemy import select

from app.models.models import (
    Notification,
    Photo,
    PhotoAuditLog,
    PhotoProcessingJob,
)


def _jpeg_bytes(size=(64, 64), color=(160, 80, 40)) -> bytes:
    buf = BytesIO()
    PILImage.new("RGB", size, color=color).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


class _FakeStorage:
    def __init__(self):
        self.uploads: list[dict] = []
        self.deletes: list[str] = []
        self._counter = 0

    async def upload_file(self, file_data, filename, content_type, facility_id):
        from app.core.storage import _sanitize_extension, _sanitize_object_prefix

        prefix = _sanitize_object_prefix(facility_id)
        ext = _sanitize_extension(filename.rsplit(".", 1)[-1] if "." in filename else "")
        self._counter += 1
        key = f"{prefix}/object-{self._counter:03}.{ext}"
        self.uploads.append({"key": key, "facility_id": facility_id})
        return key

    async def delete_file(self, key):
        self.deletes.append(key)

    def extract_object_key(self, key):
        return key

    def to_presigned(self, url, expires_in=3600):
        return f"https://presigned/{url}"

    def get_url(self, key):
        return f"http://fake-minio/{key}"


@pytest.fixture
def fake_storage(monkeypatch):
    fake = _FakeStorage()
    monkeypatch.setattr("app.api.photos.get_storage", lambda: fake)
    return fake


@pytest.fixture
async def staff_session(integration_client, integration_db):
    payload = {
        "email": "admin@delete.io",
        "password": "DeleterPass123!",
        "name": "Deleter",
        "phone": "010-8888-0000",
        "facilityName": "삭제 시설",
        "facilityAddress": "서울 어딘가",
        "facilityPhone": "02-0000-0000",
    }
    resp = await integration_client.post("/auth/register/admin", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    yield integration_client, body["facility"]["id"], body["user"]["id"]


async def _upload(client, facility_id, n=1):
    files = [
        ("files", (f"p{i}.jpg", _jpeg_bytes(color=(i * 30 % 255, 80, 40)), "image/jpeg"))
        for i in range(n)
    ]
    resp = await client.post(f"/photos/upload?facility_id={facility_id}", files=files)
    assert resp.status_code == 200, resp.text
    return [p["id"] for p in resp.json()["photos"]]


@pytest.mark.asyncio
async def test_delete_single_photo_clears_processing_job(
    staff_session, fake_storage, integration_db
):
    """단건 삭제: PhotoProcessingJob (NOT NULL FK) 함께 정리 → 200."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    [pid] = await _upload(client, facility_id, n=1)

    async with SessionLocal() as s:
        assert len((await s.execute(select(PhotoProcessingJob))).scalars().all()) == 1

    resp = await client.delete(f"/photos/{pid}")
    assert resp.status_code == 200, resp.text

    async with SessionLocal() as s:
        assert (await s.execute(select(Photo))).scalars().all() == []
        assert (await s.execute(select(PhotoProcessingJob))).scalars().all() == []
        assert (await s.execute(select(PhotoAuditLog))).scalars().all() == []


@pytest.mark.asyncio
async def test_delete_single_photo_with_audit_log(
    staff_session, fake_storage, integration_db
):
    """
    PhotoAuditLog 가 1행 이상 있어도 (조회 등으로 audit 가 쌓인 사진) 삭제 시
    함께 정리되고 200. fix 전엔 audit FK 위반으로 500.
    """
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    [pid] = await _upload(client, facility_id, n=1)

    # 사진 조회 → PhotoAuditLog action="view" enqueue (T-101)
    await client.get(f"/photos/{pid}")

    async with SessionLocal() as s:
        audits = (await s.execute(select(PhotoAuditLog))).scalars().all()
        assert len(audits) >= 1, "사진 조회 시 audit row 가 최소 1개 있어야 함"

    resp = await client.delete(f"/photos/{pid}")
    assert resp.status_code == 200, resp.text

    async with SessionLocal() as s:
        assert (await s.execute(select(Photo))).scalars().all() == []
        assert (await s.execute(select(PhotoAuditLog))).scalars().all() == []


@pytest.mark.asyncio
async def test_bulk_delete_photos(staff_session, fake_storage, integration_db):
    """다중 삭제: N개 모두 cleanup."""
    client, facility_id, _ = staff_session
    SessionLocal, _ = integration_db

    pids = await _upload(client, facility_id, n=3)

    resp = await client.post("/photos/bulk-delete", json=pids)
    assert resp.status_code == 200, resp.text
    assert resp.json()["deleted"] == 3

    async with SessionLocal() as s:
        assert (await s.execute(select(Photo))).scalars().all() == []
        assert (await s.execute(select(PhotoProcessingJob))).scalars().all() == []


@pytest.mark.asyncio
async def test_delete_photo_nulls_notification_photo_id(
    staff_session, fake_storage, integration_db
):
    """
    Notification.photo_id 는 nullable FK 지만 ON DELETE 미지정이라 RESTRICT.
    photo 삭제 시 NULL update 로 처리 → 200 + 알림 자체는 보존.
    """
    client, facility_id, user_id = staff_session
    SessionLocal, _ = integration_db

    [pid] = await _upload(client, facility_id, n=1)

    # 같은 사진을 참조하는 Notification 1행 직접 생성.
    async with SessionLocal() as s:
        import uuid as _uuid
        from datetime import datetime

        s.add(
            Notification(
                id=str(_uuid.uuid4()),
                user_id=user_id,
                photo_id=pid,
                title="t",
                message="m",
                notification_type="photo_uploaded",
                is_read=False,
                is_sent=False,
                created_at=datetime.utcnow(),
            )
        )
        await s.commit()

    resp = await client.delete(f"/photos/{pid}")
    assert resp.status_code == 200, resp.text

    async with SessionLocal() as s:
        notifs = (await s.execute(select(Notification))).scalars().all()
        assert len(notifs) == 1
        assert notifs[0].photo_id is None
