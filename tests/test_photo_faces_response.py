"""T-324: GET /photos/{id} + GET /photos/facility/{id} 응답에 PhotoFace bbox 노출 검증.

정책:
- 직원/운영자: faces[] 에 bbox + resident_name (있으면) + confidence.
- 보호자: faces=[] (다른 입소자 bbox 가 같은 사진에 있으면 PII 누출 → noexpose).
- is_rejected=True 얼굴은 모든 응답에서 제외.
- resident 가 매핑 안 된 (unmatched) 얼굴도 응답에 포함, resident_name=None.
"""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

import uuid
from datetime import datetime

import pytest

from app.core.security import SecurityService
from app.models.models import Facility, Guardian, Photo, PhotoFace, Resident, User


# T-324 테스트는 _enrich_photos_with_residents 가 부르는 storage.to_presigned()
# 가 실제 MinIO 에 connect 시도하지 않게 fake 로 치환한다.
class _FakeStorage:
    def to_presigned(self, url, expires_in=3600):
        return f"https://presigned/{url}"

    def get_url(self, key):
        return f"http://fake-minio/{key}"


@pytest.fixture(autouse=True)
def _patch_storage(monkeypatch):
    # _enrich_photos_with_residents 가 함수 본문에서 다시 `from app.core.storage
    # import get_storage` 하므로 source 모듈 자체를 패치해야 한다 (module-level alias 만
    # 바꾸면 회피됨).
    monkeypatch.setattr("app.core.storage.get_storage", lambda: _FakeStorage())
    monkeypatch.setattr("app.api.photos.get_storage", lambda: _FakeStorage())


async def _seed_facility(session, *, code: str = "FAC-T324") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name="햇살요양원", address="서울")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_staff(session, *, facility_id: str, email: str = "staff@x.io") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="직원",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="staff",
        is_active=True,
        is_staff_approved=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_guardian(
    session, *, facility_id: str, resident_id: str, email: str = "guardian@x.io"
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="보호자",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="guardian",
        is_active=True,
        phone="01099998888",
        phone_verified_at=datetime.utcnow(),
    )
    session.add(u)
    await session.commit()

    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=u.id,
        resident_id=resident_id,
        facility_id=facility_id,
        relationship_type="아들",
        is_approved=True,
    )
    session.add(g)
    await session.commit()
    return u


async def _seed_resident(session, *, facility_id: str, name: str = "김할머니") -> Resident:
    from tests._pii_seed import make_resident
    r = make_resident(facility_id=facility_id, name=name)
    session.add(r)
    await session.commit()
    return r


async def _seed_photo(
    session,
    *,
    facility_id: str,
    is_public: bool = True,
    resident_id: str | None = None,
) -> Photo:
    photo = Photo(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        resident_id=resident_id,
        original_url=f"facility/{facility_id}/photo.jpg",
        thumbnail_url=f"facility/{facility_id}/thumbnails/photo.jpg",
        is_processed=True,
        processing_status="completed",
        is_public=is_public,
    )
    session.add(photo)
    await session.commit()
    return photo


async def _seed_face(
    session,
    *,
    photo_id: str,
    resident_id: str | None = None,
    bbox: tuple[float, float, float, float] = (10.0, 20.0, 110.0, 120.0),
    confidence: float = 0.95,
    is_confirmed: bool = False,
    is_rejected: bool = False,
) -> PhotoFace:
    face = PhotoFace(
        id=str(uuid.uuid4()),
        photo_id=photo_id,
        resident_id=resident_id,
        bbox_x1=bbox[0],
        bbox_y1=bbox[1],
        bbox_x2=bbox[2],
        bbox_y2=bbox[3],
        confidence=confidence,
        is_confirmed=is_confirmed,
        is_rejected=is_rejected,
    )
    session.add(face)
    await session.commit()
    return face


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )
    return {"access_token": token}


# ---------------------------------------------------------------------------
# 직원: faces 노출
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staff_get_photo_returns_faces(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, facility_id=fac.id)
    resident = await _seed_resident(session, facility_id=fac.id, name="김할머니")
    photo = await _seed_photo(session, facility_id=fac.id, resident_id=resident.id)
    await _seed_face(
        session, photo_id=photo.id, resident_id=resident.id,
        bbox=(10.0, 20.0, 110.0, 120.0), confidence=0.95,
    )

    resp = await integration_client.get(
        f"/photos/{photo.id}", cookies=_auth_cookies(staff)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["faces"]) == 1
    face = body["faces"][0]
    assert face["bbox_x1"] == 10.0
    assert face["bbox_y2"] == 120.0
    assert face["resident_id"] == resident.id
    assert face["resident_name"] == "김할머니"
    assert face["confidence"] == 0.95


@pytest.mark.asyncio
async def test_staff_facility_list_returns_faces_per_photo(
    integration_client, integration_db
):
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, facility_id=fac.id)
    resident = await _seed_resident(session, facility_id=fac.id)
    photo1 = await _seed_photo(session, facility_id=fac.id)
    photo2 = await _seed_photo(session, facility_id=fac.id)
    await _seed_face(session, photo_id=photo1.id, resident_id=resident.id, confidence=0.9)
    await _seed_face(session, photo_id=photo1.id, resident_id=None, confidence=0.7)
    await _seed_face(session, photo_id=photo2.id, resident_id=resident.id, confidence=0.8)

    resp = await integration_client.get(
        f"/photos/facility/{fac.id}", cookies=_auth_cookies(staff)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    faces_by_photo = {p["id"]: p["faces"] for p in body}
    assert len(faces_by_photo[photo1.id]) == 2
    assert len(faces_by_photo[photo2.id]) == 1


@pytest.mark.asyncio
async def test_rejected_faces_excluded(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, facility_id=fac.id)
    resident = await _seed_resident(session, facility_id=fac.id)
    photo = await _seed_photo(session, facility_id=fac.id)
    await _seed_face(session, photo_id=photo.id, resident_id=resident.id, confidence=0.9)
    await _seed_face(
        session, photo_id=photo.id, resident_id=None, confidence=0.5, is_rejected=True
    )

    resp = await integration_client.get(
        f"/photos/{photo.id}", cookies=_auth_cookies(staff)
    )
    body = resp.json()
    assert len(body["faces"]) == 1
    assert body["faces"][0]["resident_id"] == resident.id


@pytest.mark.asyncio
async def test_unmatched_face_returned_with_null_resident_name(
    integration_client, integration_db
):
    """resident 가 매핑 안 된 얼굴 (분류 대기) 도 응답에 포함 — 직원이 검토 가능해야 함."""
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, facility_id=fac.id)
    photo = await _seed_photo(session, facility_id=fac.id)
    await _seed_face(session, photo_id=photo.id, resident_id=None, confidence=0.6)

    resp = await integration_client.get(
        f"/photos/{photo.id}", cookies=_auth_cookies(staff)
    )
    body = resp.json()
    assert len(body["faces"]) == 1
    assert body["faces"][0]["resident_id"] is None
    assert body["faces"][0]["resident_name"] is None


# ---------------------------------------------------------------------------
# 보호자: faces 노출 X
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guardian_get_photo_does_not_expose_faces(
    integration_client, integration_db
):
    """보호자는 자기 어르신의 사진 라이트박스에 접근 가능하지만 faces[] 는 빈 리스트.

    같은 사진에 다른 입소자 bbox 가 있으면 그 입소자가 함께 찍힌 것을 보호자에게
    노출하게 됨 → PII 누출.
    """
    _, session = integration_db
    fac = await _seed_facility(session)
    resident_a = await _seed_resident(session, facility_id=fac.id, name="A")
    resident_b = await _seed_resident(session, facility_id=fac.id, name="B")
    guardian = await _seed_guardian(
        session, facility_id=fac.id, resident_id=resident_a.id, email="ga@x.io"
    )
    photo = await _seed_photo(
        session, facility_id=fac.id, resident_id=resident_a.id, is_public=True
    )
    # A 와 B 둘 다 찍힌 사진.
    await _seed_face(session, photo_id=photo.id, resident_id=resident_a.id, confidence=0.9)
    await _seed_face(session, photo_id=photo.id, resident_id=resident_b.id, confidence=0.85)

    resp = await integration_client.get(
        f"/photos/{photo.id}", cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["faces"] == []
