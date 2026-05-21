"""T-320-2 dual-write hook 검증 — User/Facility/Invitation/PhoneClaimReport.

ORM event listener 가 평문 phone 컬럼 set 시점에 phone_ct + phone_bi 를 자동으로
채우는지, 빈 phone 일 때 NULL 유지하는지, 같은 정규화 결과를 가진 다른 포맷 입력이
같은 bi 를 만드는지 확인한다.
"""

from __future__ import annotations

import base64
import os
import platform
import sys
import types
import uuid

# Windows libmagic segfault 회피.
if platform.system() == "Windows" and "magic" not in sys.modules:
    _stub = types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    sys.modules["magic"] = _stub

# Settings 필수 env (다른 테스트와 동일 패턴).
os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x40" * 32).decode())
os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x41" * 32).decode())
os.environ.setdefault("USER_PHONE_HMAC_KEY", base64.b64encode(b"\x50" * 32).decode())

import pytest
from sqlalchemy import select

from app.core.crypto import decrypt_phone, phone_blind_index
from app.models.models import (
    Facility,
    Invitation,
    PhoneClaimReport,
    Resident,
    User,
)


pytestmark = pytest.mark.asyncio


def _new_user(*, phone: str | None) -> User:
    return User(
        id=str(uuid.uuid4()),
        email=f"u-{uuid.uuid4().hex[:8]}@example.com",
        name="이름",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="guardian",
        is_admin=False,
        is_operator=False,
        is_active=True,
        phone=phone,
    )


async def test_user_phone_set_populates_ct_and_bi(integration_db):
    _, s = integration_db
    u = _new_user(phone="010-1234-5678")
    s.add(u)
    await s.commit()

    row = (await s.execute(select(User).filter(User.id == u.id))).scalar_one()
    assert row.phone == "010-1234-5678"
    assert row.phone_ct is not None
    assert row.phone_bi is not None
    assert decrypt_phone(row.phone_ct) == "01012345678"
    assert row.phone_bi == phone_blind_index("01012345678")


async def test_user_phone_empty_keeps_ct_bi_null(integration_db):
    _, s = integration_db
    u = _new_user(phone=None)
    s.add(u)
    await s.commit()
    row = (await s.execute(select(User).filter(User.id == u.id))).scalar_one()
    assert row.phone_ct is None
    assert row.phone_bi is None

    u2 = _new_user(phone="")
    s.add(u2)
    await s.commit()
    row2 = (await s.execute(select(User).filter(User.id == u2.id))).scalar_one()
    assert row2.phone_ct is None
    assert row2.phone_bi is None


async def test_user_phone_update_rewrites_ct_and_bi(integration_db):
    _, s = integration_db
    u = _new_user(phone="01011111111")
    s.add(u)
    await s.commit()
    old_ct = u.phone_ct
    old_bi = u.phone_bi

    u.phone = "010-2222-2222"
    await s.commit()
    await s.refresh(u)
    assert u.phone_ct != old_ct
    assert u.phone_bi != old_bi
    assert decrypt_phone(u.phone_ct) == "01022222222"
    assert u.phone_bi == phone_blind_index("01022222222")


async def test_phone_bi_matches_across_formats(integration_db):
    _, s = integration_db
    u1 = _new_user(phone="010-1234-5678")
    u2 = _new_user(phone="01012345678")
    u3 = _new_user(phone=" (010) 1234 5678 ")
    # phone UNIQUE 제약 때문에 동일 phone 으로 3개 INSERT 는 SQLite 에서 막힘.
    # 평문 컬럼은 그대로 두고 따로 commit — 같은 phone 으로 3 row 가 만들어지는 건
    # 마이그 dedup 시나리오용 별 테스트에서 검증한다. 여기선 다른 평문 포맷이
    # 같은 normalized phone 이면 phone_bi 가 동일해진다는 사실만 helper 직접 호출로 검증.
    s.add(u1)
    await s.commit()
    await s.refresh(u1)
    # 동일 정규화 → 동일 bi (DB row 만들지 않고도 검증 가능, helper 가 결정적이므로).
    assert u1.phone_bi == phone_blind_index("01012345678") == phone_blind_index("010-1234-5678")
    assert decrypt_phone(u1.phone_ct) == "01012345678"


async def _seed_facility(s) -> Facility:
    f = Facility(
        id=str(uuid.uuid4()),
        name="시설",
        address="주소",
        code=f"FAC-{uuid.uuid4().hex[:6].upper()}",
        phone="010-9999-8888",
    )
    s.add(f)
    return f


async def test_facility_phone_dual_write(integration_db):
    _, s = integration_db
    f = await _seed_facility(s)
    await s.commit()
    await s.refresh(f)
    assert decrypt_phone(f.phone_ct) == "01099998888"
    assert f.phone_bi == phone_blind_index("01099998888")


async def test_invitation_phone_dual_write(integration_db):
    _, s = integration_db
    f = await _seed_facility(s)
    inviter = _new_user(phone=None)
    inviter.role = "staff"
    inviter.facility_id = f.id
    s.add(inviter)
    await s.commit()

    r = Resident(
        id=str(uuid.uuid4()),
        facility_id=f.id,
        code=f"RES-{uuid.uuid4().hex[:6].upper()}",
    )
    s.add(r)
    await s.commit()

    inv = Invitation(
        id=str(uuid.uuid4()),
        facility_id=f.id,
        resident_id=r.id,
        invite_type="sms",
        phone="010-3333-4444",
        invited_by=inviter.id,
    )
    s.add(inv)
    await s.commit()
    await s.refresh(inv)
    assert decrypt_phone(inv.phone_ct) == "01033334444"
    assert inv.phone_bi == phone_blind_index("01033334444")


async def test_phone_claim_report_dual_write(integration_db):
    _, s = integration_db
    u = _new_user(phone=None)
    s.add(u)
    await s.commit()

    pcr = PhoneClaimReport(
        id=str(uuid.uuid4()),
        reporter_user_id=u.id,
        claimed_phone="010-5555-6666",
    )
    s.add(pcr)
    await s.commit()
    await s.refresh(pcr)
    assert decrypt_phone(pcr.claimed_phone_ct) == "01055556666"
    assert pcr.claimed_phone_bi == phone_blind_index("01055556666")
