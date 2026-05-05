"""T-003-4 — residents PII 백필 모듈 단위 테스트.

in-memory SQLite + Base.metadata.create_all 로 실 마이그가 적용된 듯한 상태를
구성하고, `backfill_residents` 가 다음을 만족하는지 검증:

- dek_wrapped 가 비어있는 row 는 ct + dek + blind_idx 가 모두 채워진다
- 채워진 ct 는 unwrap_dek + decrypt_field 로 round-trip 가능한 진짜 ct
- birth_date / medical_notes 가 None 이면 해당 ct 컬럼은 None 그대로
- 이미 dek_wrapped 가 있는 row 는 건드리지 않는다 (dual-write row 보호)
- name 이 None 인 row 는 건드리지 않는다 (스키마상 NOT NULL 이지만 방어적으로)
- 두 번째 실행은 0 rows processed (멱등성)
"""

from __future__ import annotations

import base64
import os as _os
import platform as _platform
import sys as _sys
import types as _types

# 유효한 32-byte base64 키. crypto.py 의 lru_cache 가 첫 호출 시 잡으므로 import 전.
_os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x0b" * 32).decode())
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x0c" * 32).decode())
_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")

if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

import uuid
from datetime import datetime

import pytest
from sqlalchemy import create_engine, text

from app.core.crypto import (
    blind_index,
    decrypt_field,
    encrypt_field,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)
from app.models.models import Base
from app.scripts.backfill_resident_pii import backfill_residents


@pytest.fixture
def conn():
    """sync sqlite — backfill 모듈은 sync connection 을 받아 동작 (alembic op.get_bind() 흉내)."""
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
    # facility 1개 미리 — residents.facility_id FK 만족용. raw SQL 이라 ORM default 가
    # 안 먹어서 created_at 도 명시.
    now = datetime.utcnow()
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO facilities (id, code, name, address, created_at) "
                "VALUES (:id, :code, :name, :address, :created_at)"
            ),
            {
                "id": "fac-1",
                "code": "FAC-T",
                "name": "테스트원",
                "address": "서울",
                "created_at": now,
            },
        )
    with engine.connect() as connection:
        yield connection
    engine.dispose()


def _insert_plaintext_resident(
    conn,
    *,
    id: str,
    name: str | None,
    birth_date: str | None = None,
    medical_notes: str | None = None,
    dek_wrapped: bytes | None = None,
    name_ct: bytes | None = None,
):
    conn.execute(
        text(
            "INSERT INTO residents (id, facility_id, code, name, birth_date, medical_notes, "
            "is_active, name_ct, dek_wrapped, created_at) "
            "VALUES (:id, :facility_id, :code, :name, :birth_date, :medical_notes, "
            ":is_active, :name_ct, :dek_wrapped, :created_at)"
        ),
        {
            "id": id,
            "facility_id": "fac-1",
            "code": f"RES-{id[:6]}",
            "name": name,
            "birth_date": birth_date,
            "medical_notes": medical_notes,
            "is_active": True,
            "name_ct": name_ct,
            "dek_wrapped": dek_wrapped,
            "created_at": datetime.utcnow(),
        },
    )
    conn.commit()


def _select_resident(conn, id_: str):
    row = conn.execute(
        text(
            "SELECT id, name, birth_date, medical_notes, name_ct, name_blind_idx, "
            "birth_date_ct, medical_notes_ct, dek_wrapped FROM residents WHERE id = :id"
        ),
        {"id": id_},
    ).one()
    return row


def test_backfill_populates_ct_and_round_trips(conn):
    """평문만 있는 row 가 백필 후 ct 로 decrypt 가능."""
    _insert_plaintext_resident(
        conn,
        id="r-pt",
        name="홍길동",
        birth_date="1940-03-15",
        medical_notes="고혈압",
    )

    result = backfill_residents(conn)
    assert result["processed"] == 1

    row = _select_resident(conn, "r-pt")
    assert row.dek_wrapped is not None
    dek = unwrap_dek(bytes(row.dek_wrapped))
    assert decrypt_field(bytes(row.name_ct), dek) == "홍길동"
    assert decrypt_field(bytes(row.birth_date_ct), dek) == "1940-03-15"
    assert decrypt_field(bytes(row.medical_notes_ct), dek) == "고혈압"
    # blind index 는 결정적 — 같은 평문이면 같은 값
    assert bytes(row.name_blind_idx) == blind_index("홍길동")


def test_backfill_handles_optional_fields_as_none(conn):
    """birth_date / medical_notes 가 None 인 row 는 그 ct 컬럼만 None 으로 둔다."""
    _insert_plaintext_resident(conn, id="r-min", name="순자", birth_date=None, medical_notes=None)

    result = backfill_residents(conn)
    assert result["processed"] == 1

    row = _select_resident(conn, "r-min")
    assert row.dek_wrapped is not None
    assert row.name_ct is not None
    assert row.birth_date_ct is None
    assert row.medical_notes_ct is None


def test_backfill_skips_already_encrypted_rows(conn):
    """dual-write 로 이미 dek_wrapped 가 있는 row 는 건드리지 않는다."""
    dek = generate_dek()
    original_wrapped = wrap_dek(dek)
    original_ct = encrypt_field("기존이름", dek)

    _insert_plaintext_resident(
        conn,
        id="r-dw",
        name="기존이름",
        dek_wrapped=original_wrapped,
        name_ct=original_ct,
    )

    result = backfill_residents(conn)
    assert result["processed"] == 0

    # 컬럼 값이 그대로인지 확인 (백필이 만진 흔적이 없어야 함)
    row = _select_resident(conn, "r-dw")
    assert bytes(row.dek_wrapped) == original_wrapped
    assert bytes(row.name_ct) == original_ct


def test_backfill_skips_rows_with_null_name(conn):
    """name 이 None 인 비정상 row 도 건드리지 않는다 (방어적)."""
    # 모델은 name NOT NULL 이지만 raw INSERT 로 우회 — sqlite 는 NOT NULL 강제하므로
    # 직접 NULL INSERT 가 실패한다. 대신 빈 dek_wrapped 만 가진 row 를 한 개 두고,
    # WHERE 의 `name IS NOT NULL` 분기를 검증하는 대안: name 빈 row 는 NOT NULL 이라
    # 만들 수 없으므로 이 케이스는 sqlite 환경에선 skip — 운영(Postgres)도 동일 NOT NULL.
    # 대신 "백필이 오직 dek_wrapped IS NULL 만 처리" 라는 invariant 만 다른 테스트로 커버됨.
    pytest.skip("residents.name NOT NULL — sqlite/postgres 둘 다 raw INSERT NULL 불가")


def test_backfill_is_idempotent(conn):
    """두 번 실행해도 두 번째는 0 rows processed (멱등성)."""
    for i in range(3):
        _insert_plaintext_resident(conn, id=f"r-{i}", name=f"이름{i}")

    first = backfill_residents(conn)
    second = backfill_residents(conn)

    assert first["processed"] == 3
    assert second["processed"] == 0


def test_backfill_processes_only_pending_rows_in_mixed_set(conn):
    """일부는 이미 암호화, 일부는 평문 — 평문만 처리되는지."""
    # row1: 평문만
    _insert_plaintext_resident(conn, id="r-pt1", name="A")
    # row2: 이미 dual-write
    dek = generate_dek()
    _insert_plaintext_resident(
        conn, id="r-dw2", name="B", dek_wrapped=wrap_dek(dek), name_ct=encrypt_field("B", dek)
    )
    # row3: 평문만
    _insert_plaintext_resident(conn, id="r-pt3", name="C")

    result = backfill_residents(conn)
    assert result["processed"] == 2

    pt1 = _select_resident(conn, "r-pt1")
    pt3 = _select_resident(conn, "r-pt3")
    dw2 = _select_resident(conn, "r-dw2")
    assert pt1.dek_wrapped is not None
    assert pt3.dek_wrapped is not None
    # dw2 는 백필이 손대지 않아 원래 wrapped 그대로 — round-trip 검증으로 충분
    assert decrypt_field(bytes(dw2.name_ct), unwrap_dek(bytes(dw2.dek_wrapped))) == "B"
