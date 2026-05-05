"""T-003-4 — residents PII envelope encryption 백필.

T-003-2 dual-write 가 켜진 시점 이전에 만들어진 row 들은 평문 컬럼만 채워져
있고 `dek_wrapped` / `*_ct` 가 비어있다. 본 함수가 그런 row 들을 순회해
ciphertext 컬럼 + blind index 를 채운다.

알고리즘은 `_apply_pii_encryption` 과 동일하지만, ORM 의존을 피하려고 raw SQL
로 작성 — 마이그레이션 코드는 실행 시점에 모델이 어떻게 변해있을지 모르기
때문에 테이블 스키마를 그 시점의 컬럼명으로 직접 참조하는 것이 안전하다.

멱등성: `WHERE dek_wrapped IS NULL AND name IS NOT NULL` 필터로 이미 백필된
row 는 자동 skip. 두 번째 실행하면 0 rows processed.

KEK / NAME_HMAC_KEY 는 환경변수로 주입돼 있어야 한다 — 마이그레이션 컨테이너에
SealedSecret 으로 마운트되거나, 로컬에선 .env 에 set. 환경변수 누락 시 첫
encrypt 호출에서 ValueError 를 던지므로 마이그가 부분 적용되는 일은 없다
(alembic 트랜잭션 롤백).
"""

from __future__ import annotations

from sqlalchemy import text

from app.core.crypto import (
    blind_index,
    encrypt_field,
    generate_dek,
    wrap_dek,
)


_SELECT_PENDING = text(
    "SELECT id, name, birth_date, medical_notes "
    "FROM residents "
    "WHERE dek_wrapped IS NULL AND name IS NOT NULL"
)

_UPDATE_ROW = text(
    "UPDATE residents SET "
    "name_ct = :name_ct, "
    "name_blind_idx = :name_blind_idx, "
    "birth_date_ct = :birth_date_ct, "
    "medical_notes_ct = :medical_notes_ct, "
    "dek_wrapped = :dek_wrapped "
    "WHERE id = :id"
)


def backfill_residents(connection) -> dict:
    """`dek_wrapped IS NULL` 인 모든 row 에 envelope encryption 결과를 채운다.

    Args:
        connection: 활성 SQLAlchemy Connection. alembic 안에선 `op.get_bind()` 로
                    얻을 수 있다.

    Returns:
        `{"processed": int}` — 실제로 UPDATE 가 실행된 row 수. 멱등 검증/로그용.
    """
    rows = list(connection.execute(_SELECT_PENDING))

    processed = 0
    for row in rows:
        dek = generate_dek()
        params = {
            "id": row.id,
            "name_ct": encrypt_field(row.name, dek),
            "name_blind_idx": blind_index(row.name),
            "birth_date_ct": encrypt_field(row.birth_date, dek) if row.birth_date else None,
            "medical_notes_ct": encrypt_field(row.medical_notes, dek) if row.medical_notes else None,
            "dek_wrapped": wrap_dek(dek),
        }
        connection.execute(_UPDATE_ROW, params)
        processed += 1

    return {"processed": processed}
