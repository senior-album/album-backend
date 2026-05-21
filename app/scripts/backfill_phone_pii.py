"""T-320-2 — User/Facility/Invitation/PhoneClaimReport phone PII 백필.

dual-write hook 이 들어가기 전에 만들어진 row 의 평문 phone 을 ct/bi 로 채운다.
멱등: WHERE phone IS NOT NULL AND phone_ct IS NULL 필터로 이미 채워진 row 는 skip.

KEK / USER_PHONE_HMAC_KEY 환경변수가 주입돼 있어야 함 — 누락 시 첫 encrypt 호출에서
ValueError, alembic 트랜잭션 롤백.
"""

from __future__ import annotations

from sqlalchemy import text


def _backfill_table(
    connection,
    table: str,
    plain_col: str,
    ct_col: str,
    bi_col: str,
) -> int:
    from app.core.crypto import encrypt_phone, phone_blind_index, _normalize_phone

    rows = list(
        connection.execute(
            text(
                f"SELECT id, {plain_col} AS phone FROM {table} "
                f"WHERE {plain_col} IS NOT NULL AND {plain_col} != '' AND {ct_col} IS NULL"
            )
        )
    )
    update = text(
        f"UPDATE {table} SET {ct_col} = :ct, {bi_col} = :bi WHERE id = :id"
    )
    processed = 0
    for row in rows:
        normalized = _normalize_phone(row.phone)
        if not normalized:
            continue
        connection.execute(
            update,
            {"id": row.id, "ct": encrypt_phone(normalized), "bi": phone_blind_index(normalized)},
        )
        processed += 1
    return processed


def backfill_phone_pii(connection) -> dict:
    """4 테이블의 평문 phone → ct/bi 백필.

    Returns:
        `{"users": int, "facilities": int, "invitations": int, "phone_claim_reports": int}`
        — 테이블별 백필 row 수.
    """
    return {
        "users": _backfill_table(connection, "users", "phone", "phone_ct", "phone_bi"),
        "facilities": _backfill_table(connection, "facilities", "phone", "phone_ct", "phone_bi"),
        "invitations": _backfill_table(connection, "invitations", "phone", "phone_ct", "phone_bi"),
        "phone_claim_reports": _backfill_table(
            connection, "phone_claim_reports", "claimed_phone", "claimed_phone_ct", "claimed_phone_bi"
        ),
    }
