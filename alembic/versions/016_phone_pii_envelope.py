"""T-320-2: User/Facility/Invitation/PhoneClaimReport phone PII envelope encryption

Revision ID: 016_phone_pii_envelope
Revises: 015_password_reset_tokens
Create Date: 2026-05-18

T-003 패턴 그대로 phone 도메인에 적용 — 새 ct + bi 컬럼 add + 기존 평문 백필.
평문 컬럼 drop 은 T-320-Z (별도 마이그) 에서. 그 사이는 dual-write hook (models.py
event listener) 이 일관성 유지.

신규 컬럼:
- users.phone_ct                  BYTEA NULL
- users.phone_bi                  BYTEA NULL INDEX
- facilities.phone_ct             BYTEA NULL
- facilities.phone_bi             BYTEA NULL INDEX
- invitations.phone_ct            BYTEA NULL
- invitations.phone_bi            BYTEA NULL INDEX
- phone_claim_reports.claimed_phone_ct  BYTEA NULL
- phone_claim_reports.claimed_phone_bi  BYTEA NULL INDEX

UNIQUE 는 본 마이그에서 손대지 않음 — `users.phone` UNIQUE 그대로 유지. plaintext
drop 시 phone_bi 로 이전 (그 시점에 ROW_NUMBER dedup 동반).

환경변수 `RESIDENT_PII_KEK` (KEK 재사용) + `USER_PHONE_HMAC_KEY` 가 주입돼 있어야
함. 누락 시 백필 단계에서 ValueError → 트랜잭션 롤백.

Downgrade: 인덱스 drop + 컬럼 drop. 백필된 ct/bi 데이터는 소실 — 평문 컬럼은
그대로라 회복 가능.
"""

from alembic import op


revision = "016_phone_pii_envelope"
down_revision = "015_password_reset_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) 컬럼 add
    op.execute("ALTER TABLE users ADD COLUMN phone_ct BYTEA")
    op.execute("ALTER TABLE users ADD COLUMN phone_bi BYTEA")
    op.execute("ALTER TABLE facilities ADD COLUMN phone_ct BYTEA")
    op.execute("ALTER TABLE facilities ADD COLUMN phone_bi BYTEA")
    op.execute("ALTER TABLE invitations ADD COLUMN phone_ct BYTEA")
    op.execute("ALTER TABLE invitations ADD COLUMN phone_bi BYTEA")
    op.execute("ALTER TABLE phone_claim_reports ADD COLUMN claimed_phone_ct BYTEA")
    op.execute("ALTER TABLE phone_claim_reports ADD COLUMN claimed_phone_bi BYTEA")

    # 2) bi 컬럼 index
    op.execute("CREATE INDEX ix_users_phone_bi ON users (phone_bi)")
    op.execute("CREATE INDEX ix_facilities_phone_bi ON facilities (phone_bi)")
    op.execute("CREATE INDEX ix_invitations_phone_bi ON invitations (phone_bi)")
    op.execute(
        "CREATE INDEX ix_phone_claim_reports_claimed_phone_bi "
        "ON phone_claim_reports (claimed_phone_bi)"
    )

    # 3) 기존 평문 phone → ct/bi 백필
    from app.scripts.backfill_phone_pii import backfill_phone_pii

    result = backfill_phone_pii(op.get_bind())
    print(f"[T-320-2] phone PII backfilled: {result}")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_phone_claim_reports_claimed_phone_bi")
    op.execute("DROP INDEX IF EXISTS ix_invitations_phone_bi")
    op.execute("DROP INDEX IF EXISTS ix_facilities_phone_bi")
    op.execute("DROP INDEX IF EXISTS ix_users_phone_bi")
    op.execute("ALTER TABLE phone_claim_reports DROP COLUMN IF EXISTS claimed_phone_bi")
    op.execute("ALTER TABLE phone_claim_reports DROP COLUMN IF EXISTS claimed_phone_ct")
    op.execute("ALTER TABLE invitations DROP COLUMN IF EXISTS phone_bi")
    op.execute("ALTER TABLE invitations DROP COLUMN IF EXISTS phone_ct")
    op.execute("ALTER TABLE facilities DROP COLUMN IF EXISTS phone_bi")
    op.execute("ALTER TABLE facilities DROP COLUMN IF EXISTS phone_ct")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS phone_bi")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS phone_ct")
