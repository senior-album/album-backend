"""T-003-1: residents PII envelope encryption — ciphertext / DEK / blind-index 컬럼 추가

Revision ID: 002_resident_pii_ciphertext
Revises: 001_baseline
Create Date: 2026-04-27

이 마이그레이션은 컬럼만 추가한다. 평문 컬럼/기존 데이터/애플리케이션 동작은
영향 없음. 새 컬럼은 모두 NULL 허용 — 다음 단계 (T-003-2 dual-write,
T-003-3 backfill) 가 채운다.

신규 컬럼 (residents):
- name_ct          BYTEA NULL  — name AES-256-GCM ciphertext (nonce 12B || ct+tag)
- name_blind_idx   BYTEA NULL  — HMAC-SHA256(RESIDENT_NAME_HMAC_KEY, name). INDEX.
- birth_date_ct    BYTEA NULL
- medical_notes_ct BYTEA NULL
- dek_wrapped      BYTEA NULL  — nonce(12B) || AESGCM(KEK).encrypt(DEK). row 당 1개,
                                  세 PII 컬럼이 공유.

Downgrade 는 단순 DROP — 이 단계까진 데이터가 안 들어가므로 손실 없음.
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "002_resident_pii_ciphertext"
down_revision = "001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE residents ADD COLUMN name_ct BYTEA")
    op.execute("ALTER TABLE residents ADD COLUMN name_blind_idx BYTEA")
    op.execute("ALTER TABLE residents ADD COLUMN birth_date_ct BYTEA")
    op.execute("ALTER TABLE residents ADD COLUMN medical_notes_ct BYTEA")
    op.execute("ALTER TABLE residents ADD COLUMN dek_wrapped BYTEA")
    op.execute("CREATE INDEX ix_residents_name_blind_idx ON residents (name_blind_idx)")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_residents_name_blind_idx")
    op.execute("ALTER TABLE residents DROP COLUMN IF EXISTS dek_wrapped")
    op.execute("ALTER TABLE residents DROP COLUMN IF EXISTS medical_notes_ct")
    op.execute("ALTER TABLE residents DROP COLUMN IF EXISTS birth_date_ct")
    op.execute("ALTER TABLE residents DROP COLUMN IF EXISTS name_blind_idx")
    op.execute("ALTER TABLE residents DROP COLUMN IF EXISTS name_ct")
