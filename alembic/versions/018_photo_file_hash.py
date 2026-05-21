"""T-325: photos 테이블에 file_hash 컬럼 + (facility_id, file_hash) 인덱스 추가

Revision ID: 018_photo_file_hash
Revises: 017_phone_pii_envelope
Create Date: 2026-05-21

같은 시설 안에서 동일한 파일 내용 (SHA-256 일치) 의 사진을 두 번 업로드할 때
중복을 차단한다. 기존 row 는 NULL 로 backfill (별도 스크립트는 follow-up — 컬럼
nullable 이라 즉시 머지 안전).

- file_hash: VARCHAR(64) NULL — SHA-256 hex digest.
- 인덱스 `ix_photos_facility_hash` (facility_id, file_hash) — 업로드 dup check
  쿼리가 같은 시설 안에서만 lookup 하므로 composite. UNIQUE 는 박지 않음
  (NULL row 가 다수라 UNIQUE 동작이 DB 마다 다르고, backfill 전 단계 안전).
"""

from alembic import op
import sqlalchemy as sa


revision = "018_photo_file_hash"
down_revision = "017_phone_pii_envelope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "photos",
        sa.Column("file_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_photos_facility_hash",
        "photos",
        ["facility_id", "file_hash"],
    )


def downgrade() -> None:
    op.drop_index("ix_photos_facility_hash", table_name="photos")
    op.drop_column("photos", "file_hash")
