"""phone uniqueness + phone_claim_reports

Revision ID: 005_phone_uniqueness_and_claims
Revises: 004_legal_settings
Create Date: 2026-05-05

목적:
1. users.phone 에 UNIQUE — 한 번호는 한 계정에만 매핑. 사칭/오등록 방지.
   기존 빈 문자열 phone 은 NULL 로 정규화 후 unique index 추가 (PostgreSQL 의 NULL
   여러 개 허용 특성을 그대로 활용 — 미인증 사용자끼리 충돌 안 남).
2. phone_claim_reports 테이블 신규 — "이 번호 내가 등록 안 했는데?" 신고 저장.
   운영자가 어드민에서 수동 검토하는 워크플로우는 별 PR.
"""

from alembic import op
import sqlalchemy as sa


revision = "005_phone_uniqueness_and_claims"
down_revision = "004_legal_settings"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) 빈 문자열 phone -> NULL 정규화 (UNIQUE 충돌 방지)
    op.execute("UPDATE users SET phone = NULL WHERE phone = ''")

    # 2) users.phone UNIQUE index — NULL 은 여러 개 허용
    op.create_index(
        "ix_users_phone_unique",
        "users",
        ["phone"],
        unique=True,
    )

    # 3) phone_claim_reports
    op.create_table(
        "phone_claim_reports",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "reporter_user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("claimed_phone", sa.String(20), nullable=False, index=True),
        sa.Column("note", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending", index=True),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=True),
    )
    # server_default 제거 — 모델 default 만 유지 (alembic check 충돌 방지)
    op.alter_column("phone_claim_reports", "note", server_default=None)
    op.alter_column("phone_claim_reports", "status", server_default=None)


def downgrade() -> None:
    op.drop_table("phone_claim_reports")
    op.drop_index("ix_users_phone_unique", table_name="users")
