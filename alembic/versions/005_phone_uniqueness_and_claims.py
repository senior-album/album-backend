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

    # 2) dup phone 정리 — 옛 verify_phone_otp 가 다른 user 의 dup 체크를 안 했고,
    #    카카오 가입 흐름이 phone 만 채우고 verify 거치지 않은 row 도 만들 수 있어서
    #    같은 phone 이 여러 user 에 박혀있을 수 있음. UNIQUE 추가 전에 정리 필요.
    #
    #    유지 규칙: phone 별로 phone_verified_at 가장 최근 row (NULL 은 가장 옛것) 1개만
    #    유지. 나머지는 phone + phone_verified_at NULL 로 비움.
    #    -> 진짜 인증한 사용자는 그대로, 미인증 stale 데이터는 무력화.
    op.execute("""
        UPDATE users
        SET phone = NULL,
            phone_verified_at = NULL
        WHERE id IN (
            SELECT id FROM (
                SELECT id,
                       ROW_NUMBER() OVER (
                           PARTITION BY phone
                           ORDER BY phone_verified_at DESC NULLS LAST, created_at DESC
                       ) AS rn
                FROM users
                WHERE phone IS NOT NULL
            ) t
            WHERE t.rn > 1
        )
    """)

    # 3) users.phone UNIQUE constraint — 모델이 Column(unique=True) 라 constraint 형태로 일치시킴.
    #    Postgres 는 unique constraint 를 내부적으로 unique index 로 구현하니 동작 동일.
    #    NULL 은 여러 row 허용 (Postgres 기본 동작) → 미인증 사용자끼리 충돌 X.
    op.create_unique_constraint("uq_users_phone", "users", ["phone"])

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
    op.drop_constraint("uq_users_phone", "users", type_="unique")
