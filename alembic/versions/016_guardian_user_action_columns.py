"""T-323: guardians 테이블에 cancelled_at + hidden_from_user_at 추가

Revision ID: 016_guardian_user_action_columns
Revises: 015_password_reset_tokens
Create Date: 2026-05-21

보호자 본인이 시설 연결 신청에 대해 종료/숨김 액션을 취할 수 있게 한다.

- cancelled_at        : 대기 중 신청을 본인이 취소한 시각 (soft delete, 이력 보존).
- hidden_from_user_at : 거부된 신청을 본인 화면에서 숨긴 시각.

두 컬럼 모두 nullable=True. 기존 row 는 NULL 로 backfill — 동작 변화 없음.
"""

from alembic import op
import sqlalchemy as sa


revision = "016_guardian_user_action_columns"
down_revision = "015_password_reset_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "guardians",
        sa.Column("cancelled_at", sa.DateTime(), nullable=True),
    )
    op.add_column(
        "guardians",
        sa.Column("hidden_from_user_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("guardians", "hidden_from_user_at")
    op.drop_column("guardians", "cancelled_at")
