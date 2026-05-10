"""T-306: password_reset_tokens 테이블 추가

Revision ID: 015_password_reset_tokens
Revises: 014_event_birthday_notified_at
Create Date: 2026-05-10

비밀번호 재설정 토큰 저장. 토큰 자체가 아닌 sha256 해시만 저장 (DB 유출 시
재사용 차단). 30분 TTL + 1회용 (used_at).

downgrade 는 테이블 drop. 운영 데이터 손실 가능 — 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "015_password_reset_tokens"
down_revision = "014_event_birthday_notified_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(length=36),
            sa.ForeignKey("users.id"),
            nullable=False,
            index=True,
        ),
        # sha256 hex = 64 자
        sa.Column("token_hash", sa.String(length=64), nullable=False, unique=True),
        # email | sms — 발송 채널 (audit + 디버깅용)
        sa.Column("channel", sa.String(length=10), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False, index=True),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )


def downgrade() -> None:
    op.drop_table("password_reset_tokens")
