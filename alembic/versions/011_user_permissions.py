"""T-150: user_permissions 테이블 생성

Revision ID: 011_user_permissions
Revises: 010_resident_wellness_log
Create Date: 2026-05-05

시설 직원 메뉴 권한 위임용 테이블. 시설장(is_admin) / 운영자(is_operator) 는
행 없이 자동 통과 — 위임 받은 직원만 행을 가진다.

UNIQUE(user_id, permission_key) 로 중복 부여 방지. user 삭제 시 CASCADE.
"""

from alembic import op
import sqlalchemy as sa


revision = "011_user_permissions"
down_revision = "010_resident_wellness_log"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_permissions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("permission_key", sa.String(64), nullable=False),
        sa.Column("granted_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("granted_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint(
            "user_id", "permission_key", name="uq_user_permissions_user_key"
        ),
    )
    op.create_index("ix_user_permissions_user_id", "user_permissions", ["user_id"])
    op.create_index(
        "ix_user_permissions_permission_key", "user_permissions", ["permission_key"]
    )


def downgrade() -> None:
    op.drop_index("ix_user_permissions_permission_key", table_name="user_permissions")
    op.drop_index("ix_user_permissions_user_id", table_name="user_permissions")
    op.drop_table("user_permissions")
