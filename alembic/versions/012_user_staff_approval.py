"""T-056: User 직원 승인 게이트 컬럼 + 기존 staff backfill

Revision ID: 012_user_staff_approval
Revises: 011_user_permissions
Create Date: 2026-05-06

추가:
- is_staff_approved (bool, NOT NULL default False)
- staff_approved_by (FK users.id, nullable)
- staff_approved_at (datetime, nullable)
- is_rejected (bool, NOT NULL default False)
- staff_rejected_by (FK users.id, nullable)
- staff_rejected_at (datetime, nullable)
- staff_reject_reason (str(500), nullable)

Backfill: 운영 데이터 보존 — 기존에 활성(is_active=True) 인 모든 user 는
is_staff_approved=True 로 채운다. role=staff 가 아닌 user (guardian/operator 등)
도 True 박지만 본 컬럼이 그쪽엔 의미 없어 무해하다. 거부 컬럼 (is_rejected 외)
는 모두 default 그대로.

downgrade 는 컬럼 drop. 실제 운영 데이터에서 되돌릴 일 없음 — 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "012_user_staff_approval"
down_revision = "011_user_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "is_staff_approved", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "users",
        sa.Column("staff_approved_by", sa.String(length=36), nullable=True),
    )
    op.create_foreign_key(
        "fk_users_staff_approved_by", "users", "users", ["staff_approved_by"], ["id"]
    )
    op.add_column(
        "users", sa.Column("staff_approved_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "users",
        sa.Column(
            "is_rejected", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
    )
    op.add_column(
        "users",
        sa.Column("staff_rejected_by", sa.String(length=36), nullable=True),
    )
    op.create_foreign_key(
        "fk_users_staff_rejected_by", "users", "users", ["staff_rejected_by"], ["id"]
    )
    op.add_column(
        "users", sa.Column("staff_rejected_at", sa.DateTime(), nullable=True)
    )
    op.add_column(
        "users", sa.Column("staff_reject_reason", sa.String(length=500), nullable=True)
    )

    # 운영 데이터 보존 — 기존 활성 user 는 모두 승인된 상태로 시드.
    op.execute(
        "UPDATE users SET is_staff_approved = TRUE WHERE is_active = TRUE"
    )

    # server_default 는 backfill 후 제거 — 코드(default=False) 로 통일.
    op.alter_column("users", "is_staff_approved", server_default=None)
    op.alter_column("users", "is_rejected", server_default=None)


def downgrade() -> None:
    op.drop_constraint("fk_users_staff_rejected_by", "users", type_="foreignkey")
    op.drop_constraint("fk_users_staff_approved_by", "users", type_="foreignkey")
    op.drop_column("users", "staff_reject_reason")
    op.drop_column("users", "staff_rejected_at")
    op.drop_column("users", "staff_rejected_by")
    op.drop_column("users", "is_rejected")
    op.drop_column("users", "staff_approved_at")
    op.drop_column("users", "staff_approved_by")
    op.drop_column("users", "is_staff_approved")
