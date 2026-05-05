"""T-241: resident_wellness_logs 테이블 생성

Revision ID: 010_resident_wellness_log
Revises: 009_drop_residents_plaintext
Create Date: 2026-05-05

입소자 안부 일지 — 시설 직원이 거동·식사 상태를 일일 기록.
한 입소자 × 하루 = 1 row. UNIQUE(resident_id, log_date) 로 중복 방지 (PUT upsert
가 같은 키에 다시 떨어지면 같은 row 갱신).

downgrade 는 테이블 drop. 운영 데이터가 쌓인 상태에선 되돌릴 일 없음 — 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "010_resident_wellness_log"
down_revision = "009_drop_residents_plaintext"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "resident_wellness_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("resident_id", sa.String(36), sa.ForeignKey("residents.id"), nullable=False),
        sa.Column("log_date", sa.Date(), nullable=False),
        sa.Column("mobility_status", sa.String(20), nullable=True),
        sa.Column("meal_breakfast", sa.String(20), nullable=True),
        sa.Column("meal_lunch", sa.String(20), nullable=True),
        sa.Column("meal_dinner", sa.String(20), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.UniqueConstraint(
            "resident_id", "log_date", name="uq_resident_wellness_logs_resident_date"
        ),
    )
    op.create_index(
        "ix_resident_wellness_logs_resident_id",
        "resident_wellness_logs",
        ["resident_id"],
    )
    op.create_index(
        "ix_resident_wellness_logs_log_date",
        "resident_wellness_logs",
        ["log_date"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_resident_wellness_logs_log_date", table_name="resident_wellness_logs"
    )
    op.drop_index(
        "ix_resident_wellness_logs_resident_id", table_name="resident_wellness_logs"
    )
    op.drop_table("resident_wellness_logs")
