"""T-243: events 테이블 생성

Revision ID: 012_events
Revises: 011_user_permissions
Create Date: 2026-05-06

이벤트 캘린더 — 시설 직원이 입소자/시설 단위 일정 (생신·외출·기타) 을 등록.
type 어휘는 스키마 레이어 (Literal) 에서만 검증 — 컬럼은 String(20). resident_id
는 nullable (시설 전체 행사 허용).

read 권한: 시설 직원 | 가디언 | 운영자. write 권한: 시설 직원.

downgrade 는 테이블 drop. 운영 데이터가 쌓인 상태에선 되돌릴 일 없음 — 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "012_events"
down_revision = "011_user_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "facility_id",
            sa.String(36),
            sa.ForeignKey("facilities.id"),
            nullable=False,
        ),
        sa.Column(
            "resident_id",
            sa.String(36),
            sa.ForeignKey("residents.id"),
            nullable=True,
        ),
        sa.Column("type", sa.String(20), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("start_at", sa.DateTime(), nullable=False),
        sa.Column("end_at", sa.DateTime(), nullable=True),
        sa.Column("all_day", sa.Boolean(), nullable=False),
        sa.Column(
            "created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False
        ),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_events_facility_id", "events", ["facility_id"])
    op.create_index("ix_events_resident_id", "events", ["resident_id"])
    op.create_index("ix_events_start_at", "events", ["start_at"])
    op.create_index("ix_events_type", "events", ["type"])


def downgrade() -> None:
    op.drop_index("ix_events_type", table_name="events")
    op.drop_index("ix_events_start_at", table_name="events")
    op.drop_index("ix_events_resident_id", table_name="events")
    op.drop_index("ix_events_facility_id", table_name="events")
    op.drop_table("events")
