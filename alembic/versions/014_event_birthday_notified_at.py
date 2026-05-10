"""T-243-4: events.birthday_notified_at 컬럼 추가

Revision ID: 014_event_birthday_notified_at
Revises: 013_events
Create Date: 2026-05-10

생신 자동 발급 cron (T-243-3) 이 캘린더 UX 와 D-7 알림 두 일을 한 게이트로
처리하던 걸 분리한다 (T-243-4). cron 이 활성 입소자의 올해 birthday event 를
idempotent 생성하므로, 알림 발송 여부는 event 존재만으론 판단 불가 — 별도
컬럼이 필요.

신규 row 는 NULL 로 시작하고, cron 이 D-7 매칭 시점에 발송 후 채운다. 기존
운영 데이터는 NULL 상태로 시작하므로 다음 D-7 cron 에서 알림 1회 발송될 수
있는데, 운영 중 발급된 birthday event 가 있다면 직원이 이미 인지하고 있던
케이스라 신규 알림 발송이 큰 노이즈는 아님.

downgrade 는 컬럼 drop. 운영에서 되돌릴 일 없음 — 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "014_event_birthday_notified_at"
down_revision = "013_events"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "events",
        sa.Column("birthday_notified_at", sa.DateTime(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("events", "birthday_notified_at")
