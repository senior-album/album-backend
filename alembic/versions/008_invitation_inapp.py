"""T-149: invitations 채널 확장 (sms / in_app)

Revision ID: 008_invitation_inapp
Revises: 007_residents_plaintext_nullable
Create Date: 2026-05-05

목적:
- 가입 회원 초대 (in_app) 채널 도입. 직원이 이미 가입돼 있는 보호자를 검색해
  바로 초대를 보낼 수 있게. 외부 채널 (sms/알림톡) 의존을 줄이는 것이 목적.

원래 007 로 PR 가 갔으나 같은 시점에 머지된 T-003-5a 의
007_residents_plaintext_nullable 때문에 alembic head 가 분기됨 (multiple
heads → `alembic upgrade head` 실패). 의미상 PII 작업과 독립이므로 008 로
한 칸 미뤄 단일 chain 으로 정렬.

변경:
1. `invitations.invite_type` (varchar 20, NOT NULL, default 'sms') 추가.
   기존 row 는 모두 phone/email 기반이므로 'sms' 로 백필.
2. `invitations.invitee_user_id` (varchar 36, nullable, FK users.id) 추가.
   in_app 초대 시에만 채워진다. sms 초대에서는 NULL.

phone 인덱스: 005 가 이미 unique constraint 를 걸어둠 (= unique index) 이므로
검색용 추가 인덱스는 불필요.

downgrade: 새 컬럼 drop 만. invite_type='in_app' 인 row 는 phone/email 이
비어있어서 drop 후엔 의미가 사라지지만, downgrade 는 운영에서 쓰지 않는 비상용.
"""

from alembic import op
import sqlalchemy as sa


revision = "008_invitation_inapp"
down_revision = "007_residents_plaintext_nullable"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) invite_type — server_default 로 백필 후 NOT NULL.
    op.add_column(
        "invitations",
        sa.Column("invite_type", sa.String(20), nullable=False, server_default="sms"),
    )
    op.create_index(
        "ix_invitations_invite_type", "invitations", ["invite_type"]
    )
    # server_default 제거 — 모델 default 만 유지 (alembic check 충돌 방지, 005 패턴 동일)
    op.alter_column("invitations", "invite_type", server_default=None)

    # 2) invitee_user_id
    op.add_column(
        "invitations",
        sa.Column("invitee_user_id", sa.String(36), nullable=True),
    )
    op.create_foreign_key(
        "fk_invitations_invitee_user_id_users",
        "invitations",
        "users",
        ["invitee_user_id"],
        ["id"],
    )
    op.create_index(
        "ix_invitations_invitee_user_id", "invitations", ["invitee_user_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_invitations_invitee_user_id", table_name="invitations")
    op.drop_constraint(
        "fk_invitations_invitee_user_id_users", "invitations", type_="foreignkey"
    )
    op.drop_column("invitations", "invitee_user_id")
    op.drop_index("ix_invitations_invite_type", table_name="invitations")
    op.drop_column("invitations", "invite_type")
