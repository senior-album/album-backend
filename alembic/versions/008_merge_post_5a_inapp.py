"""merge: 007_residents_plaintext_nullable + 007_invitation_inapp

Revision ID: 008_merge_post_5a_inapp
Revises: 007_residents_plaintext_nullable, 007_invitation_inapp
Create Date: 2026-05-05

T-003-5a (PR #105) 와 T-149 (PR #106) 가 서로 다른 head (둘 다 006 자식) 로
머지되어 alembic chain 이 multiple heads 가 됐다. 본 마이그는 두 head 를 합치는
빈 merge — 변경 없음. 다음 마이그 (009) 가 이 위에서 진행.
"""

# revision identifiers, used by Alembic.
revision = "008_merge_post_5a_inapp"
down_revision = ("007_residents_plaintext_nullable", "007_invitation_inapp")
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
