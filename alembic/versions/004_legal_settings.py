"""T-020 PR3a: legal_settings + users.is_operator

Revision ID: 004_legal_settings
Revises: 003_consents
Create Date: 2026-04-27

목적: 운영자 (Senior Album) 가 PrivacyPage/TermsPage 에 노출되는 회사 정보를 DB 에서
편집할 수 있게 한다 (§22 처리방침의 "개인정보 보호책임자" 등 항목 변경 시 코드 배포 없이 갱신).

추가:
- users.is_operator BOOLEAN NOT NULL DEFAULT FALSE — 운영자 권한 플래그.
- legal_settings (key TEXT PK, value TEXT, updated_at, updated_by_user_id) — KV.
  10 종 시드 — 일부는 사용자 메일/이름으로 미리 채움, 나머지는 빈 문자열.

부트스트랩: app.main 에서 OPERATOR_EMAIL env 매칭 유저를 시작 시 is_operator=true 로 promote.
DB 시드만으론 부족 (가입 후 매칭) — 그래서 마이그레이션이 아닌 lifespan 에서 처리.
"""

from datetime import datetime

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "004_legal_settings"
down_revision = "003_consents"
branch_labels = None
depends_on = None


# 시드 — (key, default_value)
# 빈 문자열은 운영자가 어드민에서 채울 placeholder. 일부는 사용자 정보로 미리 채움
# (kimyounghwan06271990@gmail.com 은 owner 메일 — git history 와 PrivacyPage 초안 기준).
SEED_SETTINGS = [
    ("company_name",            "Senior Album"),
    ("company_address",         ""),
    ("ceo_name",                "김영환"),
    ("business_no",             ""),
    ("dpo_name",                "김영환"),
    ("dpo_email",               "kimyounghwan06271990@gmail.com"),
    ("dpo_phone",               ""),
    ("privacy_effective_date",  ""),
    ("terms_effective_date",    ""),
    ("customer_support_email",  "kimyounghwan06271990@gmail.com"),
]


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_operator", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # 컬럼 추가 후 server_default 제거 — 모델은 Python-only default. 안 그러면 alembic check 실패.
    op.alter_column("users", "is_operator", server_default=None)

    op.create_table(
        "legal_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
        sa.Column(
            "updated_by_user_id",
            sa.String(36),
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
    )

    now = datetime.utcnow()
    rows = [
        {"key": k, "value": v, "updated_at": now, "updated_by_user_id": None}
        for k, v in SEED_SETTINGS
    ]
    legal_settings = sa.table(
        "legal_settings",
        sa.column("key", sa.String),
        sa.column("value", sa.Text),
        sa.column("updated_at", sa.DateTime),
        sa.column("updated_by_user_id", sa.String),
    )
    op.bulk_insert(legal_settings, rows)


def downgrade() -> None:
    op.drop_table("legal_settings")
    op.drop_column("users", "is_operator")
