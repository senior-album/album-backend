"""T-020: consent_documents + user_consents + v1.0 시드 4 종

Revision ID: 003_consents
Revises: 002_resident_pii_ciphertext
Create Date: 2026-04-27

목적: §15 (동의), §22 (처리방침), §23 (민감정보 별도 동의) 의무 이행 — 보호자 가입
시점에 활성 약관에 어떤 버전으로 동의/거부했는지를 기록한다.

테이블:
- consent_documents — 약관 본문 스냅샷 (type, version 유니크). v1.0 4 종 시드.
- user_consents     — 사용자가 어느 문서에 agreed=t/f 로 응답했는지. ip/UA 포함.

시드 본문은 alembic/seeds/v1.0/*.md 에 source-of-truth 사본이 있으며, 본 마이그레이션이
그 파일을 읽어 INSERT 한다. 개정 시에는 어드민 (T-020 PR3) 에서 새 row 발행.

Downgrade 는 user_consents → consent_documents 순으로 DROP. 기존 가입자
동의 로그 손실 위험이 있어 운영 환경 downgrade 는 권장하지 않음.
"""

from datetime import datetime
from pathlib import Path
import uuid

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "003_consents"
down_revision = "002_resident_pii_ciphertext"
branch_labels = None
depends_on = None


# v1.0 시드 정의 — (type, version, title, file, is_mandatory)
# 본문은 alembic/seeds/v1.0/<file> 에서 읽어옴.
SEED_SPECS = [
    ("terms_guardian", "v1.0", "보호자 이용약관 v1.0",       "terms_guardian.md", True),
    ("privacy",        "v1.0", "개인정보처리방침 v1.0",       "privacy.md",        True),
    ("sensitive_info", "v1.0", "민감정보 처리 동의서 v1.0",    "sensitive_info.md", True),
    ("marketing",      "v1.0", "마케팅·알림 수신 동의 v1.0",   "marketing.md",      False),
]


def _seed_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "seeds" / "v1.0"


def upgrade() -> None:
    op.create_table(
        "consent_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("version", sa.String(20), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("is_mandatory", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("effective_from", sa.DateTime, nullable=False),
        sa.Column("effective_until", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("type", "version", name="uq_consent_documents_type_version"),
    )
    op.create_index(
        "ix_consent_documents_type",
        "consent_documents",
        ["type"],
    )

    op.create_table(
        "user_consents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "document_id",
            sa.String(36),
            sa.ForeignKey("consent_documents.id"),
            nullable=False,
        ),
        sa.Column("agreed", sa.Boolean, nullable=False),
        sa.Column("agreed_at", sa.DateTime, nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(500), nullable=True),
    )
    op.create_index("ix_user_consents_user_id", "user_consents", ["user_id"])
    op.create_index("ix_user_consents_document_id", "user_consents", ["document_id"])

    # 시드 — v1.0 4 종 (terms_guardian / privacy / sensitive_info / marketing)
    seed_dir = _seed_dir()
    now = datetime.utcnow()
    rows = []
    for type_, version, title, fname, is_mandatory in SEED_SPECS:
        path = seed_dir / fname
        content = path.read_text(encoding="utf-8")
        rows.append({
            "id": str(uuid.uuid4()),
            "type": type_,
            "version": version,
            "title": title,
            "content": content,
            "is_mandatory": is_mandatory,
            "effective_from": now,
            "effective_until": None,
            "created_at": now,
        })

    consent_documents = sa.table(
        "consent_documents",
        sa.column("id", sa.String),
        sa.column("type", sa.String),
        sa.column("version", sa.String),
        sa.column("title", sa.String),
        sa.column("content", sa.Text),
        sa.column("is_mandatory", sa.Boolean),
        sa.column("effective_from", sa.DateTime),
        sa.column("effective_until", sa.DateTime),
        sa.column("created_at", sa.DateTime),
    )
    op.bulk_insert(consent_documents, rows)


def downgrade() -> None:
    op.drop_index("ix_user_consents_document_id", table_name="user_consents")
    op.drop_index("ix_user_consents_user_id", table_name="user_consents")
    op.drop_table("user_consents")
    op.drop_index("ix_consent_documents_type", table_name="consent_documents")
    op.drop_table("consent_documents")
