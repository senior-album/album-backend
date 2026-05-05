"""T-003-5b: residents 평문 PII 컬럼 DROP COLUMN

Revision ID: 009_drop_residents_plaintext
Revises: 008_invitation_inapp
Create Date: 2026-05-05

T-003-5a (PR #105) 가 평문 컬럼 write 를 멈추고 백필된 row 의 평문을 NULL out
했다. 이로써 모든 row 의 평문 컬럼이 NULL — 컬럼 자체를 안전하게 drop 할 수
있다.

DROP 후엔:
- 디스크에 평문 PII 가 일체 남지 않는다 (P0 PII envelope encryption 종료).
- 모델에서도 컬럼 정의가 사라져 누군가 실수로 평문 set 을 시도해도 attribute
  error 로 즉시 차단.
- read 경로는 `apply_pii_decryption` 이 ct→평문을 instance attribute 로 setattr
  하고, Pydantic 응답이 그걸 from_attributes 로 읽어 평문을 client 에 전달.

운영 적용 순서:
  1) 005a/006/007 적용 끝낸 상태 (백필 + 평문 NULL out 완료)
  2) 본 009 마이그 적용 (DROP COLUMN — Postgres 는 metadata-only 가 아니라
     full-table rewrite 가 일어나니, 운영 시간 잠깐의 락 발생 — 우리 규모에선
     무시 가능 (~수십 row))
  3) 새 코드 (T-003-5b 모델) 배포

Downgrade 는 의도적 no-op — 컬럼을 다시 만들어도 데이터는 복구 불가 (평문은
이미 NULL out 됐고 ct 는 평문으로 풀어 컬럼에 채우는 별도 스크립트가 필요).
운영에서 되돌릴 일 생기면 별도 데이터 복구 절차로 처리.
"""

from alembic import op


# revision identifiers, used by Alembic.
# main 의 PR #107 (T-149 rebase) 가 007_invitation_inapp 을 008_invitation_inapp
# 으로 sequential rebase 하면서 multi-head 가 해소된 상태. 단일 down_revision.
revision = "009_drop_residents_plaintext"  # alembic_version 컬럼 32자 제한 — 짧게.
down_revision = "008_invitation_inapp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("residents", "name")
    op.drop_column("residents", "birth_date")
    op.drop_column("residents", "medical_notes")


def downgrade() -> None:
    pass
