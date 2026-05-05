"""T-003-5a: residents 평문 PII 컬럼 nullable + 백필된 row 의 평문 NULL out

Revision ID: 007_residents_plaintext_nullable
Revises: 006_resident_pii_backfill
Create Date: 2026-05-05

T-003-2 dual-write 시기에 평문 + ct 가 함께 들어갔던 데이터를 정리.
006 백필이 적용된 후엔 모든 row 의 ct 가 채워져 있으므로, 평문 컬럼은 더 이상
필요 없다 (read 는 PR #100 / #102 의 `apply_pii_decryption` 으로 ct 를 거쳐
나간다).

본 마이그는 다음을 한다:
1. `residents.name` 의 NOT NULL 제약을 푼다 — 새 row 의 INSERT 가 name=NULL 로
   들어올 수 있도록 (T-003-5a 코드 변경과 짝).
2. 이미 ct 가 채워져 있는 row 들의 평문 PII 컬럼 (name / birth_date /
   medical_notes) 을 NULL 로 비운다 — 디스크에 평문이 남는 것을 막기 위함.

T-003-5b 후속 PR 에서 컬럼 자체를 DROP COLUMN 한다 — 그땐 모델에서도 컬럼
정의를 제거.

운영 적용 순서:
  1) 006 백필 적용 (이미 prod 에 적용된 상태여야 함)
  2) 본 007 마이그 적용
  3) 새 코드 (T-003-5a, plaintext write 안 함) 배포

만약 코드가 마이그보다 먼저 떠도 — 코드가 INSERT 에서 name 을 보내지 않으면
구 스키마 (NOT NULL) 에서 `null value in column "name"` 에러로 거부된다. 따라서
**알람빅 마이그를 코드 배포보다 먼저** 돌려야 한다 (k8s init container 패턴).
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "007_residents_plaintext_nullable"
down_revision = "006_resident_pii_backfill"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1) NOT NULL 제거 — Postgres 는 이게 ALTER TABLE 에서 metadata-only 변경.
    op.alter_column("residents", "name", nullable=True)

    # 2) 이미 백필된 row 의 평문 PII 컬럼을 NULL 로 비운다. dek_wrapped 가 채워진
    #    row 만 대상 — 만약 어떤 이유로 백필 안 된 row 가 남아있으면 평문 보존
    #    (안전망: 그런 row 는 read 에서 plaintext fallback 으로 흐른다).
    op.execute(
        "UPDATE residents "
        "SET name = NULL, birth_date = NULL, medical_notes = NULL "
        "WHERE dek_wrapped IS NOT NULL"
    )


def downgrade() -> None:
    # 평문은 한 번 NULL 로 비우면 복구 불가 (ct 는 그대로지만 평문은 잃음).
    # NOT NULL 만 되돌리는 건 이미 NULL 인 row 가 있으면 실패한다. 따라서
    # downgrade 도 의도적 no-op. 운영에서 되돌릴 일이 생기면 별도 데이터 복구
    # 스크립트로 ct 를 decrypt 해 평문 컬럼에 다시 채운 뒤 NOT NULL 을 거는
    # 절차가 필요.
    pass
