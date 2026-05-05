"""T-003-4: residents PII envelope encryption — 기존 row 백필

Revision ID: 006_resident_pii_backfill
Revises: 005_phone_uniqueness_and_claims
Create Date: 2026-05-05

T-003-2 dual-write 시작 이전에 만들어져 평문 컬럼만 차있고 ciphertext 가 비어있는
row 를 모두 envelope encryption 으로 채운다. 백필 후엔 모든 row 가 read 경로에서
`apply_pii_decryption` (T-003-3) 을 거쳐 ct 결과를 반환 — 이로써 T-003-5
(plaintext 컬럼 drop) 가 안전해진다.

전제:
- T-003-1 (002 마이그) 가 컬럼을 이미 만들어둠 (`name_ct`, `dek_wrapped` 등).
- 환경변수 `RESIDENT_PII_KEK` / `RESIDENT_NAME_HMAC_KEY` 가 주입돼 있어야 함.
  마이그 실행 컨테이너에 SealedSecret 마운트 필수 (album-deploy 측 책임).

멱등성: `WHERE dek_wrapped IS NULL AND name IS NOT NULL` 로 필터 — 두 번째 실행
시 0 rows. 따라서 staging → prod 단계 적용도 안전.

Downgrade 는 no-op. 한 번 백필된 데이터를 되돌리는 일은 위험 — dual-write 시점
이후 만들어진 row 도 ct 가 채워져 있어서, 일괄 NULL 로 되돌리면 dual-write 데이터를
파괴한다. 운영에서 되돌릴 일 생기면 별도 데이터 복구 스크립트로 처리.
"""

from alembic import op

from app.scripts.backfill_resident_pii import backfill_residents


# revision identifiers, used by Alembic.
revision = "006_resident_pii_backfill"
down_revision = "005_phone_uniqueness_and_claims"
branch_labels = None
depends_on = None


def upgrade() -> None:
    result = backfill_residents(op.get_bind())
    # 마이그 로그에 처리 건수 남김 — alembic 출력으로 흘러 운영 회고에 도움.
    print(f"[T-003-4] residents PII backfilled: {result['processed']} rows")


def downgrade() -> None:
    # 의도적 no-op. 본문 docstring 참고.
    pass
