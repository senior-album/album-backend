# DB Migrations — Alembic

Alembic 로 DB 스키마 변경을 버전 관리한다. 관련 설정: `alembic.ini`, `alembic/env.py`,
`alembic/versions/`.

## TL;DR — 일상 개발 플로우

```bash
# 1. 모델 수정
vim app/models/models.py

# 2. 마이그레이션 자동 생성
alembic revision --autogenerate -m "add X column to Y"

# 3. 생성된 파일 리뷰 (alembic/versions/NNN_xxx.py)
#    - 의도한 변경만 들어있는지 확인
#    - downgrade() 가 올바른지 확인 (rollback 가능해야 함)

# 4. 로컬에서 적용
alembic upgrade head

# 5. 커밋
git add alembic/versions/ app/models/models.py
```

## 현재 상태

- `001_baseline` 리비전이 head.
- 컨테이너 기동 시 `alembic upgrade head` 가 자동 실행 (Dockerfile CMD). 실패하면 컨테이너가 죽고 k8s 재시작.
- `DDL_AUTO` / `_add_missing_columns` 제거됨 — Alembic 이 유일한 스키마 소스.

## 프로덕션 최초 반영 (1회 수동 작업)

baseline 작성 시점에 이미 존재하는 스테이징/운영 DB 에는 `upgrade head`
를 돌리면 안 된다 (CREATE TABLE 이 "already exists" 로 실패). 대신
baseline 을 "적용된 걸로 표시" 만 한다:

```bash
kubectl -n senior-album exec -it deploy/backend -- alembic stamp head
```

이후 `alembic_version` 테이블이 `001_baseline` 을 들고 있게 된다.
다음 마이그레이션부터는 정상 `alembic upgrade head` 경로.

## 신규 환경 (로컬 / CI / 새 배포)

빈 DB 면 그냥 전부 실행:

```bash
alembic upgrade head
```

`001_baseline` 부터 최신 head 까지 순차 적용.

## 새 마이그레이션 작성

```bash
# 자동 생성 (권장) - 모델과 현재 DB 를 비교해 diff 를 migration 파일로
alembic revision --autogenerate -m "설명"

# 수동 생성 - 데이터 백필, 인덱스 리빌드 등 autogenerate 가 못 잡는 것
alembic revision -m "설명"
```

**생성된 파일 리뷰 필수**:
- 불필요한 index drop/recreate 가 들어있지 않은지 (SQLAlchemy 가 index 이름을
  다르게 생각하는 경우 발생)
- `op.execute()` 로 raw SQL 이 필요하면 downgrade 도 빠짐없이 작성
- 대용량 테이블에서 ALTER COLUMN 은 lock 이 길어질 수 있음 - 별도 커뮤니케이션

## 롤백

```bash
# 직전 리비전으로
alembic downgrade -1

# 특정 리비전으로
alembic downgrade 001_baseline

# 전부 되돌리기 (드롭)
alembic downgrade base
```

## 트러블슈팅

### `already exists` 에러 (production 에서 upgrade 시)
→ stamp 를 건너뛰었을 가능성. 현재 DB 상태를 파악 후:
```bash
alembic current  # 현재 표시된 리비전
alembic stamp head  # 최신으로 강제 스탬프 (데이터는 건드리지 않음)
```

### 로컬에서 autogenerate 가 DB 연결 에러
→ `.env` 에 `POSTGRES_*` 변수 또는 `DATABASE_URL` 이 세팅돼 있어야 함.
로컬 postgres 가 안 돌고 있으면 docker-compose up 먼저.

### 여러 사람이 동시에 revision 만들어서 head 가 두 개
→ `alembic merge heads -m "merge"` 로 머지 리비전 생성.

## 설정 파일 위치

- `alembic.ini` - alembic CLI 설정 (URL 은 env.py 에서 덮어씀)
- `alembic/env.py` - 런타임 설정 (Base.metadata 연결, URL 주입)
- `alembic/versions/NNN_xxx.py` - 개별 마이그레이션
- `scripts/dump_baseline_ddl.py` - baseline 재생성용 (normally 불필요)
