# Senior Album API - FastAPI 백엔드

요양원에서 촬영한 사진을 AI 얼굴 인식(InsightFace/ArcFace)으로 자동 분류하고, 보호자에게 해당 어르신 사진만 공유하는 B2B SaaS의 백엔드 API입니다.

## 기술 스택

- **Framework**: FastAPI 0.111.0
- **Database**: PostgreSQL (SQLAlchemy 2.0 AsyncSession + asyncpg)
- **Search Engine**: OpenSearch (얼굴 임베딩 벡터 검색)
- **Authentication**: JWT (자체 발급) + 카카오 OAuth
- **Storage**: MinIO (S3 호환 오브젝트 스토리지), 로컬 fallback
- **Face Recognition**: InsightFace (ArcFace) / ONNX Runtime
- **Cache / Rate Limiting**: Redis (인메모리 fallback 지원)
- **Background Worker**: asyncio 기반 사진 처리 워커

## 프로젝트 구조

```
src/backend/
├── app/
│   ├── main.py                     # FastAPI 앱, 라이프사이클, 라우터 등록
│   ├── core/
│   │   ├── config.py               # 환경변수 및 설정 (pydantic-settings)
│   │   ├── database.py             # DB 연결, 세션, DDL 자동 마이그레이션
│   │   ├── security.py             # JWT 생성/검증, 시설 접근 제어
│   │   ├── storage.py              # MinIO/로컬 파일 스토리지
│   │   └── redis.py                # Redis 연결, Rate Limiting
│   ├── models/
│   │   └── models.py               # SQLAlchemy ORM (User, Facility, Resident, Photo 등)
│   ├── schemas/
│   │   └── schemas.py              # Pydantic 요청/응답 스키마
│   ├── api/
│   │   ├── auth.py                 # 이메일/비밀번호 로그인, 회원가입, 토큰 갱신
│   │   ├── kakao_auth.py           # 카카오 OAuth 로그인
│   │   ├── facilities.py           # 시설 관리 (코드↔UUID 자동 변환)
│   │   ├── residents.py            # 입소자 CRUD, 기준 사진 등록
│   │   ├── photos.py               # 사진 업로드, 공개/비공개, 공유링크, 좋아요
│   │   ├── guardians.py            # 보호자 사진 조회, 프로필, 승인 관리
│   │   └── invitations.py          # 보호자↔입소자 초대/수락/거절
│   └── services/
│       ├── face_recognition.py     # InsightFace 얼굴 감지 및 임베딩 추출
│       ├── opensearch_service.py   # OpenSearch 벡터 인덱스 관리
│       ├── photo_service.py        # 사진 처리 로직
│       ├── photo_worker.py         # 백그라운드 사진 처리 워커
│       ├── notification_service.py # 알림 서비스
│       └── biztalk_service.py      # 외부 연동 서비스
├── requirements.txt
├── .env.example
└── uploads/                        # MinIO 없을 때 로컬 저장소
```

## 설치 및 실행

### 1. 환경 설정

```bash
cp .env.example .env
# .env 파일을 편집하여 환경에 맞게 수정
```

### 2. 외부 서비스 (사전에 실행 필요)

- **PostgreSQL**: `DATABASE_URL`에 설정된 주소
- **Redis**: `REDIS_URL`에 설정된 주소 (없으면 인메모리 fallback)
- **MinIO**: `MINIO_ENDPOINT`에 설정된 주소 (없으면 로컬 파일 저장)
- **OpenSearch**: `OPENSEARCH_HOST:OPENSEARCH_PORT` (없으면 얼굴 검색 비활성화)

### 3. 로컬 실행

```bash
# Python 3.10+ 필요
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements.txt

# 서버 실행
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

서버 시작 시 자동으로 수행되는 작업:
- `alembic upgrade head` — Alembic 마이그레이션 적용 (컨테이너 CMD)
- Redis 연결 시도
- InsightFace 모델 로드
- OpenSearch 인덱스 초기화
- 사진 처리 백그라운드 워커 시작

## 환경변수 (.env)

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `DATABASE_URL` | PostgreSQL 연결 | `postgresql+asyncpg://postgres:postgres@localhost:5432/senior_album` |
| `REDIS_URL` | Redis 연결 | `redis://localhost:6379/0` |
| `JWT_SECRET` | JWT 서명 키 | (프로덕션에서 반드시 변경) |
| `JWT_EXPIRE_MINUTES` | 토큰 만료 시간 | `10080` (7일) |
| `JWT_REFRESH_THRESHOLD_MINUTES` | 토큰 갱신 가능 시간 | `1440` (1일) |
| `MINIO_ENDPOINT` | MinIO 주소 | `localhost:9000` |
| `MINIO_BUCKET` | 버킷 이름 | `senior-album-photos` |
| `FACE_SIMILARITY_THRESHOLD` | 얼굴 유사도 임계값 | `0.6` |
| `LOGIN_MAX_ATTEMPTS` | 로그인 시도 제한 | `5` |
| `LOGIN_LOCKOUT_MINUTES` | 잠금 시간(분) | `15` |
| `SHARE_LINK_EXPIRE_HOURS` | 공유 링크 만료(시간) | `72` |
| `KAKAO_CLIENT_ID` | 카카오 앱 키 | (선택) |
| `FRONTEND_URL` | 프론트엔드 URL | `http://localhost:5173` |
| `API_BASE_URL` | API 외부 URL | `http://localhost:8000` |

## API 엔드포인트

### 시스템
- `GET /health` — 헬스 체크
- `GET /` — API 정보

### 인증 (`/auth`)
- `POST /auth/login` — 이메일/비밀번호 로그인 (Rate Limiting 적용)
- `POST /auth/register/admin` — 시설 관리자 가입 (시설 자동 생성)
- `POST /auth/register/staff` — 직원 가입 (시설 코드로 합류)
- `POST /auth/register/guardian` — 보호자 가입
- `POST /auth/refresh` — JWT 토큰 갱신
- `GET /auth/me` — 현재 사용자 + 시설 정보

### 카카오 OAuth (`/auth/kakao`)
- `GET /auth/kakao/login-url` — 카카오 로그인 URL
- `POST /auth/kakao/callback` — 카카오 인증 콜백
- `POST /auth/kakao/set-role` — 카카오 로그인 후 역할 설정

### 시설 (`/facilities`)
- `GET /facilities/{id}` — 시설 조회 (코드/UUID 모두 지원)
- `GET /facilities/{id}/residents` — 시설 입소자 목록
- `GET /facilities/{id}/photos` — 시설 사진 목록
- `GET /facilities/{id}/stats` — 시설 통계 (총 사진, 입소자 수 등)

### 입소자 (`/residents`)
- `POST /residents/` — 입소자 등록 (시설 격리 적용)
- `POST /residents/{id}/register-face` — 기준 사진 등록 (얼굴 임베딩)
- `GET /residents/{id}/faces` — 등록된 얼굴 목록
- `DELETE /residents/{id}/faces/{doc_id}` — 얼굴 삭제

### 사진 (`/photos`)
- `POST /photos/upload` — 사진 업로드 (시설 격리, 감사 로그)
- `POST /photos/{id}/like` — 좋아요 토글
- `POST /photos/{id}/share` — 공유 링크 생성 (72시간 만료)
- `GET /photos/shared/{token}` — 공유 사진 조회 (만료 체크)
- `POST /photos/{id}/publish` — 공개/비공개 토글 (감사 로그)
- `POST /photos/bulk-publish` — 일괄 공개/비공개

### 보호자 (`/guardians`)
- `GET /guardians/me/photos` — 내 어르신 사진 (공개된 것만)
- `GET /guardians/me/residents` — 내 어르신 목록
- `GET /guardians/me/status` — 보호자 상태
- `GET /guardians/me` — 보호자 프로필
- `PUT /guardians/me/profile` — 프로필 수정
- `PUT /guardians/me/settings` — 알림 설정
- `GET /guardians/facility/{id}/pending` — 대기 중인 보호자 (직원용)
- `GET /guardians/facility/{id}/all` — 전체 보호자 (직원용)
- `POST /guardians/{id}/approve` — 보호자 승인/거절

### 초대 (`/invitations`)
- `POST /invitations` — 보호자 초대 생성
- `GET /invitations/me` — 내 초대 목록
- `POST /invitations/{id}/accept` — 초대 수락
- `POST /invitations/{id}/reject` — 초대 거절
- `GET /invitations/facility/{id}` — 시설 초대 목록

## 보안

- **JWT 인증**: 자체 발급 토큰, 7일 만료, 프론트엔드에서 자동 갱신
- **Rate Limiting**: Redis 기반 로그인 시도 제한 (5회/15분), Redis 미연결 시 인메모리 fallback
- **시설 데이터 격리**: `verify_facility_access()`로 JWT의 facility_id 검증
- **사진 감사 로그**: `PhotoAuditLog` 테이블에 공개/비공개 이력 추적
- **공유 링크 만료**: 72시간 후 자동 만료, presigned URL 사용
- **CORS**: `ALLOWED_ORIGINS` 환경변수로 허용 도메인 제어

## 데이터베이스 관리

스키마는 Alembic 이 관리합니다. 자세한 워크플로우는 [`docs/MIGRATIONS.md`](docs/MIGRATIONS.md) 참조.

요약:
- 모델 변경 → `alembic revision --autogenerate -m "설명"` → 리뷰 → 커밋
- 로컬: `alembic upgrade head` 수동 실행 (또는 컨테이너에서 자동)
- 컨테이너 기동 시 자동으로 `alembic upgrade head` 실행 (Dockerfile CMD)

## 얼굴 인식

- **모델**: InsightFace buffalo_l (ArcFace 기반)
- **감지 신뢰도**: 0.9 (`FACE_DETECTION_CONFIDENCE`)
- **유사도 임계값**: 0.6 (`FACE_SIMILARITY_THRESHOLD`)
- **벡터 검색**: OpenSearch에 임베딩 저장, cosine similarity로 매칭
- **다대다 분류**: 한 사진에 여러 입소자, 한 입소자가 여러 사진 (PhotoResident 테이블)

## Graceful Fallback

외부 서비스 연결 실패 시에도 서버는 정상 기동됩니다:
- **Redis 없음**: 인메모리 dict로 rate limiting fallback
- **MinIO 없음**: 로컬 `./uploads` 디렉토리에 파일 저장
- **OpenSearch 없음**: 얼굴 벡터 검색 비활성화
- **InsightFace 없음**: 얼굴 인식 비활성화

## CI/CD

`main` 브랜치에 push되면 GitHub Actions가 자동으로 실행됩니다:

1. **Build & Push**: Docker 이미지 빌드 후 `ghcr.io/senior-album/album-backend`에 push (태그: commit SHA 7자리 + `latest`)
2. **Update Manifest**: `senior-album/album-deploy` 레포의 `k8s/backend.yaml` 이미지 태그를 새 SHA로 업데이트
3. **Auto Deploy**: ArgoCD가 GitHub Webhook을 받아 즉시 동기화 → 맥미니 k3d 클러스터에 롤아웃

수동 롤아웃이나 polling 대기 없이 push → 배포가 자동으로 이어집니다.

## 라이선스

MIT License
