# album-backend 레포용 Dockerfile
# 레포 루트에 Dockerfile로 저장

# Stage 1: 빌드 의존성 설치
# 베이스 이미지 digest pin (T-053) — tag 이동으로 인한 공급망 리스크 차단
FROM python:3.11-slim@sha256:6d85378d88a19cd4d76079817532d62232be95757cb45945a99fec8e8084b9c2 AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: 런타임
FROM python:3.11-slim@sha256:6d85378d88a19cd4d76079817532d62232be95757cb45945a99fec8e8084b9c2

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libgl1 \
    libglib2.0-0 \
    libmagic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# Albumentations 기동 시 version check HTTP 호출을 막아 liveness timeout 방지
ENV NO_ALBUMENTATIONS_UPDATE=1

COPY app ./app
COPY requirements.txt .
# Alembic (DB migrations) — PR #57 로 추가됐지만 Dockerfile COPY 누락돼서
# 컨테이너에서 `alembic` CLI 가 script_location 을 못 찾아 실패했던 문제 수정.
COPY alembic.ini .
COPY alembic ./alembic

# InsightFace buffalo_l 모델 자동 다운로드
RUN python -c "\
from insightface.app import FaceAnalysis; \
app = FaceAnalysis(name='buffalo_l', root='/app/models'); \
app.prepare(ctx_id=-1, det_size=(640,640)); \
print('Model downloaded successfully')"

RUN mkdir -p /app/uploads

RUN useradd -m -s /bin/bash appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# 기동 시 DB 마이그레이션을 먼저 적용한 후 uvicorn 실행.
# - `alembic upgrade head` 가 실패하면 컨테이너가 죽고 k8s 가 재시작 → fail-fast.
# - `exec` 로 uvicorn 을 띄워 shell 이 중간에 끼지 않게 하고 signal (SIGTERM) 이
#   그대로 uvicorn 에 전달되도록 한다.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2"]
