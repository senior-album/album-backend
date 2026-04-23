# album-backend 레포용 Dockerfile
# 레포 루트에 Dockerfile로 저장

# Stage 1: 빌드 의존성 설치
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: 런타임
FROM python:3.11-slim

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

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
