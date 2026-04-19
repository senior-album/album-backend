#!/bin/bash
# 프로덕션 환경 실행 스크립트

set -e

echo "Senior Album API - Production Server"
echo "====================================="

# .env 파일 확인
if [ ! -f ".env" ]; then
    echo "Error: .env file not found"
    exit 1
fi

# 의존성 설치
echo "Installing dependencies..."
pip install -r requirements.txt

# 데이터베이스 마이그레이션 (필요시)
echo "Running database migrations..."
alembic upgrade head

# 프로덕션 서버 실행 (Gunicorn 권장)
echo ""
echo "Starting production server..."
echo ""

# uvicorn 사용 (Gunicorn이 설치되지 않은 경우)
# Gunicorn을 사용하려면: pip install gunicorn
# gunicorn app.main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

uvicorn app.main:app --host 0.0.0.0 --port 8000
