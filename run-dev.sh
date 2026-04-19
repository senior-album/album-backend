#!/bin/bash
# 개발 환경 실행 스크립트

set -e

echo "Senior Album API - Development Server"
echo "======================================"

# .env 파일 확인
if [ ! -f ".env" ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    echo "Please update .env with your configuration"
fi

# Python 가상환경 확인
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3.11 -m venv venv
    echo "Virtual environment created"
fi

# 가상환경 활성화
source venv/bin/activate

# 의존성 설치
echo "Installing dependencies..."
pip install -r requirements.txt

# 서버 실행
echo ""
echo "Starting server on http://localhost:8000"
echo "API docs: http://localhost:8000/docs"
echo ""

uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
