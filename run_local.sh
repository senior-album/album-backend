#!/bin/bash
# Senior Album API - 로컬 실행 스크립트
# 사전 준비:
#   brew install postgresql@16
#   brew services start postgresql@16
#   createdb senior_album
#   (선택) brew install redis && brew services start redis

set -e

echo "=== Senior Album API 로컬 실행 ==="

# 가상환경 확인/생성
if [ ! -d "venv" ]; then
    echo "가상환경 생성 중..."
    python3 -m venv venv
fi

echo "가상환경 활성화..."
source venv/bin/activate

# 패키지 설치
echo "패키지 설치 중..."
pip install -r requirements.txt --quiet

# uploads 디렉토리 생성
mkdir -p uploads

# 서버 실행
echo ""
echo "=== FastAPI 서버 시작 (http://localhost:8000) ==="
echo "  API 문서: http://localhost:8000/docs"
echo ""
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
