"""
Alembic baseline migration 에 심을 CREATE TABLE / CREATE INDEX SQL 을 덤프.

실행:
    .venv/Scripts/python.exe -m scripts.dump_baseline_ddl > /tmp/baseline_ddl.sql

동작 원리:
    - `Base.metadata.sorted_tables` 는 FK 의존성에 따라 부모 → 자식 순서로 정렬됨
    - 각 테이블을 postgres dialect 로 DDL 컴파일 → SQL 생성
    - 인덱스 / UNIQUE / FK 제약도 그대로 포함됨 (Column 에 붙은 것은 inline, Index(...) 는 별도 statement)

이 SQL 을 alembic versions/001_baseline.py 안에 `op.execute(...)` 로 심으면
baseline 이 작성 시점의 모델을 frozen snapshot 으로 박제한다. 이후 모델이
바뀌어도 baseline 은 그 시점 스키마를 정확히 재현 — subsequent revisions 와
충돌 없음.
"""

import sys
from pathlib import Path

# backend 루트를 path 에 추가 (스크립트를 직접 실행할 때도 app. 로딩 가능하게)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable, CreateIndex

from app.models.models import Base


def main():
    dialect = postgresql.dialect()
    print("-- BEGIN baseline DDL (postgres dialect)")
    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=dialect)).strip()
        print(ddl + ";")
        print()
        for index in table.indexes:
            idx_ddl = str(CreateIndex(index).compile(dialect=dialect)).strip()
            print(idx_ddl + ";")
        print()
    print("-- END baseline DDL")


if __name__ == "__main__":
    main()
