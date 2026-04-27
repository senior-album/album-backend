"""
T-020: 동의 문서 조회 + 운영자 publish API.

- GET /consents/active: 가입 폼용. 비인증.
- GET /consents/admin/all: 운영자만. 만료 포함 전체 이력.
- POST /consents/admin/publish: 운영자만. 신규 버전 발행 + 이전 활성 row 만료.
"""

import logging
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import require_operator
from app.models.models import ConsentDocument
from app.schemas.schemas import ConsentDocumentResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/consents", tags=["consents"])

# 가입 폼이 다루는 4 종 — publish 도 이 안에서만 허용 (오타로 새 type 만들지 못하게).
ALLOWED_TYPES = {"terms_guardian", "privacy", "sensitive_info", "marketing"}


@router.get("/active", response_model=List[ConsentDocumentResponse])
async def get_active_consents(db: AsyncSession = Depends(get_db)):
    """
    현재 시점에 유효한 약관 문서 목록 — type 별 최신 1개씩 (필수 + 선택 모두).
    """
    now = datetime.utcnow()
    stmt = (
        select(ConsentDocument)
        .where(
            and_(
                ConsentDocument.effective_from <= now,
                or_(
                    ConsentDocument.effective_until.is_(None),
                    ConsentDocument.effective_until > now,
                ),
            )
        )
        .order_by(ConsentDocument.type, ConsentDocument.effective_from.desc())
    )
    rows = (await db.execute(stmt)).scalars().all()

    by_type: dict[str, ConsentDocument] = {}
    for d in rows:
        if d.type not in by_type:
            by_type[d.type] = d
    return list(by_type.values())


@router.get("/admin/all", response_model=List[ConsentDocumentResponse])
async def list_all_consent_documents(
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_operator),
):
    """운영자 — 모든 type · 모든 version (만료 포함) 의 이력. 최신 발행 순."""
    stmt = select(ConsentDocument).order_by(
        ConsentDocument.type, ConsentDocument.effective_from.desc()
    )
    return (await db.execute(stmt)).scalars().all()


class ConsentPublishRequest(BaseModel):
    """신규 약관 버전 발행 — 동일 type 의 기존 활성 row 는 자동으로 effective_until=now 로 만료."""

    type: str = Field(..., description="약관 타입 (terms_guardian/privacy/sensitive_info/marketing)")
    version: str = Field(..., min_length=1, max_length=20, description="새 버전 (예: v1.1)")
    title: str = Field(..., min_length=1, max_length=200)
    content: str = Field(..., min_length=1, description="본문 (markdown)")
    is_mandatory: Optional[bool] = None  # 미지정 시 이전 row 의 값 승계


@router.post(
    "/admin/publish",
    response_model=ConsentDocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def publish_consent_document(
    body: ConsentPublishRequest,
    db: AsyncSession = Depends(get_db),
    _: dict = Depends(require_operator),
):
    """
    신규 약관 버전 발행. 흐름:
    1) 동일 (type, version) 중복 차단 — UniqueConstraint 가 잡지만 사용자에게 명확한 에러.
    2) 동일 type 의 현재 활성 row 들에 effective_until = now 세팅.
    3) 신규 row 를 effective_from = now, effective_until = NULL 로 INSERT.
    is_mandatory 미지정 시 이전 활성 row 의 값을 승계 (마케팅이 갑자기 필수가 되는 사고 방지).
    """
    if body.type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"허용된 type 이 아닙니다: {sorted(ALLOWED_TYPES)}",
        )

    # 동일 (type, version) 존재 검사
    dup = await db.execute(
        select(ConsentDocument).where(
            ConsentDocument.type == body.type,
            ConsentDocument.version == body.version,
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"{body.type} {body.version} 은 이미 존재하는 버전입니다.",
        )

    now = datetime.utcnow()

    # 현재 활성 row 들 만료
    active_stmt = select(ConsentDocument).where(
        ConsentDocument.type == body.type,
        ConsentDocument.effective_from <= now,
        or_(
            ConsentDocument.effective_until.is_(None),
            ConsentDocument.effective_until > now,
        ),
    )
    active_rows = (await db.execute(active_stmt)).scalars().all()

    inherited_mandatory = active_rows[0].is_mandatory if active_rows else True
    is_mandatory = body.is_mandatory if body.is_mandatory is not None else inherited_mandatory

    for row in active_rows:
        row.effective_until = now

    new_doc = ConsentDocument(
        id=str(uuid.uuid4()),
        type=body.type,
        version=body.version,
        title=body.title,
        content=body.content,
        is_mandatory=is_mandatory,
        effective_from=now,
        effective_until=None,
        created_at=now,
    )
    db.add(new_doc)

    await db.commit()
    await db.refresh(new_doc)
    return new_doc
