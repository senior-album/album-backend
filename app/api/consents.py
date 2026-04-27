"""
T-020: 동의 문서 조회 API

가입 폼이 사용 — type 별로 가장 최신의 활성(effective_from <= now < effective_until) 문서를 반환.
"""

import logging
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import ConsentDocument
from app.schemas.schemas import ConsentDocumentResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/consents", tags=["consents"])


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
