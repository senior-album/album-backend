"""
T-020 PR3a: legal_settings (회사 정보 KV) 조회/편집 API.

- GET /legal/settings: 비인증 공개. PrivacyPage/TermsPage 가 회사명·연락처·시행일을 렌더할 때 호출.
- PUT /legal/settings: 운영자만. 부분 업데이트 — 보낸 키만 upsert. 미존재 키도 새로 생성.

본문 (consent_documents.content) 의 publish 는 별도 — app/api/consents_admin.py.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, require_operator
from app.models.models import LegalSetting

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/legal", tags=["legal"])


class LegalSettingsUpdate(BaseModel):
    """운영자가 보내는 부분 업데이트 페이로드 — { key: value, ... }."""

    settings: dict[str, str]


@router.get("/settings")
async def get_legal_settings(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    """현재 모든 legal_settings 키-값 맵. 비인증 (PrivacyPage/TermsPage 가 직접 호출)."""
    rows = (await db.execute(select(LegalSetting))).scalars().all()
    return {r.key: r.value for r in rows}


@router.put("/settings")
async def update_legal_settings(
    body: LegalSettingsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: dict = Depends(require_operator),
) -> dict[str, str]:
    """운영자만. 보낸 키만 업데이트. 미존재 키는 새로 INSERT."""
    if not body.settings:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="업데이트할 항목이 없습니다.",
        )

    user_id = current_user.get("user_id")
    now = datetime.utcnow()

    existing = {
        r.key: r
        for r in (
            await db.execute(
                select(LegalSetting).where(LegalSetting.key.in_(list(body.settings.keys())))
            )
        )
        .scalars()
        .all()
    }

    for key, value in body.settings.items():
        if key in existing:
            existing[key].value = value
            existing[key].updated_at = now
            existing[key].updated_by_user_id = user_id
        else:
            db.add(
                LegalSetting(
                    key=key,
                    value=value,
                    updated_at=now,
                    updated_by_user_id=user_id,
                )
            )

    await db.commit()

    rows = (await db.execute(select(LegalSetting))).scalars().all()
    return {r.key: r.value for r in rows}
