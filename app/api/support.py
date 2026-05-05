"""고객 지원 — 휴대폰 번호 사칭/오등록 신고 등."""

import logging
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import PhoneClaimReport
from app.schemas.schemas import PhoneClaimRequest, PhoneClaimResponse
from app.services.phone_otp import normalize_phone

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/support", tags=["support"])


@router.post("/phone-claim", response_model=PhoneClaimResponse)
async def report_phone_claim(
    body: PhoneClaimRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    "이 번호 내가 등록 안 했는데?" 신고. OTP verify 가 409 반환했을 때 프론트가 호출.
    DB 저장만 — 운영자가 어드민에서 검토하는 워크플로우는 별 PR.
    """
    phone = normalize_phone(body.phone)
    if not phone:
        raise HTTPException(status_code=400, detail="휴대폰 번호를 입력해주세요.")

    report = PhoneClaimReport(
        id=str(uuid4()),
        reporter_user_id=current_user["user_id"],
        claimed_phone=phone,
        note=(body.note or "").strip(),
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    logger.info(
        f"phone-claim reported id={report.id} reporter={current_user['user_id']} "
        f"phone={phone[:3]}****{phone[-4:]}"
    )
    return PhoneClaimResponse(id=report.id, created_at=report.created_at)
