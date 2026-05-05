"""
초대 API 엔드포인트
- 직원: 보호자 초대 (전화번호 또는 이메일)
- 보호자: 초대 확인 및 수락/거절
"""

import uuid
import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import Response
from sqlalchemy import select, desc, and_, or_
from sqlalchemy.orm import aliased
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.residents import apply_pii_decryption
from app.core.audit import admin_audit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user, get_current_guardian, get_current_staff
from app.models.models import Invitation, Guardian, Resident, User, Facility, Notification
from app.schemas.schemas import InvitationCreate, InvitationResponse
from app.services.biztalk_service import BizTalkService
from app.services.poster import build_invitation_poster_pdf

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/invitations", tags=["invitations"])


# ==================== 직원용 API ====================

@router.post("", response_model=InvitationResponse)
async def create_invitation(
    req: InvitationCreate,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """보호자 초대 (직원/관리자용).

    T-149: 채널 분기.
    - sms    : 문자메시지 채널. phone 또는 email 필수. 카카오 알림톡 발송 시도 (MOCK).
    - in_app : 가입 회원 초대. invitee_user_id 필수. 인앱 알림 레코드 생성.
    """
    facility_id = current_user.get("facility_id")
    if not facility_id:
        raise HTTPException(status_code=400, detail="시설 정보가 없습니다.")

    invite_type = (req.invite_type or "sms").strip()
    if invite_type not in ("sms", "in_app"):
        raise HTTPException(status_code=400, detail="invite_type 은 sms 또는 in_app 이어야 합니다.")

    if invite_type == "sms":
        if not req.phone and not req.email:
            raise HTTPException(status_code=400, detail="전화번호 또는 이메일 중 하나는 필수입니다.")
    else:  # in_app
        if not req.invitee_user_id:
            raise HTTPException(status_code=400, detail="초대 대상 회원이 필요합니다.")

    # 입소자 확인
    res_stmt = select(Resident).filter(
        Resident.id == req.resident_id,
        Resident.facility_id == facility_id,
        Resident.is_active == True,
    )
    res_result = await db.execute(res_stmt)
    resident = res_result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="해당 입소자를 찾을 수 없습니다.")
    apply_pii_decryption(resident)  # T-003-3

    # 시설 정보
    fac_stmt = select(Facility).filter(Facility.id == facility_id)
    fac_result = await db.execute(fac_stmt)
    facility = fac_result.scalar_one_or_none()

    # in_app: 초대 대상 회원 존재 확인 + 자기 자신 초대 방지
    invitee: User | None = None
    if invite_type == "in_app":
        invitee_stmt = select(User).filter(User.id == req.invitee_user_id, User.is_active == True)
        invitee_result = await db.execute(invitee_stmt)
        invitee = invitee_result.scalar_one_or_none()
        if not invitee:
            raise HTTPException(status_code=404, detail="해당 회원을 찾을 수 없습니다.")
        if invitee.id == current_user["user_id"]:
            raise HTTPException(status_code=400, detail="본인을 초대할 수 없습니다.")

        # 이미 같은 입소자에 승인된 보호자라면 초대 의미가 없다.
        already_stmt = select(Guardian).filter(
            Guardian.user_id == invitee.id,
            Guardian.resident_id == req.resident_id,
            Guardian.facility_id == facility_id,
            Guardian.is_approved == True,
        )
        already_result = await db.execute(already_stmt)
        if already_result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="이미 해당 입소자의 보호자로 연결되어 있습니다.")

    # 중복 초대 확인 (같은 시설 + 같은 입소자 + 같은 대상으로 pending 초대)
    dup_filters = [
        Invitation.facility_id == facility_id,
        Invitation.resident_id == req.resident_id,
        Invitation.status == "pending",
        Invitation.invite_type == invite_type,
    ]
    if invite_type == "in_app":
        dup_filters.append(Invitation.invitee_user_id == req.invitee_user_id)
    elif req.phone and req.email:
        dup_filters.append(or_(Invitation.phone == req.phone, Invitation.email == req.email))
    elif req.phone:
        dup_filters.append(Invitation.phone == req.phone)
    else:
        dup_filters.append(Invitation.email == req.email)

    dup_stmt = select(Invitation).filter(*dup_filters)
    dup_result = await db.execute(dup_stmt)
    if dup_result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 해당 대상으로 대기 중인 초대가 있습니다.")

    invitation = Invitation(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        resident_id=req.resident_id,
        invite_type=invite_type,
        phone=req.phone if invite_type == "sms" else None,
        email=req.email if invite_type == "sms" else None,
        invitee_user_id=req.invitee_user_id if invite_type == "in_app" else None,
        relationship_type=req.relationship_type,
        message=req.message,
        status="pending",
        invited_by=current_user["user_id"],
    )
    db.add(invitation)

    # in_app: 인앱 알림 레코드 생성 (NotificationService 와 동등한 구조).
    # 직접 만든 이유: send_push_notification 은 push_token 없으면 레코드도 안 만들어
    # 인앱 알림 화면에 안 떠 — 우리는 화면 노출이 핵심이라 무조건 레코드를 만든다.
    if invite_type == "in_app" and invitee is not None:
        notif = Notification(
            id=str(uuid.uuid4()),
            user_id=invitee.id,
            photo_id=None,
            title="보호자 초대 도착",
            message=f"{(facility.name if facility else '시설')}에서 {resident.name}님의 보호자로 초대했습니다.",
            notification_type="guardian_invitation",
            is_read=False,
            is_sent=True,
            sent_at=datetime.utcnow(),
        )
        db.add(notif)

    # T-102: 초대 발송은 시설 외부인에게 접근 권한을 부여하는 시작점 — 감사 대상.
    # 연락처는 존재 여부만 남기고 원본은 미기록 (감사 로그 유출 시 PII 재-유출 방지).
    if invite_type == "in_app":
        channel_label = "in_app"
    elif req.phone:
        channel_label = "phone"
    else:
        channel_label = "email"
    admin_audit(
        db,
        action="invitation_create",
        performed_by=current_user["user_id"],
        target_type="invitation",
        target_id=invitation.id,
        facility_id=facility_id,
        detail=f"resident_id={req.resident_id}, channel={channel_label}",
    )
    await db.commit()

    # 카카오 알림톡 발송 (sms 채널 + 전화번호가 있는 경우만)
    if invite_type == "sms" and req.phone:
        try:
            inviter_stmt = select(User).filter(User.id == current_user["user_id"])
            inviter_result = await db.execute(inviter_stmt)
            inviter = inviter_result.scalar_one_or_none()

            await BizTalkService.send_invitation_notification(
                phone=req.phone,
                facility_name=facility.name if facility else "시설",
                resident_name=resident.name,
                inviter_name=inviter.name if inviter else "직원",
                message=req.message,
            )
        except Exception as e:
            logger.warning(f"BizTalk notification failed: {e}")

    return InvitationResponse(
        id=invitation.id,
        facility_id=invitation.facility_id,
        resident_id=invitation.resident_id,
        invite_type=invitation.invite_type,
        phone=invitation.phone,
        email=invitation.email,
        invitee_user_id=invitation.invitee_user_id,
        invitee_name=invitee.name if invitee else None,
        relationship_type=invitation.relationship_type,
        message=invitation.message,
        status=invitation.status,
        facility_name=facility.name if facility else None,
        resident_name=resident.name,
        created_at=invitation.created_at,
    )


@router.get("/{invitation_id}/poster.pdf")
async def download_invitation_poster(
    invitation_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """
    T-032: 초대 QR 포스터 PDF 다운로드 (직원용).

    시설에서 인쇄해 게시판 / 방에 붙이는 용도. QR 은 프런트엔드의 초대 수락
    페이지 URL 을 인코드하고, 보호자가 로그인 후 accept 엔드포인트에 도달.
    """
    stmt = (
        select(Invitation, Resident, Facility)
        .join(Resident, Invitation.resident_id == Resident.id)
        .join(Facility, Invitation.facility_id == Facility.id)
        .filter(Invitation.id == invitation_id)
    )
    result = await db.execute(stmt)
    row = result.one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail="초대를 찾을 수 없습니다.")

    invitation, resident, facility = row
    apply_pii_decryption(resident)  # T-003-3

    # 호출자가 해당 시설 직원인지 확인 — 타 시설 초대 포스터 발급 차단.
    if current_user.get("facility_id") != facility.id:
        raise HTTPException(status_code=403, detail="해당 시설의 초대가 아닙니다.")

    settings = get_settings()
    invite_url = f"{settings.FRONTEND_URL.rstrip('/')}/invitations/{invitation.id}"

    pdf_bytes = build_invitation_poster_pdf(
        facility_name=facility.name,
        resident_name=resident.name,
        invite_url=invite_url,
        message=invitation.message,
    )

    filename = f"invite-{invitation.id[:8]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/facility/{facility_id}", response_model=list[InvitationResponse])
async def get_facility_invitations(
    facility_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """시설의 모든 초대 목록 (직원용)"""
    Invitee = aliased(User)  # noqa: N806 — invitee_user_id outer join
    stmt = (
        select(Invitation, Resident, Facility, Invitee)
        .join(Resident, Invitation.resident_id == Resident.id)
        .join(Facility, Invitation.facility_id == Facility.id)
        .outerjoin(Invitee, Invitation.invitee_user_id == Invitee.id)
        .filter(Invitation.facility_id == facility_id)
        .order_by(desc(Invitation.created_at))
    )
    result = await db.execute(stmt)
    rows = result.all()

    # T-003-3: Resident PII envelope decrypt
    for _, res, _, _ in rows:
        apply_pii_decryption(res)

    return [
        InvitationResponse(
            id=inv.id,
            facility_id=inv.facility_id,
            resident_id=inv.resident_id,
            invite_type=inv.invite_type,
            phone=inv.phone,
            email=inv.email,
            invitee_user_id=inv.invitee_user_id,
            invitee_name=invitee.name if invitee else None,
            relationship_type=inv.relationship_type,
            message=inv.message,
            status=inv.status,
            facility_name=fac.name,
            resident_name=res.name,
            created_at=inv.created_at,
        )
        for inv, res, fac, invitee in rows
    ]


# ==================== 보호자용 API ====================

@router.get("/me", response_model=list[InvitationResponse])
async def get_my_invitations(
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """내 전화번호/이메일/계정으로 온 초대 목록.

    T-149: in_app 채널 추가 — invitee_user_id 가 본인 ID 인 초대도 같이 노출.
    """
    user_stmt = select(User).filter(User.id == current_user["user_id"])
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if not user:
        return []

    # 전화번호 / 이메일 / 본인 계정 ID 매칭
    match_conditions = [Invitation.invitee_user_id == user.id]
    if user.phone:
        match_conditions.append(Invitation.phone == user.phone)
    if user.email:
        match_conditions.append(Invitation.email == user.email)

    stmt = (
        select(Invitation, Resident, Facility)
        .join(Resident, Invitation.resident_id == Resident.id)
        .join(Facility, Invitation.facility_id == Facility.id)
        .filter(
            or_(*match_conditions),
            Invitation.status == "pending",
        )
        .order_by(desc(Invitation.created_at))
    )
    result = await db.execute(stmt)
    rows = result.all()

    # T-003-3: Resident PII envelope decrypt
    for _, res, _ in rows:
        apply_pii_decryption(res)

    return [
        InvitationResponse(
            id=inv.id,
            facility_id=inv.facility_id,
            resident_id=inv.resident_id,
            invite_type=inv.invite_type,
            phone=inv.phone,
            email=inv.email,
            invitee_user_id=inv.invitee_user_id,
            invitee_name=user.name if inv.invitee_user_id == user.id else None,
            relationship_type=inv.relationship_type,
            message=inv.message,
            status=inv.status,
            facility_name=fac.name,
            resident_name=res.name,
            created_at=inv.created_at,
        )
        for inv, res, fac in rows
    ]


@router.post("/{invitation_id}/accept")
async def accept_invitation(
    invitation_id: str,
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """초대 수락 → Guardian 자동 생성 + 자동 승인"""
    stmt = select(Invitation).filter(
        Invitation.id == invitation_id,
        Invitation.status == "pending",
    )
    result = await db.execute(stmt)
    invitation = result.scalar_one_or_none()
    if not invitation:
        raise HTTPException(status_code=404, detail="초대를 찾을 수 없거나 이미 처리되었습니다.")

    # 전화번호 / 이메일 / 가입 회원 (invitee_user_id) 일치 확인
    user_stmt = select(User).filter(User.id == current_user["user_id"])
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()

    phone_match = user and user.phone and invitation.phone and user.phone == invitation.phone
    email_match = user and user.email and invitation.email and user.email == invitation.email
    user_match = user and invitation.invitee_user_id and invitation.invitee_user_id == user.id
    if not phone_match and not email_match and not user_match:
        raise HTTPException(status_code=403, detail="이 초대의 대상이 아닙니다.")

    # 이미 Guardian 연결이 있는지 확인
    dup_stmt = select(Guardian).filter(
        Guardian.user_id == current_user["user_id"],
        Guardian.resident_id == invitation.resident_id,
        Guardian.facility_id == invitation.facility_id,
    )
    dup_result = await db.execute(dup_stmt)
    existing = dup_result.scalar_one_or_none()
    if existing and existing.is_approved:
        # 이미 승인된 연결이 있으면 초대만 처리
        invitation.status = "accepted"
        invitation.accepted_at = datetime.utcnow()
        await db.commit()
        return {"message": "이미 연결되어 있습니다."}

    # Guardian 레코드 생성 (자동 승인)
    if existing:
        existing.is_approved = True
        existing.is_rejected = False
        existing.approved_at = datetime.utcnow()
        existing.approved_by = invitation.invited_by
        existing.relationship_type = invitation.relationship_type
    else:
        guardian = Guardian(
            id=str(uuid.uuid4()),
            user_id=current_user["user_id"],
            resident_id=invitation.resident_id,
            facility_id=invitation.facility_id,
            relationship_type=invitation.relationship_type,
            is_approved=True,
            approved_by=invitation.invited_by,
            approved_at=datetime.utcnow(),
        )
        db.add(guardian)

    invitation.status = "accepted"
    invitation.accepted_at = datetime.utcnow()
    await db.commit()

    # 시설/입소자 이름 조회
    res_stmt = select(Resident).filter(Resident.id == invitation.resident_id)
    res_result = await db.execute(res_stmt)
    resident = res_result.scalar_one_or_none()
    if resident is not None:
        apply_pii_decryption(resident)  # T-003-3

    fac_stmt = select(Facility).filter(Facility.id == invitation.facility_id)
    fac_result = await db.execute(fac_stmt)
    facility = fac_result.scalar_one_or_none()

    return {
        "message": f"{facility.name}에서 {resident.name}님의 보호자로 연결되었습니다.",
        "facility_name": facility.name if facility else None,
        "resident_name": resident.name if resident else None,
    }


@router.post("/{invitation_id}/reject")
async def reject_invitation(
    invitation_id: str,
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """초대 거절"""
    stmt = select(Invitation).filter(
        Invitation.id == invitation_id,
        Invitation.status == "pending",
    )
    result = await db.execute(stmt)
    invitation = result.scalar_one_or_none()
    if not invitation:
        raise HTTPException(status_code=404, detail="초대를 찾을 수 없거나 이미 처리되었습니다.")

    invitation.status = "rejected"
    await db.commit()

    return {"message": "초대를 거절했습니다."}
