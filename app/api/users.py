"""
사용자 관련 API (직원·관리자가 일반 사용자를 조회하는 좁은 라우트).

T-149: 가입 회원 초대를 위해 직원이 보호자 사용자를 검색할 수 있는 엔드포인트.
운영자용 광역 검색 (`/admin/users`) 과는 달리, 한 시설의 일반 직원도 호출 가능
하지만 결과는 정확 일치 1건 + 마스킹된 필드만 노출 — 회원 디렉터리 사고 방지.
"""

import logging
import re
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import phone_blind_index
from app.core.database import get_db
from app.core.security import get_current_staff
from app.models.models import User
from app.schemas.schemas import UserSearchResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])


_PHONE_DIGITS_RE = re.compile(r"[^0-9]")


def _normalize_phone(raw: str) -> str:
    """하이픈/공백/괄호 제거. DB 저장 포맷이 일관되지 않을 수 있어 비교 시 정규화."""
    return _PHONE_DIGITS_RE.sub("", raw or "")


def _mask_name(name: str) -> str:
    """홍길동 → 홍O동, 이OO → 이OO. 1글자면 그대로."""
    if not name:
        return ""
    if len(name) <= 1:
        return name
    if len(name) == 2:
        return name[0] + "O"
    return name[0] + "O" * (len(name) - 2) + name[-1]


def _mask_phone(phone: str | None) -> str | None:
    """010-1234-5678 → 010-****-5678. 형식이 다르면 가운데를 그냥 마스킹."""
    if not phone:
        return None
    digits = _normalize_phone(phone)
    if len(digits) >= 8:
        return f"{digits[:3]}-****-{digits[-4:]}"
    # 짧은 번호 — 절반만 노출
    half = max(1, len(digits) // 2)
    return digits[:half] + "*" * (len(digits) - half)


def _mask_email(email: str | None) -> str | None:
    """abc@example.com → a**@example.com. local-part 첫 글자만 노출."""
    if not email or "@" not in email:
        return None
    local, _, domain = email.partition("@")
    if not local:
        return f"@{domain}"
    return local[0] + "*" * max(1, len(local) - 1) + "@" + domain


@router.get("/search", response_model=UserSearchResult | None)
async def search_user(
    query: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """
    가입 회원 검색 (직원 전용).

    매칭 규칙 — 개인정보 보호상 **정확 일치만** 허용:
    - `query` 에 `@` 가 들어 있으면 이메일 전체 일치 (대소문자 구분 없이)
    - 그렇지 않으면 전화번호 정규화 (숫자만 추출) 후 정확 일치

    부분/이름 검색은 의도적으로 막음 — 회원 명단을 훑는 행위가 가능해지면
    개인정보 영향평가 (T-283) 범위가 커진다. 직원이 보호자에게서 받은 정확한
    번호/이메일을 입력해야만 1명을 찾을 수 있다.

    반환 형식:
    - 매칭 1건이면 마스킹된 결과
    - 매칭 0건이면 204 가 아닌 200 + null body (프론트에서 분기 단순화)
    """
    if not query or not query.strip():
        raise HTTPException(status_code=400, detail="검색어가 비어있습니다.")
    q = query.strip()

    if "@" in q:
        # 이메일 정확 일치 (소문자 정규화)
        stmt = select(User).filter(User.email == q.lower())
    else:
        digits = _normalize_phone(q)
        if not digits:
            raise HTTPException(
                status_code=400,
                detail="전화번호 또는 이메일 형식으로 입력해주세요.",
            )
        # T-320-3: blind-index 단일 비교로 통합. `phone_blind_index` 가 정규화 후
        # HMAC 하므로 하이픈 유무 모두 같은 키로 매칭 — 옛 `digits|q` OR 도 불필요.
        stmt = select(User).filter(User.phone_bi == phone_blind_index(q))

    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user is None:
        return None

    return UserSearchResult(
        id=user.id,
        name_masked=_mask_name(user.name or ""),
        phone_masked=_mask_phone(user.phone),
        email_masked=_mask_email(user.email),
    )
