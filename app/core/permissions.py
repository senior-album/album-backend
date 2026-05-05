"""
T-150: 시설 직원 메뉴 권한 카탈로그 + 검사 의존성.

`UserPermission.permission_key` 에 들어갈 수 있는 값을 코드 레벨에서 단일 출처로
관리. DB 는 자유 문자열 컬럼이지만 본 모듈을 거치지 않은 키는 grant 거부.

키 컨벤션: `<scope>:<resource>:<action>`
- scope: `facility` (시설 한정), 향후 다른 스코프 추가 가능
- resource: `stats`, `residents`, `guardians`, ...
- action: `view`, `edit`, `approve`, ...

자동 통과 규칙 (DB 행 불필요):
- `is_operator=True` — Senior Album 자체 운영자, 모든 시설/모든 키
- `is_admin=True` — 시설장, 자기 시설의 모든 키 (스코프가 `facility:` 인 키)
"""

from __future__ import annotations

from typing import Final

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user


FACILITY_STATS_VIEW: Final[str] = "facility:stats:view"


# 위임 가능한 모든 키. grant API 와 require_permission 양쪽이 화이트리스트로 사용.
ALL_PERMISSION_KEYS: Final[frozenset[str]] = frozenset({
    FACILITY_STATS_VIEW,
})


def is_known_permission_key(key: str) -> bool:
    return key in ALL_PERMISSION_KEYS


async def has_permission(db: AsyncSession, user, key: str) -> bool:
    """
    DB 모델 인스턴스 `user` 가 `key` 를 보유하는지 검사.

    호출 전에 user 가 활성 상태(`is_active=True`) 인지는 호출자가 보장.
    """
    if user.is_operator:
        return True
    if user.is_admin and key.startswith("facility:"):
        # 시설장은 자기 시설 한정 키를 행 없이 자동 통과.
        # 단, facility_id 가 비어있으면 (운영자가 시설 해제한 시설장 등) 차단 — admin.py
        # 의 patch_user 가 is_admin=True + facility_id 빈 조합을 막지만 데이터 정합성
        # 보장은 못 하므로 한 번 더 체크.
        return bool(user.facility_id)

    from app.models.models import UserPermission

    stmt = select(UserPermission.id).where(
        UserPermission.user_id == user.id,
        UserPermission.permission_key == key,
    ).limit(1)
    result = await db.execute(stmt)
    return result.scalar_one_or_none() is not None


def require_permission(key: str):
    """
    FastAPI dependency factory. `Depends(require_permission("facility:stats:view"))`
    형태로 사용.

    T-105 패턴: JWT 가 아닌 DB 에서 사용자 활성/권한을 매 요청 재검증.
    권한 없음 → 403, 사용자 비활성/미존재 → 401.

    사용 키는 카탈로그(`ALL_PERMISSION_KEYS`) 에 등록되어 있어야 함 — 등록 안 된 키로
    require_permission 을 호출하는 코드는 import 시점이 아니라 요청 시점에 500 으로
    드러남. 카탈로그 추가를 잊지 않도록 방어.
    """
    if not is_known_permission_key(key):
        raise ValueError(
            f"Unknown permission key: {key!r}. Add it to ALL_PERMISSION_KEYS."
        )

    async def _dep(
        current_user: dict = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
    ) -> dict:
        from app.models.models import User

        user = await db.get(User, current_user.get("user_id"))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="계정이 비활성화되었거나 존재하지 않습니다.",
            )
        if not await has_permission(db, user, key):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 메뉴 접근 권한이 없습니다.",
            )
        return current_user

    return _dep
