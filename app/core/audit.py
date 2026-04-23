"""
T-102: 관리자 특권 행위 감사 로그 헬퍼.

각 API 라우터에서 이 헬퍼를 호출해서 `AdminAuditLog` 에 이벤트를 추가한다.
감사 실패가 본 요청을 깨지 않도록 try/except 로 감싼다 — 감사는 best-effort,
실제 쓰기 트랜잭션을 막지 않는다. 호출자는 `db.commit()` 로 일괄 커밋.
"""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import AdminAuditLog


logger = logging.getLogger(__name__)


def admin_audit(
    db: AsyncSession,
    *,
    action: str,
    performed_by: str,
    target_type: str,
    target_id: str,
    facility_id: Optional[str] = None,
    detail: Optional[str] = None,
) -> None:
    """
    `AdminAuditLog` 행을 세션에 enqueue. 커밋은 호출자 몫.

    detail 에는 추가 컨텍스트(승인/거부 사유, 대상 이름 등) 를 짧게 문자열로
    넣는다. PII 는 최소화 — 이름 풀네임이나 휴대폰 원본은 이 감사 로그 자체가
    유출됐을 때 재-유출이 되므로 마스킹된 식별자 선호.
    """
    try:
        db.add(AdminAuditLog(
            action=action,
            performed_by=performed_by,
            target_type=target_type,
            target_id=target_id,
            facility_id=facility_id,
            detail=detail,
        ))
    except Exception as e:
        logger.warning(
            f"admin_audit enqueue failed (action={action}, target={target_type}/{target_id}): {e}"
        )
