"""T-003-5b 후 테스트용 Resident 시드 헬퍼.

평문 PII 컬럼 (`name` / `birth_date` / `medical_notes`) 이 모델에서 drop 됐으므로
`Resident(name="...")` 와 같은 직접 생성은 TypeError. 본 헬퍼가 평문 input 을
받아 envelope encryption 컬럼 (ct + dek + blind_idx) 으로 변환해 시드한다.
"""

from __future__ import annotations

import uuid

from app.core.crypto import blind_index, encrypt_field, generate_dek, wrap_dek
from app.models.models import Resident


def make_resident(
    *,
    facility_id: str,
    name: str = "기본이름",
    birth_date: str | None = None,
    medical_notes: str | None = None,
    code: str | None = None,
    **overrides,
) -> Resident:
    """envelope encryption 컬럼이 채워진 Resident 인스턴스 반환.

    Args:
        facility_id: required FK.
        name / birth_date / medical_notes: 평문 input. ct 로 변환됨.
        code: 명시 안 하면 RES-XXXXXX 자동 생성.
        **overrides: gender / room_number / id / is_active 등 ORM 컬럼 직접 set.
    """
    dek = generate_dek()
    r = Resident(
        id=overrides.pop("id", str(uuid.uuid4())),
        facility_id=facility_id,
        code=code or f"RES-{uuid.uuid4().hex[:6].upper()}",
        is_active=overrides.pop("is_active", True),
        dek_wrapped=wrap_dek(dek),
        name_ct=encrypt_field(name, dek),
        name_blind_idx=blind_index(name),
        birth_date_ct=encrypt_field(birth_date, dek) if birth_date else None,
        medical_notes_ct=encrypt_field(medical_notes, dek) if medical_notes else None,
    )
    for k, v in overrides.items():
        setattr(r, k, v)
    return r
