"""T-003-3 envelope encryption — read 경로 decrypt 단위 테스트.

`apply_pii_decryption` 의 두 갈래를 검증:
  1. dual-write row (`dek_wrapped` + `name_ct` 가 채워진 row) — ct decrypt 결과로
     평문 attribute 가 덮어씌워져 응답이 ct 기반으로 흐른다.
  2. 백필 전 row (`dek_wrapped` 가 None) — no-op. 평문 컬럼이 그대로 응답에 흐른다.

DEK 캐싱(한 row 당 한 번 unwrap) 도 함께 검증해, 컬럼 3개를 decrypt 해도 KEK 호출
횟수가 1회로 유지되는지 확인.
"""

from __future__ import annotations

import base64
import os
import platform as _platform
import sys as _sys
import types as _types

# Settings 가 import 시점에 모든 필수 필드(JWT_*, KEK, HMAC) 를 강제하므로 더미 주입.
# .env 가 있으면 setdefault 가 no-op — 그쪽 값을 그대로 쓴다.
os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x07" * 32).decode())
os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x08" * 32).decode())
os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")

# Windows 에선 libmagic 로딩이 segfault 를 유발하므로 stub. CI(Linux) 에선 절대
# 가리지 말 것 — 실제 magic.from_buffer sniff 결과로 MIME 검증을 하는 다른 테스트
# (test_photos_validate_upload 등) 가 회귀.
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

from app.api.residents import apply_pii_decryption, _apply_pii_encryption  # noqa: E402
from app.core import crypto  # noqa: E402
from app.core.crypto import encrypt_field, generate_dek, wrap_dek  # noqa: E402
from app.models.models import Resident  # noqa: E402


def _make_resident(**overrides) -> Resident:
    """T-003-5b 후 모델은 평문 PII 컬럼을 갖지 않는다 — ct/dek/blind_idx 만."""
    r = Resident(
        id="r1",
        facility_id="f1",
        code="RES-AAA",
        gender=None,
        room_number=None,
        name_ct=None,
        name_blind_idx=None,
        birth_date_ct=None,
        medical_notes_ct=None,
        dek_wrapped=None,
        is_active=True,
    )
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


def test_decrypt_no_dek_sets_plaintext_attrs_to_none():
    """백필 누락 row 안전망 — dek_wrapped 가 None 이면 평문 attribute 를 None 으로 set.

    T-003-5b 단계에선 평문 컬럼 자체가 drop 됐으므로 fallback 으로 가져올 평문이
    없다. 응답에 stale leftover 가 새지 않도록 명시적으로 None.
    """
    r = _make_resident()
    apply_pii_decryption(r)
    assert r.name is None
    assert r.birth_date is None
    assert r.medical_notes is None


def test_decrypt_returns_ct_value_via_instance_attribute():
    """ct 가 있으면 decrypt 결과가 instance attribute 로 set 되고 응답에 흐른다."""
    r = _make_resident()
    _apply_pii_encryption(r, name="ct_value")
    apply_pii_decryption(r)
    assert r.name == "ct_value"


def test_decrypt_partial_ct_unset_columns_become_none():
    """일부 컬럼만 ct 가 있는 row — 있는 컬럼은 decrypt, 없는 컬럼은 None."""
    dek = generate_dek()
    r = _make_resident(
        dek_wrapped=wrap_dek(dek),
        name_ct=encrypt_field("순자", dek),
        birth_date_ct=None,
        medical_notes_ct=None,
    )
    apply_pii_decryption(r)
    assert r.name == "순자"
    assert r.birth_date is None
    assert r.medical_notes is None


def test_decrypt_unwraps_dek_once_per_row(monkeypatch):
    """row 당 KEK unwrap 은 1회 — 컬럼 3개를 decrypt 해도 unwrap 호출은 1번."""
    calls = {"n": 0}
    real_unwrap = crypto.unwrap_dek

    def counting_unwrap(blob: bytes) -> bytes:
        calls["n"] += 1
        return real_unwrap(blob)

    # residents 모듈이 import 시점에 unwrap_dek 을 바인딩했으므로 거기를 패치.
    from app.api import residents as residents_mod

    monkeypatch.setattr(residents_mod, "unwrap_dek", counting_unwrap)

    r = _make_resident()
    _apply_pii_encryption(
        r,
        name="홍길동",
        birth_date="1940-03-15",
        medical_notes="고혈압",
    )
    # encrypt 도 unwrap 을 1회 쓰므로, decrypt 직전에 카운터를 0으로 리셋.
    calls["n"] = 0

    apply_pii_decryption(r)
    assert calls["n"] == 1
    assert r.name == "홍길동"
    assert r.birth_date == "1940-03-15"
    assert r.medical_notes == "고혈압"


def test_encrypt_populates_ct_columns():
    """write helper 는 ct / dek / blind_idx 컬럼만 채운다.

    T-003-5b 단계에선 모델에 평문 컬럼 자체가 없으므로 helper 가 자동으로
    ct-only 동작 — 검증은 ct/dek/blind_idx 가 채워졌는지로 충분.
    """
    r = _make_resident()
    _apply_pii_encryption(
        r,
        name="홍길동",
        birth_date="1940-03-15",
        medical_notes="고혈압",
    )

    assert r.dek_wrapped is not None
    assert r.name_ct is not None
    assert r.name_blind_idx is not None
    assert r.birth_date_ct is not None
    assert r.medical_notes_ct is not None


def test_encrypt_partial_update_preserves_other_ct_columns():
    """PUT 부분 갱신 — 일부 필드만 인자로 주면 나머지 ct 는 그대로 보존."""
    dek = generate_dek()
    wrapped = wrap_dek(dek)
    original_name_ct = encrypt_field("이전이름", dek)
    original_birth_ct = encrypt_field("1940-01-01", dek)

    r = _make_resident(
        dek_wrapped=wrapped,
        name_ct=original_name_ct,
        birth_date_ct=original_birth_ct,
        medical_notes_ct=None,
    )

    # name 만 갱신
    _apply_pii_encryption(r, name="새이름")

    assert r.name_ct != original_name_ct  # name 은 새 ct
    assert r.birth_date_ct == original_birth_ct  # birth_date 는 보존
    assert r.medical_notes_ct is None  # 손대지 않음


# T-003-5b: ORM dirty flag 검증 테스트 (set_committed_value 패턴) 는 더 이상
# 의미 없음 — 평문 컬럼이 drop 되어 mapped attribute 가 사라졌으므로 dirty 발생
# 기반 자체가 없다. apply_pii_decryption 은 일반 setattr 로 instance attribute
# 를 set, ORM 추적 대상 아님.
