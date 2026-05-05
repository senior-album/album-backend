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

from sqlalchemy.orm.attributes import set_committed_value  # noqa: E402

from app.api.residents import apply_pii_decryption, _apply_pii_encryption  # noqa: E402
from app.core import crypto  # noqa: E402
from app.core.crypto import encrypt_field, generate_dek, wrap_dek  # noqa: E402
from app.models.models import Resident  # noqa: E402


def _make_resident(**overrides) -> Resident:
    r = Resident(
        id="r1",
        facility_id="f1",
        code="RES-AAA",
        name=None,
        birth_date=None,
        gender=None,
        room_number=None,
        medical_notes=None,
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


def test_decrypt_noop_when_dek_missing():
    """백필 전 row — dek_wrapped 가 None 이면 평문 컬럼이 그대로 응답에 흐른다."""
    r = _make_resident(name="홍길동", birth_date="1940-03-15", medical_notes="고혈압")
    apply_pii_decryption(r)
    assert r.name == "홍길동"
    assert r.birth_date == "1940-03-15"
    assert r.medical_notes == "고혈압"


def test_decrypt_overrides_plaintext_with_ct_value():
    """dual-write row — ct 값이 평문 컬럼을 덮어쓴다.

    plaintext 와 ct 가 의도적으로 다른 값을 갖도록 만들어, 응답이 단순히 plaintext
    fallback 이 아니라 ct 경로로 흐르는지 확인. 평문 fallback 만 작동하면 이 테스트가
    실패한다.
    """
    r = _make_resident()
    _apply_pii_encryption(r, name="ct_value")  # name_ct 에 "ct_value" 의 ciphertext 박힘
    r.name = "stale_plaintext"  # plaintext 만 다른 값으로 바꿔치기
    apply_pii_decryption(r)
    assert r.name == "ct_value"


def test_decrypt_partial_ct_leaves_other_columns_untouched():
    """일부 컬럼만 ct 가 있는 row — 그 컬럼만 decrypt, 나머지는 plaintext 유지."""
    dek = generate_dek()
    r = _make_resident(
        name="placeholder",
        birth_date="1945",
        medical_notes=None,
        dek_wrapped=wrap_dek(dek),
        name_ct=encrypt_field("순자", dek),
        birth_date_ct=None,
        medical_notes_ct=None,
    )
    apply_pii_decryption(r)
    assert r.name == "순자"
    assert r.birth_date == "1945"  # ct 없음 → plaintext 그대로
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


def test_encrypt_does_not_write_plaintext_columns():
    """T-003-5a: write 가 평문 컬럼을 더 이상 set 하지 않는다.

    helper 시그니처가 input 평문을 인자로 받게 바뀌면서, 모델 컬럼의 평문 attribute
    (`resident.name` 등) 는 만지지 않고 ct / dek / blind_idx 만 채워야 한다. 평문
    set 이 다시 새어나오면 신규 row 에 평문이 디스크에 남게 되어 PII 보호가 깨진다.
    """
    r = _make_resident()
    _apply_pii_encryption(
        r,
        name="홍길동",
        birth_date="1940-03-15",
        medical_notes="고혈압",
    )

    # 평문 컬럼은 입력 후에도 None 그대로
    assert r.name is None
    assert r.birth_date is None
    assert r.medical_notes is None
    # ct / dek / blind_idx 는 채워짐
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


def test_decrypt_does_not_dirty_orm_state():
    """`set_committed_value` 사용 — decrypt 가 ORM dirty flag 를 세우면 안 됨.

    decrypt 가 평문 attribute 를 set 하면서 SQLAlchemy 가 그 컬럼을 dirty 로 인식하면
    뒤따르는 commit 에서 의도치 않게 평문 컬럼이 재기록된다. read 경로의 부수 효과를
    피하기 위해 dirty 가 안 서야 한다.

    "DB 에서 막 로딩된 row" 상태를 흉내내려고 ct/dek/평문 모두 `set_committed_value`
    로 초기화 — 이러면 history 에 변화 없음. 그 위에서 `apply_pii_decryption` 을
    돌려, decrypt 후에도 평문 컬럼들의 history 가 그대로 비어있어야 한다.
    """
    from sqlalchemy import inspect

    dek = generate_dek()
    wrapped = wrap_dek(dek)
    name_ct = encrypt_field("ct_value", dek)

    r = Resident(
        id="r2",
        facility_id="f1",
        code="RES-BBB",
        gender=None,
        room_number=None,
        is_active=True,
    )
    state = inspect(r)
    # DB load 시뮬레이션 — 로드된 컬럼은 history 비어있음.
    set_committed_value(r, "dek_wrapped", wrapped)
    set_committed_value(r, "name_ct", name_ct)
    set_committed_value(r, "birth_date_ct", None)
    set_committed_value(r, "medical_notes_ct", None)
    set_committed_value(r, "name", "stale_plaintext")
    set_committed_value(r, "birth_date", None)
    set_committed_value(r, "medical_notes", None)

    # baseline — decrypt 전엔 평문 컬럼에 history 변화 없음
    assert not state.attrs.name.history.has_changes()

    apply_pii_decryption(r)

    assert r.name == "ct_value"
    # decrypt 후에도 평문 컬럼에 ORM-level dirty flag 가 서면 안 됨.
    for col in ("name", "birth_date", "medical_notes"):
        assert not state.attrs[col].history.has_changes(), (
            f"apply_pii_decryption 이 '{col}' 을 dirty 로 만들었음 — "
            "set_committed_value 가 아닌 일반 setattr 사용 의심"
        )
