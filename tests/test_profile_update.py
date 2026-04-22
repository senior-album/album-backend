"""
apply_profile_update 단위 테스트 — 전화번호 변경 시 phone_verified_at 리셋 규칙 검증.
"""

from datetime import datetime
from types import SimpleNamespace

from app.services.profile import apply_profile_update


def _user(phone=None, verified_at=None, name="A"):
    return SimpleNamespace(name=name, phone=phone, phone_verified_at=verified_at)


def test_same_phone_keeps_verified_at():
    ts = datetime(2026, 4, 22, 10, 0)
    u = _user(phone="01012345678", verified_at=ts)
    apply_profile_update(u, phone="01012345678")
    assert u.phone_verified_at == ts


def test_normalized_equal_keeps_verified_at():
    """하이픈·공백만 다른 같은 번호는 변경으로 보지 않음"""
    ts = datetime(2026, 4, 22, 10, 0)
    u = _user(phone="010-1234-5678", verified_at=ts)
    apply_profile_update(u, phone="01012345678")
    assert u.phone_verified_at == ts
    assert u.phone == "01012345678"  # 새 값으로 저장됨


def test_different_phone_resets_verified_at():
    ts = datetime(2026, 4, 22, 10, 0)
    u = _user(phone="01012345678", verified_at=ts)
    apply_profile_update(u, phone="01099998888")
    assert u.phone_verified_at is None
    assert u.phone == "01099998888"


def test_first_time_phone_set_leaves_verified_none():
    """기존 phone 이 None 이었을 때도 새 번호는 아직 인증 전"""
    u = _user(phone=None, verified_at=None)
    apply_profile_update(u, phone="01012345678")
    assert u.phone == "01012345678"
    assert u.phone_verified_at is None


def test_name_only_update_leaves_phone_fields_untouched():
    ts = datetime(2026, 4, 22, 10, 0)
    u = _user(phone="01012345678", verified_at=ts, name="Old")
    apply_profile_update(u, name="New")
    assert u.name == "New"
    assert u.phone == "01012345678"
    assert u.phone_verified_at == ts


def test_no_args_is_noop():
    ts = datetime(2026, 4, 22, 10, 0)
    u = _user(phone="01012345678", verified_at=ts, name="A")
    apply_profile_update(u)
    assert u.name == "A"
    assert u.phone == "01012345678"
    assert u.phone_verified_at == ts
