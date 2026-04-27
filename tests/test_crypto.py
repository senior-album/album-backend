"""T-003 envelope encryption — crypto.py 단위 테스트.

KEK / HMAC 키를 모듈 import 전에 환경변수로 박아둠. 로컬 .env 에 값이 이미
있으면 setdefault 가 무시 — 어느 쪽이든 32바이트 base64 면 OK.
"""

import base64
import os

# `app.core.crypto` 가 import 되는 순간 Settings 가 평가됨 — 그 전에 셋업.
os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x01" * 32).decode())
os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x02" * 32).decode())

import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import (
    blind_index,
    decrypt_field,
    encrypt_field,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)


def test_dek_round_trip():
    dek = generate_dek()
    assert len(dek) == 32
    wrapped = wrap_dek(dek)
    assert unwrap_dek(wrapped) == dek


def test_field_encrypt_round_trip_korean():
    dek = generate_dek()
    plaintext = "홍길동"
    ct = encrypt_field(plaintext, dek)
    assert ct != plaintext.encode("utf-8")
    assert decrypt_field(ct, dek) == plaintext


def test_encrypt_nonce_is_random():
    dek = generate_dek()
    ct1 = encrypt_field("John", dek)
    ct2 = encrypt_field("John", dek)
    assert ct1 != ct2  # AES-GCM semantic security — 같은 평문도 매번 다른 ciphertext


def test_wrap_dek_nonce_is_random():
    dek = generate_dek()
    assert wrap_dek(dek) != wrap_dek(dek)


def test_blind_index_deterministic_and_fixed_size():
    a = blind_index("홍길동")
    assert a == blind_index("홍길동")
    assert len(a) == 32  # SHA-256 출력 크기


def test_blind_index_distinguishes_values():
    assert blind_index("홍길동") != blind_index("홍길순")


def test_wrong_dek_fails_with_tag_error():
    """DEK 가 틀리면 AES-GCM 이 InvalidTag — 무결성 보장 확인."""
    ct = encrypt_field("secret", generate_dek())
    with pytest.raises(InvalidTag):
        decrypt_field(ct, generate_dek())
