"""
T-003 envelope encryption — Resident PII at-rest 암호화.

설계:
- KEK (Key Encryption Key) 는 SealedSecret 에 1개. KEK 는 DEK 를 wrap 만 함.
- DEK (Data Encryption Key) 는 row 당 1개. DEK 가 실제 PII 컬럼을 암호화.
- KEK rotation 시 모든 row 의 wrapped DEK 만 재-wrap 하면 됨 (PII 컬럼 재암호화 X).
- Blind index 는 HMAC-SHA256(NAME_HMAC_KEY, value) — 결정적이라 동등 검색 가능.

컬럼 레이아웃 (모두 BYTEA):
- `*_ct` = nonce(12B) || AESGCM(dek).encrypt(plaintext_utf8)         — ct 에 16B tag 포함
- `dek_wrapped` = nonce(12B) || AESGCM(KEK).encrypt(dek)              — wrapped 32B + 16B tag
- `name_blind_idx` = HMAC-SHA256(NAME_HMAC_KEY, name_utf8)           — 32B 고정

키 디코딩은 lazy + cached. Settings 는 base64 문자열만 들고 있고, 첫 호출 시
디코드 → 길이 검증 → cache. 잘못된 키는 첫 사용 시점에 ValueError.
"""

from __future__ import annotations

import base64
import hmac
import os
from functools import lru_cache
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings


_NONCE_LEN = 12  # AES-GCM 권장 nonce 크기
_KEY_LEN = 32  # AES-256 / HMAC-SHA256 키 크기


@lru_cache(maxsize=1)
def _kek() -> bytes:
    raw = base64.b64decode(get_settings().RESIDENT_PII_KEK)
    if len(raw) != _KEY_LEN:
        raise ValueError(f"RESIDENT_PII_KEK 디코드 후 {_KEY_LEN}바이트가 아님 ({len(raw)})")
    return raw


@lru_cache(maxsize=1)
def _hmac_key() -> bytes:
    raw = base64.b64decode(get_settings().RESIDENT_NAME_HMAC_KEY)
    if len(raw) != _KEY_LEN:
        raise ValueError(f"RESIDENT_NAME_HMAC_KEY 디코드 후 {_KEY_LEN}바이트가 아님 ({len(raw)})")
    return raw


def generate_dek() -> bytes:
    return os.urandom(_KEY_LEN)


def wrap_dek(dek: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(_kek()).encrypt(nonce, dek, None)


def unwrap_dek(blob: bytes) -> bytes:
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(_kek()).decrypt(nonce, ct, None)


def encrypt_field(plaintext: str, dek: bytes) -> bytes:
    nonce = os.urandom(_NONCE_LEN)
    return nonce + AESGCM(dek).encrypt(nonce, plaintext.encode("utf-8"), None)


def decrypt_field(blob: bytes, dek: bytes) -> str:
    nonce, ct = blob[:_NONCE_LEN], blob[_NONCE_LEN:]
    return AESGCM(dek).decrypt(nonce, ct, None).decode("utf-8")


def blind_index(value: str) -> bytes:
    return hmac.new(_hmac_key(), value.encode("utf-8"), sha256).digest()
