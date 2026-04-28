"""
T-124 PR3: app.api.photos 의 업로드 진입 헬퍼 단위 테스트.

`_validate_upload` 의 4단계 검증 (크기 / 확장자 / MIME magic / Pillow 디코딩) 과
`_enforce_rate_limit` (Redis 래퍼) 의 분기를 채운다. 실제 업로드 엔드포인트
(`upload_photos`) 통합 테스트는 multipart 시뮬레이션이 부피가 커서 후속 PR.
"""

from __future__ import annotations

from io import BytesIO

import pytest
from fastapi import HTTPException
from PIL import Image as PILImage

from app.api import photos as photos_module
from app.api.photos import (
    ALLOWED_EXT,
    ALLOWED_MIME,
    MAX_UPLOAD_SIZE,
    _enforce_rate_limit,
    _validate_upload,
)


def _make_jpeg_bytes(size=(64, 64), color=(160, 80, 40)) -> bytes:
    buf = BytesIO()
    PILImage.new("RGB", size, color=color).save(buf, format="JPEG", quality=85)
    return buf.getvalue()


def _make_png_bytes(size=(32, 32)) -> bytes:
    buf = BytesIO()
    PILImage.new("RGB", size, color=(0, 0, 255)).save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# _validate_upload — 정상 입력
# ---------------------------------------------------------------------------


def test_validate_upload_accepts_jpeg():
    data = _make_jpeg_bytes()
    ext, mime = _validate_upload("photo.jpg", data)
    assert ext == ".jpg"
    assert mime == "image/jpeg"


def test_validate_upload_accepts_jpeg_with_uppercase_extension():
    data = _make_jpeg_bytes()
    ext, _ = _validate_upload("PHOTO.JPG", data)
    assert ext == ".jpg"  # 소문자로 정규화


def test_validate_upload_accepts_png():
    data = _make_png_bytes()
    ext, mime = _validate_upload("photo.png", data)
    assert ext == ".png"
    assert mime == "image/png"


def test_validate_upload_accepts_jpeg_extension_alias():
    data = _make_jpeg_bytes()
    ext, _ = _validate_upload("photo.jpeg", data)
    assert ext == ".jpeg"


# ---------------------------------------------------------------------------
# _validate_upload — 거부 분기
# ---------------------------------------------------------------------------


def test_validate_upload_rejects_oversize():
    """크기 검증이 가장 먼저 — 다른 검증보다 앞서 413 으로 거절."""
    too_big = b"\xff" * (MAX_UPLOAD_SIZE + 1)
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo.jpg", too_big)
    assert exc.value.status_code == 413
    assert "최대" in exc.value.detail


def test_validate_upload_rejects_disallowed_extension():
    data = _make_jpeg_bytes()
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo.gif", data)
    assert exc.value.status_code == 415
    assert "허용되지 않는 확장자" in exc.value.detail


def test_validate_upload_rejects_no_extension():
    data = _make_jpeg_bytes()
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo", data)
    assert exc.value.status_code == 415


def test_validate_upload_allows_extension_mime_mismatch_within_whitelist():
    """파일명은 .jpg 인데 실제 magic bytes 가 PNG — 둘 다 화이트리스트라 현재 명세는
    통과시킨다. 향후 strict 매칭으로 바꾸면 이 테스트가 회귀 알람."""
    png_data = _make_png_bytes()
    ext, mime = _validate_upload("photo.jpg", png_data)
    assert ext == ".jpg"  # 사용자가 선언한 확장자 그대로 반환
    assert mime == "image/png"  # 실제 sniff 한 MIME


def test_validate_upload_rejects_non_image_payload_with_image_extension():
    """확장자만 .jpg 이고 내용은 그냥 바이너리 → magic sniff 단계에서 거절."""
    payload = b"NOT-AN-IMAGE-AT-ALL\x00\x01\x02" * 8
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo.jpg", payload)
    assert exc.value.status_code == 415
    assert "허용되지 않는 파일 타입" in exc.value.detail


def test_validate_upload_rejects_corrupted_image(monkeypatch):
    """magic sniff 는 통과하지만 Pillow 가 디코딩 못 하면 422."""
    # magic 이 'image/jpeg' 라고 거짓말하도록 stub.
    monkeypatch.setattr(
        photos_module.magic,
        "from_buffer",
        lambda buf, mime=False: "image/jpeg" if mime else "JPEG image",
    )
    bad_jpeg = b"\xff\xd8\xff\xe0not actually a valid image"
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo.jpg", bad_jpeg)
    assert exc.value.status_code == 422
    assert "유효하지 않은 이미지" in exc.value.detail


def test_validate_upload_treats_magic_failure_as_unknown_mime(monkeypatch):
    """python-magic 자체가 예외를 던지면 sniffed=None 으로 떨어져 415 처리."""

    def _boom(*_a, **_k):
        raise RuntimeError("libmagic dead")

    monkeypatch.setattr(photos_module.magic, "from_buffer", _boom)
    data = _make_jpeg_bytes()
    with pytest.raises(HTTPException) as exc:
        _validate_upload("photo.jpg", data)
    assert exc.value.status_code == 415


def test_validate_upload_allowed_sets_are_consistent():
    """ALLOWED_EXT 와 ALLOWED_MIME 사이에 가장 흔한 매핑이 빠지지 않았는지 sanity."""
    assert ".jpg" in ALLOWED_EXT and ".jpeg" in ALLOWED_EXT
    assert ".png" in ALLOWED_EXT
    assert "image/jpeg" in ALLOWED_MIME and "image/png" in ALLOWED_MIME


# ---------------------------------------------------------------------------
# _enforce_rate_limit — Redis 래퍼
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enforce_rate_limit_passes_when_not_blocked(monkeypatch):
    captured = {}

    async def _fake_check(key, max_count, window):
        captured.update({"key": key, "max": max_count, "window": window})
        return False, None

    monkeypatch.setattr(photos_module, "check_rate_limit", _fake_check)
    await _enforce_rate_limit("upload:user-1", 100)
    assert captured == {"key": "upload:user-1", "max": 100, "window": 60}


@pytest.mark.asyncio
async def test_enforce_rate_limit_raises_429_with_retry_after(monkeypatch):
    async def _fake_check(*_a, **_k):
        return True, 42

    monkeypatch.setattr(photos_module, "check_rate_limit", _fake_check)
    with pytest.raises(HTTPException) as exc:
        await _enforce_rate_limit("upload:user-2", 100)
    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "42"


@pytest.mark.asyncio
async def test_enforce_rate_limit_falls_back_to_60_when_no_retry_hint(monkeypatch):
    """Redis 가 retry_after 를 못 주는 fallback 경로 — Retry-After: 60 디폴트."""

    async def _fake_check(*_a, **_k):
        return True, None

    monkeypatch.setattr(photos_module, "check_rate_limit", _fake_check)
    with pytest.raises(HTTPException) as exc:
        await _enforce_rate_limit("upload:user-3", 100)
    assert exc.value.headers["Retry-After"] == "60"
