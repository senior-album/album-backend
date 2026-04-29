"""
이미지 재인코딩 + 메타데이터 제거 유틸 (T-051).

업로드된 이미지에는 EXIF (GPS 좌표, 촬영 시각, 카메라 모델, 방향 등) 같은
메타데이터가 포함돼 있는데, 시설에서 찍힌 사진의 위치·기기 정보는 입소자
프라이버시와 직결되는 민감 정보임. 저장·공유 전에 재인코딩으로 strip.
"""

from io import BytesIO

from PIL import Image as PILImage
from PIL import ImageOps


JPEG_QUALITY = 92
PNG_COMPRESS_LEVEL = 6
THUMBNAIL_SIZE = (300, 300)
THUMBNAIL_QUALITY = 80


def reencode_with_thumbnail(
    data: bytes,
    *,
    prefer_jpeg: bool = True,
) -> tuple[bytes, str, str, bytes | None]:
    """
    PIL.open 1회로 메타 strip 재인코딩 + 섬네일을 함께 만든다.

    `reencode_strip_metadata` + 별도 섬네일 생성 두 단계가 PIL.open 을 두 번
    하는 구조였는데, 같은 이미지를 두 번 디코딩하는 게 사진 1장당 0.3~0.5초
    낭비라 한 번에 처리하도록 합침.

    Returns: (sanitized_bytes, ext, mime, thumbnail_bytes_or_None).
    섬네일 생성 실패 시 thumbnail_bytes 만 None — 호출부는 원본 키로 fallback.
    """
    with PILImage.open(BytesIO(data)) as img:
        img = ImageOps.exif_transpose(img)

        has_alpha = img.mode in ("RGBA", "LA") or (
            img.mode == "P" and "transparency" in img.info
        )

        # 알파 보존 경로 — PNG 로 저장. 이 경우 섬네일은 JPEG 가 아닌 동일 PNG 로 생성.
        if has_alpha and not prefer_jpeg:
            if img.mode != "RGBA":
                img = img.convert("RGBA")
            sanitized_buf = BytesIO()
            img.save(sanitized_buf, format="PNG", optimize=True, compress_level=PNG_COMPRESS_LEVEL)
            sanitized = sanitized_buf.getvalue()

            try:
                thumb_img = img.copy()
                thumb_img.thumbnail(THUMBNAIL_SIZE)
                thumb_buf = BytesIO()
                thumb_img.save(thumb_buf, format="PNG", optimize=True)
                thumb = thumb_buf.getvalue()
            except Exception:
                thumb = None

            return sanitized, "png", "image/png", thumb

        # 기본 경로 — JPEG 통일. 알파 있으면 흰 배경 합성.
        if has_alpha:
            background = PILImage.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])
            img = background
        elif img.mode != "RGB":
            img = img.convert("RGB")

        sanitized_buf = BytesIO()
        img.save(
            sanitized_buf,
            format="JPEG",
            quality=JPEG_QUALITY,
            optimize=True,
            progressive=True,
        )
        sanitized = sanitized_buf.getvalue()

        # 섬네일 — 같은 디코딩된 이미지에서 copy 후 thumbnail.
        try:
            thumb_img = img.copy()
            thumb_img.thumbnail(THUMBNAIL_SIZE)
            thumb_buf = BytesIO()
            thumb_img.save(thumb_buf, format="JPEG", quality=THUMBNAIL_QUALITY)
            thumb = thumb_buf.getvalue()
        except Exception:
            thumb = None

        return sanitized, "jpg", "image/jpeg", thumb


def reencode_strip_metadata(
    data: bytes,
    *,
    prefer_jpeg: bool = True,
) -> tuple[bytes, str, str]:
    """
    원본 바이트를 재인코딩해 EXIF/기타 메타데이터를 제거한다.

    Args:
        data: 원본 이미지 바이트
        prefer_jpeg: True 면 투명도가 없는 이미지는 JPEG 로 통일. 투명도가 있는
            PNG/WebP 는 알파 보존을 위해 PNG 로 유지. False 면 원본 포맷 유지.

    Returns:
        (new_bytes, new_ext, new_content_type). ext 는 선행 점 없이 ("jpg" / "png").

    Raises:
        PIL.UnidentifiedImageError 등 — 호출 측에서 이미 `_validate_upload` 로
        디코딩 확인을 마쳤으므로 여기서 발생하면 진짜 예외.
    """
    with PILImage.open(BytesIO(data)) as img:
        # EXIF Orientation 태그를 실제 픽셀 회전으로 반영해두고 태그 자체는 drop.
        # (회전 의도가 메타데이터가 아니라 픽셀 방향에 남게 됨)
        img = ImageOps.exif_transpose(img)

        has_alpha = img.mode in ("RGBA", "LA") or (
            img.mode == "P" and "transparency" in img.info
        )

        out = BytesIO()
        if has_alpha and not prefer_jpeg:
            # 드문 케이스 — PNG 로 알파 보존 + 메타 제거
            if img.mode != "RGBA":
                img = img.convert("RGBA")
            img.save(out, format="PNG", optimize=True, compress_level=PNG_COMPRESS_LEVEL)
            return out.getvalue(), "png", "image/png"

        # 기본 경로: JPEG 로 통일. 알파가 있으면 흰 배경에 합성.
        if has_alpha:
            background = PILImage.new("RGB", img.size, (255, 255, 255))
            background.paste(img, mask=img.split()[-1])
            img = background
        elif img.mode != "RGB":
            img = img.convert("RGB")

        img.save(
            out,
            format="JPEG",
            quality=JPEG_QUALITY,
            optimize=True,
            progressive=True,
        )
        return out.getvalue(), "jpg", "image/jpeg"
