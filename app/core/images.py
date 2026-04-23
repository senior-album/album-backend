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
