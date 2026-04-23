"""
T-032: 보호자 초대 QR 포스터 PDF 생성.

시설에서 프린트해 어르신 방이나 로비에 붙이는 용도. 보호자가 QR 을 찍으면
프런트엔드의 초대 수락 페이지로 이동하고, 거기서 로그인 후 `accept_invitation`
엔드포인트가 호출된다.

순수 함수 — DB / 요청 없이 입력만 받아 PDF 바이트를 반환한다. 엔드포인트에서
조립해 호출.
"""

from __future__ import annotations

from io import BytesIO
from typing import Optional

import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfgen import canvas


# reportlab 번들의 CID 한글 폰트. PDF 리더가 Adobe Reading System 으로
# 렌더하므로 별도 TTF 번들 없이 한글 출력 가능.
_KOREAN_FONT_NAME = "HYSMyeongJo-Medium"
_FONT_REGISTERED = False


def _ensure_font() -> None:
    global _FONT_REGISTERED
    if not _FONT_REGISTERED:
        pdfmetrics.registerFont(UnicodeCIDFont(_KOREAN_FONT_NAME))
        _FONT_REGISTERED = True


def _qr_image(data: str, box_size: int = 10) -> ImageReader:
    qr = qrcode.QRCode(
        version=None,  # 데이터 길이에 맞게 자동.
        error_correction=qrcode.constants.ERROR_CORRECT_M,  # 25% 복원 — 인쇄 손상 여유.
        box_size=box_size,
        border=2,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return ImageReader(buf)


def build_invitation_poster_pdf(
    *,
    facility_name: str,
    resident_name: str,
    invite_url: str,
    message: Optional[str] = None,
    expires_note: Optional[str] = None,
) -> bytes:
    """
    A4 한 장짜리 초대 포스터 PDF 를 바이트로 반환.

    레이아웃 (위→아래): 제목 → 시설명 → "어르신 {name}" → QR (중앙) →
    단축 URL 텍스트 → 설명/메시지 → 만료 안내.
    """
    _ensure_font()

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    width, height = A4  # 단위 포인트 (1mm = 2.834645pt)

    # ---- 제목 ----
    c.setFont(_KOREAN_FONT_NAME, 28)
    c.drawCentredString(width / 2, height - 30 * mm, "보호자 초대")

    # ---- 시설명 ----
    c.setFont(_KOREAN_FONT_NAME, 22)
    c.drawCentredString(width / 2, height - 50 * mm, facility_name)

    # ---- 어르신 이름 ----
    c.setFont(_KOREAN_FONT_NAME, 18)
    c.drawCentredString(width / 2, height - 68 * mm, f"어르신: {resident_name}")

    # ---- QR (중앙, 정사각) ----
    qr_size = 90 * mm
    qr_x = (width - qr_size) / 2
    qr_y = height - 170 * mm
    c.drawImage(_qr_image(invite_url), qr_x, qr_y, width=qr_size, height=qr_size,
                preserveAspectRatio=True, mask="auto")

    # ---- 안내 문구 ----
    c.setFont(_KOREAN_FONT_NAME, 12)
    c.drawCentredString(width / 2, qr_y - 10 * mm, "스마트폰 카메라로 QR 을 찍어주세요")

    # ---- 단축 URL 텍스트 (QR 인식 실패 시 수동 입력용) ----
    c.setFont("Helvetica", 10)
    c.drawCentredString(width / 2, qr_y - 18 * mm, invite_url)

    # ---- 초대 메시지 (있을 때만) ----
    current_y = qr_y - 35 * mm
    if message:
        c.setFont(_KOREAN_FONT_NAME, 11)
        # 긴 메시지는 줄바꿈 없이 prefix 만 — 포스터는 간결 유지.
        msg_line = (message[:60] + "…") if len(message) > 60 else message
        c.drawCentredString(width / 2, current_y, msg_line)
        current_y -= 8 * mm

    # ---- 만료 안내 ----
    if expires_note:
        c.setFont(_KOREAN_FONT_NAME, 10)
        c.setFillGray(0.3)
        c.drawCentredString(width / 2, current_y, expires_note)
        c.setFillGray(0)

    # ---- 푸터 (서비스명) ----
    c.setFont("Helvetica", 8)
    c.setFillGray(0.5)
    c.drawCentredString(width / 2, 15 * mm, "Senior Album")
    c.setFillGray(0)

    c.showPage()
    c.save()
    return buf.getvalue()
