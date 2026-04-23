"""
T-032: 초대 포스터 PDF 생성 단위 테스트.

엔드포인트 통합 테스트는 reportlab / qrcode 설치가 필요해 conftest 에 묶여
있어, 여기선 순수 함수만 검증. 엔드포인트는 Docker / CI 환경에서 실 실행.
"""

import pytest

from app.services.poster import build_invitation_poster_pdf


def test_pdf_magic_bytes():
    pdf = build_invitation_poster_pdf(
        facility_name="햇살요양원",
        resident_name="홍길동",
        invite_url="https://example.invalid/invitations/abc",
    )
    assert pdf.startswith(b"%PDF-"), "생성물이 PDF 가 아님"
    assert len(pdf) > 1000, "PDF 가 비정상적으로 작음"


def test_pdf_has_qr_image_stream():
    pdf = build_invitation_poster_pdf(
        facility_name="햇살요양원",
        resident_name="홍길동",
        invite_url="https://example.invalid/invitations/abc",
    )
    # reportlab 은 이미지를 PNG/Flate 로 임베드 — /Image 리소스 태그가 있어야 함.
    assert b"/Subtype /Image" in pdf or b"/Subtype/Image" in pdf


def test_optional_message_and_expiry():
    pdf = build_invitation_poster_pdf(
        facility_name="햇살요양원",
        resident_name="홍길동",
        invite_url="https://x.io/inv/1",
        message="가족 행사 준비 함께 해주세요",
        expires_note="초대는 2026-05-15 까지 유효합니다",
    )
    assert pdf.startswith(b"%PDF-")


def test_long_message_truncated_safely():
    long_msg = "가" * 200  # 200자 한글
    pdf = build_invitation_poster_pdf(
        facility_name="A",
        resident_name="B",
        invite_url="https://x.io/inv/1",
        message=long_msg,
    )
    # 너무 길어도 크래시 없이 렌더 — 실제 포스터는 앞 60자 + '…' 만 들어간다.
    assert pdf.startswith(b"%PDF-")
