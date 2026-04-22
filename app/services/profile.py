"""
프로필 업데이트 헬퍼. 전화번호가 실제로 바뀌면 이전 OTP 인증을 무효화 —
시설 연결 요청 같은 게이트 로직이 이전 인증으로 우회되는 걸 차단.
"""

from typing import Optional

from app.services.phone_otp import normalize_phone


def apply_profile_update(user, *, name: Optional[str] = None, phone: Optional[str] = None) -> None:
    """
    user 를 제자리(in-place)에서 수정. DB 커밋은 호출자 책임.
    - name 이 주어지면 그대로 세팅
    - phone 이 주어지면 기존과 정규화 비교해 다르면 phone_verified_at = None 리셋 후 저장
    """
    if name is not None:
        user.name = name
    if phone is not None:
        if normalize_phone(user.phone or "") != normalize_phone(phone):
            user.phone_verified_at = None
        user.phone = phone
