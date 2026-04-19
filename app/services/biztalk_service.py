"""
카카오 비즈톡 (알림톡) 서비스
보호자 초대, 새 사진 알림 등을 카카오톡으로 발송

비즈톡 연동 시 필요한 것:
1. 카카오 비즈니스 채널 생성 (카카오톡 채널 관리자센터)
2. 비즈메시지 발송 대행사 계약 (NHN Cloud, 인포뱅크 등)
3. 알림톡 템플릿 등록 및 검수 승인

현재는 대행사 API 호출 구조만 준비해두고,
실제 발송은 대행사 연동 후 활성화
"""

import logging
from typing import Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class BizTalkService:
    """카카오 알림톡 발송 서비스"""

    @classmethod
    def is_configured(cls) -> bool:
        """비즈톡이 설정되어 있는지 확인"""
        settings = get_settings()
        return bool(settings.BIZZTALK_SENDER_KEY)

    @classmethod
    async def send_invitation_notification(
        cls,
        phone: str,
        facility_name: str,
        resident_name: str,
        inviter_name: str,
        message: Optional[str] = None,
    ) -> bool:
        """
        보호자 초대 알림톡 발송

        템플릿 예시:
        ---
        [Senior Album] 보호자 초대

        #{시설명}에서 #{입소자명}님의 보호자로 초대하셨습니다.

        초대자: #{초대자명}
        #{메시지}

        앱에서 초대를 확인해주세요.
        ---
        """
        settings = get_settings()

        if not cls.is_configured():
            logger.info(
                f"BizTalk not configured. Would send invite to {phone}: "
                f"facility={facility_name}, resident={resident_name}"
            )
            return False

        template_params = {
            "시설명": facility_name,
            "입소자명": resident_name,
            "초대자명": inviter_name,
            "메시지": message or "",
        }

        return await cls._send_alimtalk(
            phone=phone,
            template_code=settings.BIZZTALK_TEMPLATE_CODE_INVITE,
            template_params=template_params,
        )

    @classmethod
    async def send_new_photo_notification(
        cls,
        phone: str,
        facility_name: str,
        resident_name: str,
        photo_count: int = 1,
    ) -> bool:
        """
        새 사진 업로드 알림톡 발송

        템플릿 예시:
        ---
        [Senior Album] 새 사진 알림

        #{시설명}에서 #{입소자명}님의 새 사진 #{사진수}장이 업로드되었습니다.

        앱에서 확인해주세요.
        ---
        """
        settings = get_settings()

        if not cls.is_configured():
            logger.info(
                f"BizTalk not configured. Would send photo alert to {phone}: "
                f"facility={facility_name}, resident={resident_name}, count={photo_count}"
            )
            return False

        template_params = {
            "시설명": facility_name,
            "입소자명": resident_name,
            "사진수": str(photo_count),
        }

        return await cls._send_alimtalk(
            phone=phone,
            template_code=settings.BIZZTALK_TEMPLATE_CODE_PHOTO,
            template_params=template_params,
        )

    @classmethod
    async def _send_alimtalk(
        cls,
        phone: str,
        template_code: str,
        template_params: dict,
    ) -> bool:
        """
        알림톡 실제 발송 (대행사 API 호출)

        대행사별 API 형식이 다르므로,
        여기서는 NHN Cloud Toast 형식으로 예시 구현.
        실제 사용 시 대행사에 맞게 수정 필요.
        """
        settings = get_settings()

        # 전화번호 정규화 (하이픈 제거)
        phone_clean = phone.replace("-", "").replace(" ", "")
        if phone_clean.startswith("0"):
            phone_clean = "82" + phone_clean[1:]

        payload = {
            "senderKey": settings.BIZZTALK_SENDER_KEY,
            "templateCode": template_code,
            "recipientList": [
                {
                    "recipientNo": phone_clean,
                    "templateParameter": template_params,
                }
            ],
        }

        logger.info(f"Sending alimtalk to {phone_clean}: template={template_code}")

        # TODO: 대행사 API URL 및 인증 키 설정 후 실제 호출
        # 지금은 로그만 남기고 성공 반환
        logger.info(f"[MOCK] AlimTalk would be sent: {payload}")
        return True

        # 실제 발송 코드 (대행사 연동 시 주석 해제):
        # try:
        #     async with httpx.AsyncClient() as client:
        #         resp = await client.post(
        #             "https://api-alimtalk.cloud.toast.com/alimtalk/v2.2/appkeys/{APP_KEY}/messages",
        #             json=payload,
        #             headers={"Content-Type": "application/json"},
        #         )
        #     if resp.status_code == 200:
        #         logger.info(f"AlimTalk sent successfully to {phone_clean}")
        #         return True
        #     else:
        #         logger.error(f"AlimTalk failed: {resp.text}")
        #         return False
        # except Exception as e:
        #     logger.error(f"AlimTalk send error: {e}")
        #     return False
