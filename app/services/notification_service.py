"""
알림 서비스
푸시 알림 및 카카오 알림톡 전송
"""

import logging
import uuid
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import get_settings
from app.models.models import Notification, User

logger = logging.getLogger(__name__)


class NotificationService:
    """알림 전송 서비스"""

    def __init__(self):
        """서비스 초기화"""
        self.settings = get_settings()

    async def send_push_notification(
        self,
        guardian_id: str,
        title: str,
        message: str,
        photo_id: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> bool:
        """
        푸시 알림 전송

        Args:
            guardian_id: 보호자 ID
            title: 알림 제목
            message: 알림 메시지
            photo_id: 연관된 사진 ID (선택)
            db: 데이터베이스 세션

        Returns:
            성공 여부
        """
        try:
            # 사용자 정보 조회
            if db:
                stmt = select(User).filter(User.id == guardian_id)
                result = await db.execute(stmt)
                user = result.scalar_one_or_none()

                if not user or not user.push_token:
                    logger.warning(f"Push token not found for user {guardian_id}")
                    return False

                # 알림 설정 확인
                if not user.notification_enabled:
                    logger.debug(f"Notifications disabled for user {guardian_id}")
                    return False

                push_token = user.push_token
            else:
                push_token = None

            # 알림 레코드 저장
            if db:
                notification = Notification(
                    id=str(uuid.uuid4()),
                    user_id=guardian_id,
                    photo_id=photo_id,
                    title=title,
                    message=message,
                    notification_type="photo_shared",
                    is_read=False,
                    is_sent=False,
                )
                db.add(notification)

            # 실제 푸시 알림 전송 (스텁)
            logger.info(f"Sending push notification to {guardian_id}: {title}")

            if push_token:
                # Firebase Cloud Messaging 사용 예시 (구현 필요)
                # result = send_fcm_notification(push_token, title, message)
                pass

            if db:
                notification.is_sent = True
                await db.commit()

            return True

        except Exception as e:
            logger.error(f"Push notification failed: {e}")
            return False

    async def send_kakao_alimtalk(
        self,
        phone_number: str,
        template_id: str,
        template_data: dict,
    ) -> bool:
        """
        카카오 알림톡 전송 (스텁)

        Args:
            phone_number: 수신자 전화번호
            template_id: 템플릿 ID
            template_data: 템플릿 데이터

        Returns:
            성공 여부
        """
        try:
            logger.info(f"Sending Kakao AlimTalk to {phone_number}")

            # 카카오 비즈니스 API 호출 (구현 필요)
            # 예시: kakao_business_api.send_alimtalk(...)

            logger.info(f"Kakao AlimTalk sent to {phone_number}")
            return True

        except Exception as e:
            logger.error(f"Kakao AlimTalk failed: {e}")
            return False

    async def send_email_notification(
        self,
        email: str,
        subject: str,
        body: str,
    ) -> bool:
        """T-305: 이메일 발송. EMAIL_PROVIDER=log (기본) 시 로그만, brevo 시 실제 발송.

        body 는 plain text 또는 HTML 모두 허용. HTML 태그가 포함되면 그대로
        htmlContent 로 전달, 없으면 textContent 로 전달.
        """
        try:
            from app.services.email import get_email_provider

            is_html = "<" in body and ">" in body
            html = body if is_html else f"<pre>{body}</pre>"
            text = None if is_html else body
            await get_email_provider().send(to=email, subject=subject, html=html, text=text)
            return True
        except Exception as e:
            logger.error(f"Email notification failed: {e}")
            return False

    async def notify_guardians_of_new_photo(
        self,
        resident_id: str,
        photo_id: str,
        db: AsyncSession,
    ) -> int:
        """
        입소자의 새로운 사진이 인식되었을 때 보호자에게 알림

        Args:
            resident_id: 입소자 ID
            photo_id: 사진 ID
            db: 데이터베이스 세션

        Returns:
            알림을 받은 보호자 수
        """
        try:
            from app.models.models import Guardian

            # 보호자 목록 조회
            stmt = select(Guardian).filter(Guardian.resident_id == resident_id)
            result = await db.execute(stmt)
            guardians = result.scalars().all()

            sent_count = 0

            for guardian in guardians:
                success = await self.send_push_notification(
                    guardian_id=guardian.user_id,
                    title=f"사진 공유됨",
                    message=f"어르신 '{resident_id}'의 새로운 사진이 공유되었습니다.",
                    photo_id=photo_id,
                    db=db,
                )

                if success:
                    sent_count += 1

            logger.info(f"Notified {sent_count} guardians of new photo {photo_id}")
            return sent_count

        except Exception as e:
            logger.error(f"Notify guardians failed: {e}")
            return 0
