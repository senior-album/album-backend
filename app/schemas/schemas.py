"""
Pydantic 스키마 정의
요청/응답 데이터 검증 및 직렬화
"""

from datetime import date, datetime
from typing import Literal, Optional, List
from pydantic import BaseModel, EmailStr, Field


# ==================== 인증 관련 스키마 ====================

class LoginRequest(BaseModel):
    """이메일/비밀번호 로그인"""
    email: EmailStr
    password: str



class RegisterAdminRequest(BaseModel):
    """시설 관리자 등록 (시설 생성 + 계정 생성)"""
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    facilityName: str
    facilityAddress: str
    facilityPhone: Optional[str] = None


class RegisterStaffRequest(BaseModel):
    """직원 등록 (시설 코드로 합류)"""
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    facilityCode: str


class ConsentInput(BaseModel):
    """가입 시 사용자가 보내는 동의 항목 — 활성 ConsentDocument 1건당 1개."""
    document_id: str
    agreed: bool


class ConsentDocumentResponse(BaseModel):
    """활성 약관 응답 — 가입 폼이 이걸로 체크박스 + 본문 모달을 그린다."""
    id: str
    type: str
    version: str
    title: str
    content: str
    is_mandatory: bool
    effective_from: datetime

    class Config:
        from_attributes = True


class RegisterGuardianRequest(BaseModel):
    """보호자 가입 (단순 가입 — 시설/입소자 연결은 별도 요청)"""
    email: EmailStr
    password: str
    name: str
    phone: Optional[str] = None
    # T-020: 가입 시 활성 필수 약관 모두 agreed=True 여야 함. 선택 항목은 거부도 함께 기록.
    consents: List[ConsentInput] = Field(default_factory=list)


class PhoneOtpSendRequest(BaseModel):
    """전화번호 OTP 발송 요청"""
    phone: str


class PhoneOtpVerifyRequest(BaseModel):
    """전화번호 OTP 검증 요청"""
    phone: str
    code: str


class PhoneClaimRequest(BaseModel):
    """'이 번호 내가 등록 안 했어요' 신고. note 는 자유 텍스트 (선택)."""
    phone: str
    note: str | None = None


class PhoneClaimResponse(BaseModel):
    """신고 접수 확인."""
    id: str
    created_at: datetime


class PasswordResetRequest(BaseModel):
    """T-306: 비밀번호 재설정 요청. channel='email' 이면 identifier=이메일,
    'sms' 면 phone."""
    identifier: str
    channel: str  # email | sms


class PasswordResetConfirm(BaseModel):
    """T-306: 토큰 + 새 비밀번호로 재설정 확정."""
    token: str
    new_password: str


# ==================== 사용자 관련 스키마 ====================

class UserResponse(BaseModel):
    """사용자 응답"""
    id: str
    email: str
    name: str
    role: str
    is_admin: bool = False
    is_operator: bool = False  # T-020: Senior Album 운영자 (legal_settings/약관 publish 권한)
    facility_id: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True
    created_at: datetime

    class Config:
        from_attributes = True


# ==================== 시설 관련 스키마 ====================

class FacilityResponse(BaseModel):
    """시설 응답"""
    id: str
    name: str
    address: str
    phone: Optional[str] = None
    code: str
    created_at: datetime

    class Config:
        from_attributes = True


class FacilityCreate(BaseModel):
    """시설 생성"""
    name: str
    address: str
    phone: Optional[str] = None


class FacilitySearchResult(BaseModel):
    """시설 검색 결과 — 회원가입 전 시설 피커용 (전화번호는 뒷자리만 노출)"""
    id: str
    name: str
    address: str
    phone_last4: Optional[str] = None
    code: str


class FacilityUpdate(BaseModel):
    """시설 수정"""
    name: Optional[str] = None
    address: Optional[str] = None
    phone: Optional[str] = None


# ==================== 입소자 관련 스키마 ====================

class ResidentBase(BaseModel):
    """입소자 기본 정보"""
    name: str
    birth_date: Optional[str] = None
    gender: Optional[str] = None
    room_number: Optional[str] = None
    medical_notes: Optional[str] = None


class ResidentCreate(ResidentBase):
    """입소자 생성"""
    facility_id: str


class ResidentUpdate(BaseModel):
    """입소자 수정"""
    name: Optional[str] = None
    birth_date: Optional[str] = None
    gender: Optional[str] = None
    room_number: Optional[str] = None
    medical_notes: Optional[str] = None


class ResidentResponse(ResidentBase):
    """입소자 응답"""
    id: str
    facility_id: str
    code: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ResidentDetailResponse(ResidentResponse):
    """입소자 상세 응답"""
    guardians: List["GuardianResponse"] = []


# ==================== 보호자 관련 스키마 ====================

class GuardianResponse(BaseModel):
    """보호자 응답"""
    id: str
    user_id: str
    resident_id: Optional[str] = None
    relationship_type: Optional[str] = None
    request_message: Optional[str] = None
    is_approved: bool = False
    is_rejected: bool = False
    reject_reason: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class GuardianDetailResponse(GuardianResponse):
    """보호자 상세 응답 (관리자용 - 유저 이름, 입소자 이름 포함)"""
    user_name: Optional[str] = None
    user_email: Optional[str] = None
    user_phone: Optional[str] = None
    resident_name: Optional[str] = None
    facility_name: Optional[str] = None
    request_message: Optional[str] = None


class GuardianAccessRequest(BaseModel):
    """보호자 열람 요청 (보호자 → 시설)"""
    facilityCode: str
    residentCode: str
    relationshipType: Optional[str] = None
    message: Optional[str] = None


class GuardianApprovalRequest(BaseModel):
    """보호자 승인/거부"""
    approved: bool
    reject_reason: Optional[str] = None
    resident_id: Optional[str] = None  # 시설코드 요청 승인 시 입소자 배정


class GuardianCreate(BaseModel):
    """보호자 생성"""
    user_id: str
    resident_id: Optional[str] = None
    relationship_type: Optional[str] = None


# ==================== 초대 관련 스키마 ====================

class InvitationCreate(BaseModel):
    """보호자 초대 생성 (직원용).

    invite_type:
    - 'sms'   : 문자메시지 채널 — phone 또는 email 중 하나 필수.
    - 'in_app': 가입 회원 초대 — invitee_user_id 필수.
    """
    resident_id: str
    invite_type: str = "sms"
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    invitee_user_id: Optional[str] = None
    relationship_type: Optional[str] = None
    message: Optional[str] = None


class InvitationResponse(BaseModel):
    """초대 응답.

    T-304: invite_url + delivery_status 필드 추가.
    - invite_url: 초대 수락 페이지 URL. 직원이 복사해 본인 SMS/이메일/메신저로
      수동 발송 (T-061 알림톡 대행사 연동 / SMTP 미연동 상태에서 정직한 UX).
    - delivery_status:
      * "in_app"       — 인앱 알림 레코드 생성됨 (실제 "발송" 도달).
      * "manual_share" — 백엔드는 발송 안 함, 직원이 invite_url 을 수동 공유.
    """
    id: str
    facility_id: str
    resident_id: str
    invite_type: str = "sms"
    phone: Optional[str] = None
    email: Optional[str] = None
    invitee_user_id: Optional[str] = None
    invitee_name: Optional[str] = None  # in_app 초대 시 받는 사람 이름
    relationship_type: Optional[str] = None
    message: Optional[str] = None
    status: str
    facility_name: Optional[str] = None
    resident_name: Optional[str] = None
    created_at: datetime
    invite_url: Optional[str] = None
    delivery_status: str = "manual_share"

    class Config:
        from_attributes = True


class UserSearchResult(BaseModel):
    """T-149: 가입 회원 초대 — 직원이 회원 검색 시 반환되는 마스킹된 결과.

    개인정보 노출 최소화를 위해 정확 일치 (전화번호 또는 이메일 전체 일치) 만 매칭.
    이름은 마지막 글자만, 연락처는 일부만 노출.
    """
    id: str
    name_masked: str  # "홍길동" -> "홍O동"
    phone_masked: Optional[str] = None  # "010-1234-5678" -> "010-****-5678"
    email_masked: Optional[str] = None  # "abc@example.com" -> "a**@example.com"


class FacilityConnectionRequest(BaseModel):
    """보호자가 시설코드로 연결 요청"""
    facility_code: str
    relationship_type: Optional[str] = None
    message: Optional[str] = None


# ==================== 사진 관련 스키마 ====================

class MatchedResidentInfo(BaseModel):
    """사진에 매칭된 입소자 정보"""
    resident_id: str
    resident_name: Optional[str] = None
    confidence: Optional[float] = None


class PhotoResponse(BaseModel):
    """사진 응답"""
    id: str
    facility_id: str
    resident_id: Optional[str] = None
    original_url: str
    thumbnail_url: Optional[str] = None
    is_processed: bool
    processing_status: str
    created_at: datetime
    # 다대다: 이 사진에 매칭된 모든 입소자
    matched_residents: List[MatchedResidentInfo] = []
    is_public: bool = False
    # 좋아요
    like_count: int = 0
    liked_by_me: bool = False

    class Config:
        from_attributes = True


class PhotoDetailResponse(PhotoResponse):
    """사진 상세 응답"""
    faces: List["PhotoFaceResponse"] = []


class PhotoFaceResponse(BaseModel):
    """얼굴 감지 결과 응답"""
    id: str
    photo_id: str
    resident_id: Optional[str] = None
    bbox_x1: float
    bbox_y1: float
    bbox_x2: float
    bbox_y2: float
    confidence: float
    is_confirmed: bool
    is_rejected: bool
    created_at: datetime

    class Config:
        from_attributes = True


class FaceReviewRequest(BaseModel):
    """얼굴 분류 결과 검토"""
    resident_id: Optional[str] = None
    is_confirmed: bool = True


# ==================== 안부 일지 스키마 (T-241) ====================

# 한 시설마다 분류 기준이 다를 수 있어 정확한 분류는 free-text notes 로 보완.
# 코드/UI 가 동일 어휘를 쓰도록 화이트리스트 — 미상의 값은 422 로 거부.
MobilityStatus = Literal["independent", "walker", "wheelchair", "bedridden"]
MealStatus = Literal["full", "partial", "refused", "skipped"]


class WellnessLogUpsert(BaseModel):
    """안부 일지 upsert 요청 (PUT body). 모든 필드 옵션 — 부분 갱신 허용."""
    mobility_status: Optional[MobilityStatus] = None
    meal_breakfast: Optional[MealStatus] = None
    meal_lunch: Optional[MealStatus] = None
    meal_dinner: Optional[MealStatus] = None
    notes: Optional[str] = None


class WellnessLogResponse(BaseModel):
    """안부 일지 응답."""
    id: str
    resident_id: str
    log_date: date
    mobility_status: Optional[str] = None
    meal_breakfast: Optional[str] = None
    meal_lunch: Optional[str] = None
    meal_dinner: Optional[str] = None
    notes: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ==================== 이벤트 캘린더 스키마 (T-243) ====================

# 시설마다 행사 종류가 갈리지만 백엔드는 분류 어휘만 고정. 각 어휘에 매핑되지
# 않는 자유 행사는 `other` 로 분류 + free-text title/description 으로 표현.
EventType = Literal["birthday", "outing", "other"]


class EventBase(BaseModel):
    """이벤트 공통 필드 (create/update 가 공유)."""
    type: EventType
    title: str
    description: Optional[str] = None
    start_at: datetime
    end_at: Optional[datetime] = None
    all_day: bool = True
    resident_id: Optional[str] = None


class EventCreate(EventBase):
    """POST /facilities/{facility_id}/events 요청 본문."""
    pass


class EventUpdate(BaseModel):
    """PATCH /events/{id} 부분 갱신 — 보낸 필드만 갱신.

    facility_id 와 created_by 는 고정 — 변경하려면 새로 만들 것.
    """
    type: Optional[EventType] = None
    title: Optional[str] = None
    description: Optional[str] = None
    start_at: Optional[datetime] = None
    end_at: Optional[datetime] = None
    all_day: Optional[bool] = None
    resident_id: Optional[str] = None


class EventResponse(BaseModel):
    """이벤트 응답."""
    id: str
    facility_id: str
    resident_id: Optional[str] = None
    type: str
    title: str
    description: Optional[str] = None
    start_at: datetime
    end_at: Optional[datetime] = None
    all_day: bool
    created_by: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ==================== 알림 관련 스키마 ====================

class NotificationResponse(BaseModel):
    """알림 응답"""
    id: str
    user_id: str
    photo_id: Optional[str] = None
    title: str
    message: str
    notification_type: str
    is_read: bool
    is_sent: bool
    sent_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class NotificationListResponse(BaseModel):
    """알림 목록 응답 + 미읽음 카운트."""
    items: List[NotificationResponse]
    unread_count: int


# ==================== 대시보드 스키마 ====================

class DashboardStatsResponse(BaseModel):
    """대시보드 통계"""
    totalPhotos: int
    photosToday: int
    totalResidents: int
    classifiedPhotos: int
    classificationRate: float
    facilityName: str
    facilityCode: str


# ==================== Forward References ====================

ResidentDetailResponse.model_rebuild()
PhotoDetailResponse.model_rebuild()
