"""
Pydantic 스키마 정의
요청/응답 데이터 검증 및 직렬화
"""

from datetime import datetime
from typing import Optional, List
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


# ==================== 사용자 관련 스키마 ====================

class UserResponse(BaseModel):
    """사용자 응답"""
    id: str
    email: str
    name: str
    role: str
    is_admin: bool = False
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
    """보호자 초대 생성 (직원용) — phone 또는 email 중 하나 필수"""
    resident_id: str
    phone: Optional[str] = None
    email: Optional[EmailStr] = None
    relationship_type: Optional[str] = None
    message: Optional[str] = None


class InvitationResponse(BaseModel):
    """초대 응답"""
    id: str
    facility_id: str
    resident_id: str
    phone: Optional[str] = None
    email: Optional[str] = None
    relationship_type: Optional[str] = None
    message: Optional[str] = None
    status: str
    facility_name: Optional[str] = None
    resident_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


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
