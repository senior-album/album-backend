"""
SQLAlchemy ORM 모델
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Date, DateTime, Text, Boolean, ForeignKey, JSON,
    LargeBinary, UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class Facility(Base):
    __tablename__ = "facilities"

    id = Column(String(36), primary_key=True)
    name = Column(String(255), nullable=False, index=True)
    address = Column(String(500), nullable=False)
    phone = Column(String(20), nullable=True, default="")
    code = Column(String(20), unique=True, nullable=False, index=True)

    staff = relationship("User", back_populates="facility", foreign_keys="[User.facility_id]")
    residents = relationship("Resident", back_populates="facility")
    photos = relationship("Photo", back_populates="facility")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False)
    password_hash = Column(String(255), nullable=True)  # 소셜 로그인은 비밀번호 없음
    role = Column(String(20), nullable=False, index=True)
    is_admin = Column(Boolean, default=False)
    # 운영자 (Senior Album 자체 운영 주체) — 약관/처리방침 publish, legal_settings 편집 권한.
    # 시설 관리자 (is_admin) 와 별개. 부트스트랩은 OPERATOR_EMAIL env + 시작 시 promote.
    is_operator = Column(Boolean, default=False, nullable=False)

    # 소셜 로그인
    provider = Column(String(20), nullable=True, index=True)  # "kakao", "google", None(이메일)
    provider_id = Column(String(100), nullable=True, index=True)  # 카카오 회원번호
    profile_image = Column(String(500), nullable=True)  # 카카오 프로필 이미지

    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=True)
    facility = relationship("Facility", back_populates="staff", foreign_keys=[facility_id])

    # OTP 인증 성공 시 갱신. UNIQUE — 한 번호는 한 계정에만 매핑 (사칭/오등록 방지).
    # 재인증 정책: phone_verified_at 이 OTP_REVERIFY_AFTER_DAYS 경과 시 게이트가 재인증 요구.
    phone = Column(String(20), unique=True, nullable=True)
    phone_verified_at = Column(DateTime, nullable=True)
    push_token = Column(String(500), nullable=True)
    notification_enabled = Column(Boolean, default=True)
    notification_settings = Column(JSON, default={})

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Resident(Base):
    __tablename__ = "residents"

    id = Column(String(36), primary_key=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=False, index=True)
    code = Column(String(20), unique=True, nullable=False, index=True)  # RES-XXXX
    # T-003-5b: 평문 PII 컬럼 (name / birth_date / medical_notes) 은 drop 됨.
    # 응답으로 노출할 평문은 라우터가 `apply_pii_decryption` 으로 ct→평문 setattr
    # 한 후 Pydantic 응답에 instance attribute 로 흘려보낸다.
    gender = Column(String(10), nullable=True)
    room_number = Column(String(50), nullable=True)

    # T-003 envelope encryption.
    # Layout: name_ct = nonce(12B) || AESGCM(dek).encrypt(name_utf8). dek_wrapped = nonce(12B) || AESGCM(KEK).encrypt(dek). row 당 dek 1개를 PII 컬럼들이 공유.
    name_ct = Column(LargeBinary, nullable=True)
    name_blind_idx = Column(LargeBinary, nullable=True, index=True)
    birth_date_ct = Column(LargeBinary, nullable=True)
    medical_notes_ct = Column(LargeBinary, nullable=True)
    dek_wrapped = Column(LargeBinary, nullable=True)

    facility = relationship("Facility", back_populates="residents")
    guardians = relationship("Guardian", back_populates="resident")
    photos = relationship("Photo", back_populates="resident")

    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Guardian(Base):
    __tablename__ = "guardians"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=True, index=True)  # 시설코드 요청 시 null (시설에서 배정)

    resident = relationship("Resident", back_populates="guardians")
    user = relationship("User", foreign_keys="[Guardian.user_id]")
    approver = relationship("User", foreign_keys="[Guardian.approved_by]")

    relationship_type = Column(String(50), nullable=True)  # 아들, 딸, 배우자, 손자녀 등
    request_message = Column(Text, nullable=True)  # 보호자가 시설에 보내는 요청 메시지
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=True, index=True)

    # 승인 관련
    is_approved = Column(Boolean, default=False, index=True)
    is_rejected = Column(Boolean, default=False)
    approved_by = Column(String(36), ForeignKey("users.id"), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    reject_reason = Column(String(500), nullable=True)

    facility = relationship("Facility", foreign_keys=[facility_id])
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Invitation(Base):
    """시설 → 보호자 초대

    T-149: invite_type 으로 채널 분기.
    - 'sms'    : 외부 채널 (전화번호로 보내는 문자/알림톡). phone 필수.
    - 'in_app' : 가입 회원 초대 — invitee_user_id 가 가리키는 기존 User 에게 인앱 알림.
                 phone/email 은 비워둔다 (스냅샷 X — 사용자 phone 변경 따라가기 위함).
    """
    __tablename__ = "invitations"

    id = Column(String(36), primary_key=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=False, index=True)
    invite_type = Column(String(20), nullable=False, default="sms", index=True)
    phone = Column(String(20), nullable=True, index=True)  # 보호자 핸드폰 번호 (sms 채널)
    email = Column(String(255), nullable=True, index=True)  # 보호자 이메일 (sms 채널 보조)
    invitee_user_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)  # in_app 채널
    relationship_type = Column(String(50), nullable=True)
    message = Column(Text, nullable=True)  # 직원이 보내는 메시지

    status = Column(String(20), default="pending", index=True)  # pending, accepted, rejected
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=False)

    facility = relationship("Facility")
    resident = relationship("Resident")
    inviter = relationship("User", foreign_keys=[invited_by])
    invitee = relationship("User", foreign_keys=[invitee_user_id])

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    accepted_at = Column(DateTime, nullable=True)


class PhotoResident(Base):
    """사진 ↔ 입소자 다대다 연결 (사진 한 장에 여러 입소자 가능)"""
    __tablename__ = "photo_residents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=False, index=True)
    confidence = Column(Float, nullable=True)  # 매칭 신뢰도

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class Photo(Base):
    __tablename__ = "photos"

    id = Column(String(36), primary_key=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=True, index=True)  # 대표 입소자 (하위 호환)

    original_url = Column(String(500), nullable=False)
    thumbnail_url = Column(String(500), nullable=True)

    is_processed = Column(Boolean, default=False)
    processing_status = Column(String(50), default="pending")
    is_public = Column(Boolean, default=False, index=True)  # 보호자에게 공개 여부 (직원이 승인)
    published_by = Column(String(36), ForeignKey("users.id"), nullable=True)  # 공개 승인자
    published_at = Column(DateTime, nullable=True)  # 공개 승인 시각

    upload_source = Column(String(50), nullable=True)
    uploaded_by = Column(String(36), ForeignKey("users.id"), nullable=True)

    facility = relationship("Facility", back_populates="photos")
    resident = relationship("Resident", back_populates="photos")
    faces = relationship("PhotoFace", back_populates="photo")
    photo_residents = relationship("PhotoResident", backref="photo")
    likes = relationship("PhotoLike", backref="photo", cascade="all, delete-orphan")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PhotoFace(Base):
    """사진 내 얼굴 감지 결과 (임베딩은 OpenSearch에 저장)"""
    __tablename__ = "photo_faces"

    id = Column(String(36), primary_key=True)
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=True, index=True)

    bbox_x1 = Column(Float, nullable=False)
    bbox_y1 = Column(Float, nullable=False)
    bbox_x2 = Column(Float, nullable=False)
    bbox_y2 = Column(Float, nullable=False)

    # 임베딩은 OpenSearch에 저장, 여기는 참조 ID만
    embedding_id = Column(String(100), nullable=True)

    confidence = Column(Float, nullable=False)
    is_confirmed = Column(Boolean, default=False)
    is_rejected = Column(Boolean, default=False)

    photo = relationship("Photo", back_populates="faces")

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class PhotoLike(Base):
    """사진 좋아요"""
    __tablename__ = "photo_likes"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PhotoShare(Base):
    """사진 공유 기록"""
    __tablename__ = "photo_shares"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    share_type = Column(String(20), nullable=False)  # "kakao", "link"
    share_token = Column(String(100), nullable=True, unique=True, index=True)
    expires_at = Column(DateTime, nullable=True)  # 공유 링크 만료 시각

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class PhotoAuditLog(Base):
    """
    사진 접근·변경 이력 감사 로그.

    T-101 으로 action 어휘 확장 — 기존 publish / unpublish / upload / delete
    외에 view / share_create / share_view 를 추가. 운영 / 법적 이슈가 생겼을
    때 "누가 언제 어떤 사진에 무슨 행위를 했는지" 재현 가능한 것이 목적.
    """
    __tablename__ = "photo_audit_logs"

    # action 값 목록 — 신규 action 추가 시 이 주석도 같이 업데이트.
    # view          : 인증된 사용자가 사진 상세 조회
    # share_create  : 공유 링크 생성
    # share_view    : 공유 링크로 사진 조회 (performer = 링크 생성자)
    # publish       : 공개 전환
    # unpublish     : 비공개 전환
    # delete        : 삭제
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False, index=True)
    performed_by = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    detail = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class AdminAuditLog(Base):
    """
    T-102: 관리자(직원/시설 관리자) 특권 행위 감사 로그.

    PhotoAuditLog 가 사진 한 장에 대한 이력을 기록한다면, 이쪽은 사진이 아닌
    대상(보호자 승인, 초대 발송, 입소자 PII 수정 등) 에 대한 행위를 기록.
    법적/유출 대응 시 "누가 언제 어떤 대상에 무엇을 했는가" 를 재현하기 위한
    비 사진 이벤트 스트림.
    """
    __tablename__ = "admin_audit_logs"

    # action 값 목록 (확장 가능) — 호출부에서 자유 문자열이지만 관례 유지:
    # guardian_approve      : 보호자 요청 승인
    # guardian_reject       : 보호자 요청 거부
    # invitation_create     : 보호자 초대 발송
    # resident_update       : 입소자 정보 수정 (이름/의료 메모 등 PII)
    # resident_face_delete  : 등록된 기준 사진(임베딩) 삭제
    # user_set_active       : 운영자가 다른 유저 활성/비활성 토글 (T-144)
    # user_set_admin        : 운영자가 다른 유저 시설관리자 권한 토글 (T-144)
    # user_set_operator     : 운영자가 다른 유저 운영자 권한 토글 (T-144)
    # user_set_facility     : 운영자가 유저의 소속 시설 변경 (T-144)
    # facility_create       : 운영자가 신규 시설 생성 (T-145)
    # facility_update       : 운영자가 시설 정보(name/address/phone) 수정 (T-145)
    # photo_job_retry       : 운영자가 실패한 사진 처리 작업 재큐 (T-147)
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    action = Column(String(50), nullable=False, index=True)
    performed_by = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    target_type = Column(String(50), nullable=False)  # "guardian" | "invitation" | "resident" ...
    target_id = Column(String(64), nullable=False, index=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=True, index=True)
    detail = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)


class PhotoProcessingJob(Base):
    """사진 처리 비동기 작업 큐"""
    __tablename__ = "photo_processing_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=False, index=True)
    status = Column(String(20), default="pending", nullable=False, index=True)
    # pending -> processing -> completed / failed
    error_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    photo = relationship("Photo", foreign_keys=[photo_id])


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=True)

    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(String(50), nullable=False)

    is_read = Column(Boolean, default=False)
    is_sent = Column(Boolean, default=False)

    sent_at = Column(DateTime, nullable=True)
    read_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ConsentDocument(Base):
    """
    T-020: 약관·처리방침·민감정보·마케팅 동의 문서.
    type+version 으로 유니크. 가입 시점에 어느 문서 어느 버전에 동의했는지를
    user_consents 가 참조 — 추후 "동의받은 시점의 약관 원문" 사본 제출 요구
    대응을 위해 본문(content) 자체를 row 에 저장.
    개정 시 새 row 발행 → 기존 version 은 effective_until 로 마감.
    """
    __tablename__ = "consent_documents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type = Column(String(30), nullable=False, index=True)
    # 'terms_guardian' | 'privacy' | 'sensitive_info' | 'marketing'
    version = Column(String(20), nullable=False)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    is_mandatory = Column(Boolean, default=True, nullable=False)
    effective_from = Column(DateTime, nullable=False)
    effective_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("type", "version", name="uq_consent_documents_type_version"),
    )


class UserConsent(Base):
    """
    T-020: 사용자가 가입 시점에 어느 문서에 동의/거부했는지 기록.
    선택 항목(마케팅 등) 미체크도 row 로 남김 — 추후 재동의 안내·감사 대응에 참조.
    """
    __tablename__ = "user_consents"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    document_id = Column(String(36), ForeignKey("consent_documents.id"), nullable=False, index=True)
    agreed = Column(Boolean, nullable=False)
    agreed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    user = relationship("User", foreign_keys=[user_id])
    document = relationship("ConsentDocument", foreign_keys=[document_id])


class LegalSetting(Base):
    """
    T-020: 운영자 (Senior Album) 의 회사·연락처·시행일 등 법령 표기용 KV.
    PrivacyPage / TermsPage 가 본문 외에 "이 회사가 누구이며, 누구에게 문의해야 하는가" 를
    렌더링할 때 참조. consent_documents.content (약관 본문) 와는 별도 — 본문은 versioning 이
    필요하지만 회사 정보는 한 번에 1 값만 유효하므로 KV 가 적합.
    """
    __tablename__ = "legal_settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=False, default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    updated_by_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)


class RefreshToken(Base):
    """
    Refresh 토큰 — DB 저장 + rotation + reuse detection (T-009)
    family_id: 같은 로그인에서 출발한 토큰 체인 식별자.
               rotation 시 유지되며, reuse 감지되면 family 전체 일괄 revoke.
    """
    __tablename__ = "refresh_tokens"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    jti = Column(String(64), unique=True, nullable=False, index=True)
    family_id = Column(String(36), nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    revoked_at = Column(DateTime, nullable=True)  # null이면 활성, NOT NULL이면 회수
    revoke_reason = Column(String(50), nullable=True)  # "rotated", "logout", "logout-all", "reuse-detected"
    user_agent = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class ResidentWellnessLog(Base):
    """T-241: 입소자 안부 일지 — 시설 직원이 거동·식사 상태를 일일 기록.

    한 입소자 × 하루 = 1 row (UNIQUE(resident_id, log_date)). PUT 으로 upsert —
    같은 날짜 재호출은 같은 row 를 업데이트한다. read 권한은 시설 직원 (해당
    시설) 또는 본인이 승인된 입소자의 가디언.

    값 어휘 (스키마 레이어에서 화이트리스트 검증):
      mobility_status: independent | walker | wheelchair | bedridden
      meal_*         : full | partial | refused | skipped
    한 시설마다 분류 기준이 갈릴 수 있어 free-text `notes` 를 같이 둠.
    """
    __tablename__ = "resident_wellness_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=False, index=True)
    log_date = Column(Date, nullable=False, index=True)

    mobility_status = Column(String(20), nullable=True)
    meal_breakfast = Column(String(20), nullable=True)
    meal_lunch = Column(String(20), nullable=True)
    meal_dinner = Column(String(20), nullable=True)
    notes = Column(Text, nullable=True)

    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("resident_id", "log_date", name="uq_resident_wellness_logs_resident_date"),
    )


class PhoneClaimReport(Base):
    """
    "이 번호 내가 등록 안 했는데?" 신고. 휴대폰 OTP 인증 시 dup 충돌 (HTTP 409) 을
    경험한 사용자가 본인이 직접 신고. 운영자가 어드민에서 수동 검토 (별 PR).
    """
    __tablename__ = "phone_claim_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    reporter_user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    claimed_phone = Column(String(20), nullable=False, index=True)
    note = Column(Text, nullable=False, default="")
    # pending | reviewed | resolved | rejected — 운영자 어드민에서 갱신
    status = Column(String(20), nullable=False, default="pending", index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
