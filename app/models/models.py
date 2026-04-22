"""
SQLAlchemy ORM 모델
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, JSON,
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

    # 소셜 로그인
    provider = Column(String(20), nullable=True, index=True)  # "kakao", "google", None(이메일)
    provider_id = Column(String(100), nullable=True, index=True)  # 카카오 회원번호
    profile_image = Column(String(500), nullable=True)  # 카카오 프로필 이미지

    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=True)
    facility = relationship("Facility", back_populates="staff", foreign_keys=[facility_id])

    phone = Column(String(20), nullable=True)
    phone_verified_at = Column(DateTime, nullable=True)  # 최근 OTP 성공 시각 — 시설 연결 요청 게이트용
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
    name = Column(String(255), nullable=False)
    birth_date = Column(String(10), nullable=True)
    gender = Column(String(10), nullable=True)
    room_number = Column(String(50), nullable=True)
    medical_notes = Column(Text, nullable=True)

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
    """시설 → 보호자 초대"""
    __tablename__ = "invitations"

    id = Column(String(36), primary_key=True)
    facility_id = Column(String(36), ForeignKey("facilities.id"), nullable=False, index=True)
    resident_id = Column(String(36), ForeignKey("residents.id"), nullable=False, index=True)
    phone = Column(String(20), nullable=True, index=True)  # 보호자 핸드폰 번호
    email = Column(String(255), nullable=True, index=True)  # 보호자 이메일
    relationship_type = Column(String(50), nullable=True)
    message = Column(Text, nullable=True)  # 직원이 보내는 메시지

    status = Column(String(20), default="pending", index=True)  # pending, accepted, rejected
    invited_by = Column(String(36), ForeignKey("users.id"), nullable=False)

    facility = relationship("Facility")
    resident = relationship("Resident")
    inviter = relationship("User")

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
    """사진 공개/비공개 이력 추적"""
    __tablename__ = "photo_audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    photo_id = Column(String(36), ForeignKey("photos.id"), nullable=False, index=True)
    action = Column(String(50), nullable=False)  # "publish", "unpublish", "upload", "delete"
    performed_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    detail = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


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
