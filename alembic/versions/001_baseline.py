"""baseline — 현재 스키마 전체 스냅샷

Revision ID: 001_baseline
Revises:
Create Date: 2026-04-24

이 마이그레이션은 Alembic 도입 시점의 모델 상태를 frozen snapshot 으로
박제한다. 원본 DDL 은 scripts/dump_baseline_ddl.py 가 Base.metadata 를
postgres dialect 로 컴파일해 생성했다.

## 운영 환경 (기존 DB)
절대로 `alembic upgrade head` 를 그냥 돌리지 말 것. 이미 모든 테이블이
존재하므로 CREATE TABLE 이 실패한다. 대신:

    kubectl -n senior-album exec -it deploy/backend -- alembic stamp head

로 baseline 을 "이미 적용됨" 으로 마킹만 한다.

## 신규 환경 (빈 DB — 로컬 개발, CI, 새 배포)
그냥 돌리면 된다:

    alembic upgrade head

## 다음 마이그레이션
모델 수정 후:

    alembic revision --autogenerate -m "설명"
    # versions/ 아래 파일 리뷰 → 커밋
    # 배포 시 alembic upgrade head 자동 실행
"""

from alembic import op


# revision identifiers, used by Alembic.
revision = "001_baseline"
down_revision = None
branch_labels = None
depends_on = None


# sorted_tables 순서 — FK 부모 → 자식 순이므로 CREATE 를 위 → 아래로 실행 가능.
# Downgrade 는 역순으로 CASCADE DROP.
TABLES_IN_CREATION_ORDER = [
    "facilities",
    "residents",
    "users",
    "admin_audit_logs",
    "guardians",
    "invitations",
    "photos",
    "refresh_tokens",
    "notifications",
    "photo_audit_logs",
    "photo_faces",
    "photo_likes",
    "photo_processing_jobs",
    "photo_residents",
    "photo_shares",
]


def upgrade() -> None:
    # ==================== facilities ====================
    op.execute("""
        CREATE TABLE facilities (
            id VARCHAR(36) NOT NULL,
            name VARCHAR(255) NOT NULL,
            address VARCHAR(500) NOT NULL,
            phone VARCHAR(20),
            code VARCHAR(20) NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id)
        )
    """)
    op.execute("CREATE INDEX ix_facilities_name ON facilities (name)")
    op.execute("CREATE UNIQUE INDEX ix_facilities_code ON facilities (code)")

    # ==================== residents ====================
    op.execute("""
        CREATE TABLE residents (
            id VARCHAR(36) NOT NULL,
            facility_id VARCHAR(36) NOT NULL,
            code VARCHAR(20) NOT NULL,
            name VARCHAR(255) NOT NULL,
            birth_date VARCHAR(10),
            gender VARCHAR(10),
            room_number VARCHAR(50),
            medical_notes TEXT,
            is_active BOOLEAN,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id)
        )
    """)
    op.execute("CREATE UNIQUE INDEX ix_residents_code ON residents (code)")
    op.execute("CREATE INDEX ix_residents_facility_id ON residents (facility_id)")

    # ==================== users ====================
    op.execute("""
        CREATE TABLE users (
            id VARCHAR(36) NOT NULL,
            email VARCHAR(255) NOT NULL,
            name VARCHAR(255) NOT NULL,
            password_hash VARCHAR(255),
            role VARCHAR(20) NOT NULL,
            is_admin BOOLEAN,
            provider VARCHAR(20),
            provider_id VARCHAR(100),
            profile_image VARCHAR(500),
            facility_id VARCHAR(36),
            phone VARCHAR(20),
            phone_verified_at TIMESTAMP WITHOUT TIME ZONE,
            push_token VARCHAR(500),
            notification_enabled BOOLEAN,
            notification_settings JSON,
            is_active BOOLEAN,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id)
        )
    """)
    op.execute("CREATE UNIQUE INDEX ix_users_email ON users (email)")
    op.execute("CREATE INDEX ix_users_role ON users (role)")
    op.execute("CREATE INDEX ix_users_provider_id ON users (provider_id)")
    op.execute("CREATE INDEX ix_users_provider ON users (provider)")

    # ==================== admin_audit_logs ====================
    op.execute("""
        CREATE TABLE admin_audit_logs (
            id VARCHAR(36) NOT NULL,
            action VARCHAR(50) NOT NULL,
            performed_by VARCHAR(36) NOT NULL,
            target_type VARCHAR(50) NOT NULL,
            target_id VARCHAR(64) NOT NULL,
            facility_id VARCHAR(36),
            detail TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(performed_by) REFERENCES users (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id)
        )
    """)
    op.execute("CREATE INDEX ix_admin_audit_logs_facility_id ON admin_audit_logs (facility_id)")
    op.execute("CREATE INDEX ix_admin_audit_logs_action ON admin_audit_logs (action)")
    op.execute("CREATE INDEX ix_admin_audit_logs_created_at ON admin_audit_logs (created_at)")
    op.execute("CREATE INDEX ix_admin_audit_logs_performed_by ON admin_audit_logs (performed_by)")
    op.execute("CREATE INDEX ix_admin_audit_logs_target_id ON admin_audit_logs (target_id)")

    # ==================== guardians ====================
    op.execute("""
        CREATE TABLE guardians (
            id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            resident_id VARCHAR(36),
            relationship_type VARCHAR(50),
            request_message TEXT,
            facility_id VARCHAR(36),
            is_approved BOOLEAN,
            is_rejected BOOLEAN,
            approved_by VARCHAR(36),
            approved_at TIMESTAMP WITHOUT TIME ZONE,
            reject_reason VARCHAR(500),
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(user_id) REFERENCES users (id),
            FOREIGN KEY(resident_id) REFERENCES residents (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id),
            FOREIGN KEY(approved_by) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_guardians_is_approved ON guardians (is_approved)")
    op.execute("CREATE INDEX ix_guardians_user_id ON guardians (user_id)")
    op.execute("CREATE INDEX ix_guardians_facility_id ON guardians (facility_id)")
    op.execute("CREATE INDEX ix_guardians_resident_id ON guardians (resident_id)")

    # ==================== invitations ====================
    op.execute("""
        CREATE TABLE invitations (
            id VARCHAR(36) NOT NULL,
            facility_id VARCHAR(36) NOT NULL,
            resident_id VARCHAR(36) NOT NULL,
            phone VARCHAR(20),
            email VARCHAR(255),
            relationship_type VARCHAR(50),
            message TEXT,
            status VARCHAR(20),
            invited_by VARCHAR(36) NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            accepted_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id),
            FOREIGN KEY(resident_id) REFERENCES residents (id),
            FOREIGN KEY(invited_by) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_invitations_status ON invitations (status)")
    op.execute("CREATE INDEX ix_invitations_facility_id ON invitations (facility_id)")
    op.execute("CREATE INDEX ix_invitations_phone ON invitations (phone)")
    op.execute("CREATE INDEX ix_invitations_email ON invitations (email)")
    op.execute("CREATE INDEX ix_invitations_resident_id ON invitations (resident_id)")

    # ==================== photos ====================
    op.execute("""
        CREATE TABLE photos (
            id VARCHAR(36) NOT NULL,
            facility_id VARCHAR(36) NOT NULL,
            resident_id VARCHAR(36),
            original_url VARCHAR(500) NOT NULL,
            thumbnail_url VARCHAR(500),
            is_processed BOOLEAN,
            processing_status VARCHAR(50),
            is_public BOOLEAN,
            published_by VARCHAR(36),
            published_at TIMESTAMP WITHOUT TIME ZONE,
            upload_source VARCHAR(50),
            uploaded_by VARCHAR(36),
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id),
            FOREIGN KEY(resident_id) REFERENCES residents (id),
            FOREIGN KEY(published_by) REFERENCES users (id),
            FOREIGN KEY(uploaded_by) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_photos_facility_id ON photos (facility_id)")
    op.execute("CREATE INDEX ix_photos_resident_id ON photos (resident_id)")
    op.execute("CREATE INDEX ix_photos_is_public ON photos (is_public)")

    # ==================== refresh_tokens ====================
    op.execute("""
        CREATE TABLE refresh_tokens (
            id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            jti VARCHAR(64) NOT NULL,
            family_id VARCHAR(36) NOT NULL,
            expires_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            revoked_at TIMESTAMP WITHOUT TIME ZONE,
            revoke_reason VARCHAR(50),
            user_agent VARCHAR(500),
            ip_address VARCHAR(45),
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """)
    op.execute("CREATE INDEX ix_refresh_tokens_user_id ON refresh_tokens (user_id)")
    op.execute("CREATE INDEX ix_refresh_tokens_family_id ON refresh_tokens (family_id)")
    op.execute("CREATE INDEX ix_refresh_tokens_expires_at ON refresh_tokens (expires_at)")
    op.execute("CREATE UNIQUE INDEX ix_refresh_tokens_jti ON refresh_tokens (jti)")

    # ==================== notifications ====================
    op.execute("""
        CREATE TABLE notifications (
            id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36),
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            notification_type VARCHAR(50) NOT NULL,
            is_read BOOLEAN,
            is_sent BOOLEAN,
            sent_at TIMESTAMP WITHOUT TIME ZONE,
            read_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(user_id) REFERENCES users (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id)
        )
    """)
    op.execute("CREATE INDEX ix_notifications_user_id ON notifications (user_id)")

    # ==================== photo_audit_logs ====================
    op.execute("""
        CREATE TABLE photo_audit_logs (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            action VARCHAR(50) NOT NULL,
            performed_by VARCHAR(36) NOT NULL,
            detail TEXT,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(performed_by) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_audit_logs_action ON photo_audit_logs (action)")
    op.execute("CREATE INDEX ix_photo_audit_logs_photo_id ON photo_audit_logs (photo_id)")
    op.execute("CREATE INDEX ix_photo_audit_logs_created_at ON photo_audit_logs (created_at)")
    op.execute("CREATE INDEX ix_photo_audit_logs_performed_by ON photo_audit_logs (performed_by)")

    # ==================== photo_faces ====================
    op.execute("""
        CREATE TABLE photo_faces (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            resident_id VARCHAR(36),
            bbox_x1 FLOAT NOT NULL,
            bbox_y1 FLOAT NOT NULL,
            bbox_x2 FLOAT NOT NULL,
            bbox_y2 FLOAT NOT NULL,
            embedding_id VARCHAR(100),
            confidence FLOAT NOT NULL,
            is_confirmed BOOLEAN,
            is_rejected BOOLEAN,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(resident_id) REFERENCES residents (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_faces_photo_id ON photo_faces (photo_id)")
    op.execute("CREATE INDEX ix_photo_faces_resident_id ON photo_faces (resident_id)")

    # ==================== photo_likes ====================
    op.execute("""
        CREATE TABLE photo_likes (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(user_id) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_likes_user_id ON photo_likes (user_id)")
    op.execute("CREATE INDEX ix_photo_likes_photo_id ON photo_likes (photo_id)")

    # ==================== photo_processing_jobs ====================
    op.execute("""
        CREATE TABLE photo_processing_jobs (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            facility_id VARCHAR(36) NOT NULL,
            status VARCHAR(20) NOT NULL,
            error_message TEXT,
            retry_count INTEGER NOT NULL,
            max_retries INTEGER NOT NULL,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            started_at TIMESTAMP WITHOUT TIME ZONE,
            completed_at TIMESTAMP WITHOUT TIME ZONE,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(facility_id) REFERENCES facilities (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_processing_jobs_facility_id ON photo_processing_jobs (facility_id)")
    op.execute("CREATE INDEX ix_photo_processing_jobs_photo_id ON photo_processing_jobs (photo_id)")
    op.execute("CREATE INDEX ix_photo_processing_jobs_status ON photo_processing_jobs (status)")

    # ==================== photo_residents ====================
    op.execute("""
        CREATE TABLE photo_residents (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            resident_id VARCHAR(36) NOT NULL,
            confidence FLOAT,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(resident_id) REFERENCES residents (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_residents_photo_id ON photo_residents (photo_id)")
    op.execute("CREATE INDEX ix_photo_residents_resident_id ON photo_residents (resident_id)")

    # ==================== photo_shares ====================
    op.execute("""
        CREATE TABLE photo_shares (
            id VARCHAR(36) NOT NULL,
            photo_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            share_type VARCHAR(20) NOT NULL,
            share_token VARCHAR(100),
            expires_at TIMESTAMP WITHOUT TIME ZONE,
            created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL,
            PRIMARY KEY (id),
            FOREIGN KEY(photo_id) REFERENCES photos (id),
            FOREIGN KEY(user_id) REFERENCES users (id)
        )
    """)
    op.execute("CREATE INDEX ix_photo_shares_user_id ON photo_shares (user_id)")
    op.execute("CREATE UNIQUE INDEX ix_photo_shares_share_token ON photo_shares (share_token)")
    op.execute("CREATE INDEX ix_photo_shares_photo_id ON photo_shares (photo_id)")


def downgrade() -> None:
    # 역순으로 CASCADE DROP — FK 무시하고 확실히 치운다.
    for table in reversed(TABLES_IN_CREATION_ORDER):
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
