# pylint: disable=trailing-whitespace
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, JSON, Enum, DECIMAL, ForeignKey, UniqueConstraint, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import enum

from config import settings

# Database engine
engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Enums
class JobStatus(enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"
    retrying = "retrying"

class BackupStatus(enum.Enum):
    success = "success"
    failed = "failed"
    pending = "pending"
    running = "running"

class CommandFormat(enum.Enum):
    TEXT = "TEXT"
    JSON = "JSON"
    XML = "XML"
    YAML = "YAML"

class StorageType(enum.Enum):
    local = "local"
    sftp = "sftp"
    ftp = "ftp"
    s3 = "s3"
    azure = "azure"
    gcp = "gcp"

class StorageStatus(enum.Enum):
    uploading = "uploading"
    stored = "stored"
    failed = "failed"
    deleted = "deleted"

# Models
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    profile = relationship("UserProfile", back_populates="user", uselist=False)
    sessions = relationship("LoginSession", back_populates="user")

class UserProfile(Base):
    __tablename__ = "user_profiles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    phone = Column(String(20))
    department = Column(String(100))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="profile")

class LoginSession(Base):
    __tablename__ = "login_sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="sessions")

class DeviceType(Base):
    __tablename__ = "device_types"
    
    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String(50), nullable=False)
    model = Column(String(100), nullable=False)
    firmware_version = Column(String(50))
    device_category = Column(String(50))
    netmiko_device_type = Column(String(50), nullable=False)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('vendor', 'model', 'firmware_version', name='unique_device_type'),)
    
    # Relationships
    devices = relationship("NetworkDevice", back_populates="device_type")
    templates = relationship("BackupCommandTemplate", back_populates="device_type")

class NetworkDevice(Base):
    __tablename__ = "network_inventory_devices"
    
    id = Column(Integer, primary_key=True, index=True)
    device_name = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=False)
    device_type_id = Column(Integer, ForeignKey("device_types.id"), nullable=False)
    hostname = Column(String(100))
    location = Column(String(200))
    management_ip = Column(String(45))
    snmp_community = Column(String(100))
    ssh_username = Column(String(50))
    ssh_password_encrypted = Column(Text)
    ssh_key_file = Column(String(255))
    ssh_port = Column(Integer, default=22)
    enable_password_encrypted = Column(Text)
    description = Column(Text)
    is_active = Column(Boolean, default=True)
    last_backup_date = Column(DateTime)
    last_backup_status = Column(Enum(BackupStatus), default=BackupStatus.pending)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('device_name', 'ip_address', name='unique_device'),)
    
    # Relationships
    device_type = relationship("DeviceType", back_populates="devices")
    backup_info = relationship("DeviceBackupInfo", back_populates="device")

class BackupCommandTemplate(Base):
    __tablename__ = "backup_command_templates"
    
    id = Column(Integer, primary_key=True, index=True)
    device_type_id = Column(Integer, ForeignKey("device_types.id"), nullable=False)
    template_name = Column(String(100), nullable=False)
    template_description = Column(Text)
    backup_command = Column(Text, nullable=False)
    command_format = Column(Enum(CommandFormat), default=CommandFormat.TEXT)
    template_variables = Column(JSON)
    timeout_seconds = Column(Integer, default=300)
    retry_count = Column(Integer, default=5)
    retry_interval_seconds = Column(Integer, default=60)
    is_active = Column(Boolean, default=True)
    version = Column(String(20), default="1.0")
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    __table_args__ = (UniqueConstraint('device_type_id', 'template_name', 'version', name='unique_template'),)
    
    # Relationships
    device_type = relationship("DeviceType", back_populates="templates")
    schedule_policies = relationship("JobSchedulePolicy", back_populates="template")

class JobCategory(Base):
    __tablename__ = "job_categories"
    
    id = Column(Integer, primary_key=True, index=True)
    category_name = Column(String(100), unique=True, nullable=False)
    description = Column(Text)
    color_code = Column(String(7))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    schedule_policies = relationship("JobSchedulePolicy", back_populates="job_category")

class JobSchedulePolicy(Base):
    __tablename__ = "job_schedule_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    policy_name = Column(String(100), nullable=False)
    device_type_id = Column(Integer, ForeignKey("device_types.id"))
    template_id = Column(Integer, ForeignKey("backup_command_templates.id"), nullable=False)
    job_category_id = Column(Integer, ForeignKey("job_categories.id"))
    cron_expression = Column(String(100), nullable=False)
    backup_path = Column(String(500), nullable=False)
    sftp_server_ip = Column(String(45))
    sftp_username = Column(String(50))
    sftp_password_encrypted = Column(Text)
    sftp_port = Column(Integer, default=22)
    retention_days = Column(Integer, default=30)
    compression_enabled = Column(Boolean, default=True)
    encryption_enabled = Column(Boolean, default=False)
    notification_enabled = Column(Boolean, default=True)
    notification_emails = Column(JSON)
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    template = relationship("BackupCommandTemplate", back_populates="schedule_policies")
    job_category = relationship("JobCategory", back_populates="schedule_policies")
    backup_info = relationship("DeviceBackupInfo", back_populates="schedule_policy")

class DeviceBackupInfo(Base):
    __tablename__ = "device_backup_info"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("network_inventory_devices.id"), nullable=False)
    schedule_policy_id = Column(Integer, ForeignKey("job_schedule_policies.id"), nullable=False)
    job_status = Column(Enum(JobStatus), default=JobStatus.pending)
    backup_start_time = Column(DateTime)
    backup_end_time = Column(DateTime)
    backup_file_path = Column(String(500))
    backup_file_size_mb = Column(DECIMAL(10, 2))
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    next_retry_time = Column(DateTime)
    execution_log = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    device = relationship("NetworkDevice", back_populates="backup_info")
    schedule_policy = relationship("JobSchedulePolicy", back_populates="backup_info")
    storage_files = relationship("BackupFileStorage", back_populates="backup_info")

class BackupFileStorage(Base):
    __tablename__ = "backup_file_storage"
    
    id = Column(Integer, primary_key=True, index=True)
    backup_info_id = Column(Integer, ForeignKey("device_backup_info.id"), nullable=False)
    storage_type = Column(Enum(StorageType), default=StorageType.sftp)
    file_path = Column(String(500), nullable=False)
    file_hash = Column(String(64))
    file_size_bytes = Column(Integer)
    compression_ratio = Column(DECIMAL(5, 2))
    is_encrypted = Column(Boolean, default=False)
    storage_status = Column(Enum(StorageStatus), default=StorageStatus.stored)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    backup_info = relationship("DeviceBackupInfo", back_populates="storage_files")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()