from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

class DeviceType(Base):
    __tablename__ = "device_types"
    
    device_type_id = Column(Integer, primary_key=True, index=True)
    device_type_name = Column(String(100), nullable=False)
    vendor = Column(String(50))
    model = Column(String(100))
    firmware_version = Column(String(50))
    default_ssh_port = Column(Integer, default=22)
    default_protocol = Column(String(20), default="ssh")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    devices = relationship("NetworkInventoryDevice", back_populates="device_type")
    backup_templates = relationship("BackupCommandTemplate", back_populates="device_type")

class NetworkInventoryDevice(Base):
    __tablename__ = "network_inventory_devices"
    
    device_id = Column(String(36), primary_key=True, index=True)  # UUID
    device_name = Column(String(100), nullable=False)
    device_type_id = Column(Integer, ForeignKey("device_types.device_type_id"), nullable=False)
    ip_address = Column(String(45), nullable=False)  # IPv4/IPv6 support
    hostname = Column(String(255))
    location = Column(String(255))
    description = Column(Text)
    ssh_port = Column(Integer, default=22)
    ssh_username = Column(String(100))
    ssh_password = Column(String(255))  # Encrypted in production
    enable_password = Column(String(255))  # Encrypted in production
    ssh_key_path = Column(String(500))
    snmp_community = Column(String(100))
    snmp_version = Column(String(10), default="2c")
    management_vlan = Column(Integer)
    is_active = Column(Boolean, default=True)
    last_backup_date = Column(DateTime)
    last_connection_test = Column(DateTime)
    connection_status = Column(String(20), default="unknown")  # unknown, online, offline, error
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(Integer, ForeignKey("users.user_id"))
    
    # Relationships
    device_type = relationship("DeviceType", back_populates="devices")
    backup_jobs = relationship("DeviceBackupInfo", back_populates="device")

class BackupCommandTemplate(Base):
    __tablename__ = "backup_command_templates"
    
    template_id = Column(Integer, primary_key=True, index=True)
    template_name = Column(String(100), nullable=False)
    device_type_id = Column(Integer, ForeignKey("device_types.device_type_id"), nullable=False)
    command_sequence = Column(Text, nullable=False)
    expected_output_format = Column(String(20), default="text")  # text, xml, json, yaml
    timeout_seconds = Column(Integer, default=30)
    retry_count = Column(Integer, default=3)
    is_active = Column(Boolean, default=True)
    version = Column(String(20), default="1.0")
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    device_type = relationship("DeviceType", back_populates="backup_templates")

class DeviceBackupInfo(Base):
    __tablename__ = "device_backup_info"
    
    backup_id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String(36), ForeignKey("network_inventory_devices.device_id"), nullable=False)
    template_id = Column(Integer, ForeignKey("backup_command_templates.template_id"))
    job_status = Column(String(20), default="pending")  # pending, running, completed, failed
    backup_file_path = Column(String(500))
    backup_file_size = Column(Integer)
    backup_start_time = Column(DateTime)
    backup_end_time = Column(DateTime)
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("NetworkInventoryDevice", back_populates="backup_jobs")