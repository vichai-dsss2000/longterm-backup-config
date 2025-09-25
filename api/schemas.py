from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum

# Authentication Schemas
class UserLogin(BaseModel):
	username: str
	password: str

class Token(BaseModel):
	access_token: str
	token_type: str
	expires_at: datetime
	user: dict

class UserCreate(BaseModel):
	username: str
	email: EmailStr
	password: str
	first_name: Optional[str] = None
	last_name: Optional[str] = None
	phone: Optional[str] = None
	department: Optional[str] = None
	is_admin: bool = False

class UserUpdate(BaseModel):
	email: Optional[EmailStr] = None
	first_name: Optional[str] = None
	last_name: Optional[str] = None
	phone: Optional[str] = None
	department: Optional[str] = None
	is_active: Optional[bool] = None
	is_admin: Optional[bool] = None

class UserResponse(BaseModel):
	id: int
	username: str
	email: str
	is_active: bool
	is_admin: bool
	created_at: datetime
	profile: Optional[dict] = None
	
	class Config:
		from_attributes = True

# Device Type Schemas
class DeviceTypeCreate(BaseModel):
	vendor: str
	model: str
	firmware_version: Optional[str] = None
	device_category: Optional[str] = None
	netmiko_device_type: str
	description: Optional[str] = None

class DeviceTypeUpdate(BaseModel):
	vendor: Optional[str] = None
	model: Optional[str] = None
	firmware_version: Optional[str] = None
	device_category: Optional[str] = None
	netmiko_device_type: Optional[str] = None
	description: Optional[str] = None
	is_active: Optional[bool] = None

class DeviceTypeResponse(BaseModel):
	id: int
	vendor: str
	model: str
	firmware_version: Optional[str]
	device_category: Optional[str]
	netmiko_device_type: str
	description: Optional[str]
	is_active: bool
	created_at: datetime
	
	class Config:
		from_attributes = True

# Network Device Schemas
class NetworkDeviceCreate(BaseModel):
	device_name: str
	ip_address: str
	device_type_id: int
	hostname: Optional[str] = None
	location: Optional[str] = None
	management_ip: Optional[str] = None
	snmp_community: Optional[str] = None
	ssh_username: Optional[str] = None
	ssh_password: Optional[str] = None  # Will be encrypted
	ssh_key_file: Optional[str] = None
	ssh_port: int = 22
	enable_password: Optional[str] = None  # Will be encrypted
	description: Optional[str] = None

class NetworkDeviceUpdate(BaseModel):
	device_name: Optional[str] = None
	ip_address: Optional[str] = None
	device_type_id: Optional[int] = None
	hostname: Optional[str] = None
	location: Optional[str] = None
	management_ip: Optional[str] = None
	snmp_community: Optional[str] = None
	ssh_username: Optional[str] = None
	ssh_password: Optional[str] = None
	ssh_key_file: Optional[str] = None
	ssh_port: Optional[int] = None
	enable_password: Optional[str] = None
	description: Optional[str] = None
	is_active: Optional[bool] = None

class NetworkDeviceResponse(BaseModel):
	id: int
	device_name: str
	ip_address: str
	device_type_id: int
	hostname: Optional[str]
	location: Optional[str]
	management_ip: Optional[str]
	ssh_username: Optional[str]
	ssh_port: int
	description: Optional[str]
	is_active: bool
	last_backup_date: Optional[datetime]
	last_backup_status: Optional[str]
	created_at: datetime
	device_type: DeviceTypeResponse
	
	class Config:
		from_attributes = True

# Backup Command Template Schemas
class BackupCommandTemplateCreate(BaseModel):
	device_type_id: int
	template_name: str
	template_description: Optional[str] = None
	backup_command: str
	command_format: str = "TEXT"
	template_variables: Optional[dict] = None
	timeout_seconds: int = 300
	retry_count: int = 5
	retry_interval_seconds: int = 60
	version: str = "1.0"

class BackupCommandTemplateUpdate(BaseModel):
	template_name: Optional[str] = None
	template_description: Optional[str] = None
	backup_command: Optional[str] = None
	command_format: Optional[str] = None
	template_variables: Optional[dict] = None
	timeout_seconds: Optional[int] = None
	retry_count: Optional[int] = None
	retry_interval_seconds: Optional[int] = None
	is_active: Optional[bool] = None
	version: Optional[str] = None

class BackupCommandTemplateResponse(BaseModel):
	id: int
	device_type_id: int
	template_name: str
	template_description: Optional[str]
	backup_command: str
	command_format: str
	template_variables: Optional[dict]
	timeout_seconds: int
	retry_count: int
	retry_interval_seconds: int
	is_active: bool
	version: str
	created_at: datetime
	device_type: DeviceTypeResponse
	
	class Config:
		from_attributes = True

# Job Category Schemas
class JobCategoryCreate(BaseModel):
	category_name: str
	description: Optional[str] = None
	color_code: Optional[str] = None

class JobCategoryUpdate(BaseModel):
	category_name: Optional[str] = None
	description: Optional[str] = None
	color_code: Optional[str] = None
	is_active: Optional[bool] = None

class JobCategoryResponse(BaseModel):
	id: int
	category_name: str
	description: Optional[str]
	color_code: Optional[str]
	is_active: bool
	created_at: datetime
	
	class Config:
		from_attributes = True

# Job Schedule Policy Schemas
class JobSchedulePolicyCreate(BaseModel):
	policy_name: str
	device_type_id: Optional[int] = None
	template_id: int
	job_category_id: Optional[int] = None
	cron_expression: str
	backup_path: str
	sftp_server_ip: Optional[str] = None
	sftp_username: Optional[str] = None
	sftp_password: Optional[str] = None
	sftp_port: int = 22
	retention_days: int = 30
	compression_enabled: bool = True
	encryption_enabled: bool = False
	notification_enabled: bool = True
	notification_emails: Optional[List[str]] = None

class JobSchedulePolicyUpdate(BaseModel):
	policy_name: Optional[str] = None
	device_type_id: Optional[int] = None
	template_id: Optional[int] = None
	job_category_id: Optional[int] = None
	cron_expression: Optional[str] = None
	backup_path: Optional[str] = None
	sftp_server_ip: Optional[str] = None
	sftp_username: Optional[str] = None
	sftp_password: Optional[str] = None
	sftp_port: Optional[int] = None
	retention_days: Optional[int] = None
	compression_enabled: Optional[bool] = None
	encryption_enabled: Optional[bool] = None
	notification_enabled: Optional[bool] = None
	notification_emails: Optional[List[str]] = None
	is_active: Optional[bool] = None

class JobSchedulePolicyResponse(BaseModel):
	id: int
	policy_name: str
	device_type_id: Optional[int]
	template_id: int
	job_category_id: Optional[int]
	cron_expression: str
	backup_path: str
	sftp_server_ip: Optional[str]
	sftp_username: Optional[str]
	sftp_port: int
	retention_days: int
	compression_enabled: bool
	encryption_enabled: bool
	notification_enabled: bool
	notification_emails: Optional[List[str]]
	is_active: bool
	created_at: datetime
	template: BackupCommandTemplateResponse
	job_category: Optional[JobCategoryResponse]
	
	class Config:
		from_attributes = True

# Device Backup Info Schemas
class DeviceBackupInfoResponse(BaseModel):
	id: int
	device_id: int
	schedule_policy_id: int
	job_status: str
	backup_start_time: Optional[datetime]
	backup_end_time: Optional[datetime]
	backup_file_path: Optional[str]
	backup_file_size_mb: Optional[float]
	error_message: Optional[str]
	retry_count: int
	next_retry_time: Optional[datetime]
	execution_log: Optional[dict]
	created_at: datetime
	device: NetworkDeviceResponse
	schedule_policy: JobSchedulePolicyResponse
	
	class Config:
		from_attributes = True

# Test Connection Schema
class TestConnectionRequest(BaseModel):
	device_id: int

class TestConnectionResponse(BaseModel):
	success: bool
	message: str
	connection_time: Optional[float] = None
	device_info: Optional[dict] = None

# Backup Job Execution Schema
class BackupJobRequest(BaseModel):
	device_id: int
	template_id: Optional[int] = None
	
class BackupJobResponse(BaseModel):
	job_id: int
	status: str
	message: str

# Dashboard Statistics
class DashboardStats(BaseModel):
	total_devices: int
	active_devices: int
	total_backups_today: int
	successful_backups_today: int
	failed_backups_today: int
	pending_jobs: int
	running_jobs: int
	
# Generic Response
class MessageResponse(BaseModel):
	message: str
	success: bool = True