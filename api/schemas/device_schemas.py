from pydantic import BaseModel, validator
from typing import Optional, List
from datetime import datetime
import ipaddress

class DeviceTypeBase(BaseModel):
    device_type_name: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    default_ssh_port: int = 22
    default_protocol: str = "ssh"

class DeviceTypeCreate(DeviceTypeBase):
    pass

class DeviceTypeResponse(DeviceTypeBase):
    device_type_id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class NetworkDeviceBase(BaseModel):
    device_name: str
    device_type_id: int
    ip_address: str
    hostname: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    ssh_port: int = 22
    ssh_username: Optional[str] = None
    management_vlan: Optional[int] = None
    
    @validator('ip_address')
    def validate_ip_address(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')

class NetworkDeviceCreate(NetworkDeviceBase):
    ssh_password: Optional[str] = None
    enable_password: Optional[str] = None
    ssh_key_path: Optional[str] = None
    snmp_community: Optional[str] = None
    snmp_version: str = "2c"

class NetworkDeviceUpdate(BaseModel):
    device_name: Optional[str] = None
    device_type_id: Optional[int] = None
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    ssh_port: Optional[int] = None
    ssh_username: Optional[str] = None
    management_vlan: Optional[int] = None
    is_active: Optional[bool] = None

class NetworkDeviceResponse(NetworkDeviceBase):
    device_id: str
    is_active: bool
    last_backup_date: Optional[datetime] = None
    last_connection_test: Optional[datetime] = None
    connection_status: str
    created_at: datetime
    updated_at: datetime
    device_type: Optional[DeviceTypeResponse] = None
    
    class Config:
        from_attributes = True

class DeviceListResponse(BaseModel):
    devices: List[NetworkDeviceResponse]
    total_count: int
    active_count: int
    offline_count: int

class ConnectionTestResponse(BaseModel):
    device_id: str
    device_name: str
    ip_address: str
    connection_status: str
    response_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    tested_at: datetime