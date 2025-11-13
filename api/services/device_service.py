from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, or_, desc
from typing import List, Optional
from uuid import uuid4
import asyncio
import subprocess
import time
from datetime import datetime

from ..models.device_models import NetworkInventoryDevice, DeviceType
from ..schemas.device_schemas import NetworkDeviceCreate, NetworkDeviceUpdate, ConnectionTestResponse

class DeviceService:
    
    @staticmethod
    def get_all_devices(
        db: Session, 
        skip: int = 0, 
        limit: int = 100,
        active_only: bool = True,
        location_filter: Optional[str] = None,
        device_type_filter: Optional[int] = None
    ) -> tuple[List[NetworkInventoryDevice], int, int, int]:
        """Get all devices with optional filtering"""
        
        query = db.query(NetworkInventoryDevice).options(
            joinedload(NetworkInventoryDevice.device_type)
        )
        
        # Apply filters
        filters = []
        if active_only:
            filters.append(NetworkInventoryDevice.is_active == True)
        if location_filter:
            filters.append(NetworkInventoryDevice.location.ilike(f"%{location_filter}%"))
        if device_type_filter:
            filters.append(NetworkInventoryDevice.device_type_id == device_type_filter)
            
        if filters:
            query = query.filter(and_(*filters))
        
        # Get total count
        total_count = query.count()
        
        # Get active and offline counts
        active_count = db.query(NetworkInventoryDevice).filter(
            NetworkInventoryDevice.is_active == True
        ).count()
        
        offline_count = db.query(NetworkInventoryDevice).filter(
            and_(
                NetworkInventoryDevice.is_active == True,
                or_(
                    NetworkInventoryDevice.connection_status == "offline",
                    NetworkInventoryDevice.connection_status == "error"
                )
            )
        ).count()
        
        # Get paginated results
        devices = query.order_by(
            NetworkInventoryDevice.location,
            NetworkInventoryDevice.device_name
        ).offset(skip).limit(limit).all()
        
        return devices, total_count, active_count, offline_count
    
    @staticmethod
    def get_device_by_id(db: Session, device_id: str) -> Optional[NetworkInventoryDevice]:
        """Get device by ID with device type information"""
        return db.query(NetworkInventoryDevice).options(
            joinedload(NetworkInventoryDevice.device_type)
        ).filter(NetworkInventoryDevice.device_id == device_id).first()
    
    @staticmethod
    def create_device(db: Session, device: NetworkDeviceCreate, created_by: int) -> NetworkInventoryDevice:
        """Create new network device"""
        
        # Generate UUID for device_id
        device_id = str(uuid4())
        
        db_device = NetworkInventoryDevice(
            device_id=device_id,
            device_name=device.device_name,
            device_type_id=device.device_type_id,
            ip_address=device.ip_address,
            hostname=device.hostname,
            location=device.location,
            description=device.description,
            ssh_port=device.ssh_port,
            ssh_username=device.ssh_username,
            ssh_password=device.ssh_password,  # TODO: Encrypt in production
            enable_password=device.enable_password,  # TODO: Encrypt in production
            ssh_key_path=device.ssh_key_path,
            snmp_community=device.snmp_community,
            snmp_version=device.snmp_version,
            management_vlan=device.management_vlan,
            created_by=created_by,
            connection_status="unknown"
        )
        
        db.add(db_device)
        db.commit()
        db.refresh(db_device)
        
        return db_device
    
    @staticmethod
    def update_device(
        db: Session, 
        device_id: str, 
        device_update: NetworkDeviceUpdate
    ) -> Optional[NetworkInventoryDevice]:
        """Update existing device"""
        
        db_device = DeviceService.get_device_by_id(db, device_id)
        if not db_device:
            return None
        
        # Update only provided fields
        update_data = device_update.dict(exclude_unset=True)
        for field, value in update_data.items():
            setattr(db_device, field, value)
        
        db_device.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(db_device)
        
        return db_device
    
    @staticmethod
    def delete_device(db: Session, device_id: str) -> bool:
        """Soft delete device (set is_active = False)"""
        
        db_device = DeviceService.get_device_by_id(db, device_id)
        if not db_device:
            return False
        
        db_device.is_active = False
        db_device.updated_at = datetime.utcnow()
        db.commit()
        
        return True
    
    @staticmethod
    async def test_device_connection(db: Session, device_id: str) -> ConnectionTestResponse:
        """Test SSH/ping connectivity to device"""
        
        device = DeviceService.get_device_by_id(db, device_id)
        if not device:
            return ConnectionTestResponse(
                device_id=device_id,
                device_name="Unknown",
                ip_address="Unknown",
                connection_status="error",
                error_message="Device not found",
                tested_at=datetime.utcnow()
            )
        
        start_time = time.time()
        
        try:
            # Test ping connectivity first
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', device.ip_address],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            response_time_ms = (time.time() - start_time) * 1000
            
            if ping_result.returncode == 0:
                connection_status = "online"
                error_message = None
            else:
                connection_status = "offline"
                error_message = "Ping timeout or unreachable"
            
        except subprocess.TimeoutExpired:
            connection_status = "offline"
            error_message = "Connection timeout"
            response_time_ms = None
        except Exception as e:
            connection_status = "error"
            error_message = str(e)
            response_time_ms = None
        
        # Update device connection status in database
        device.connection_status = connection_status
        device.last_connection_test = datetime.utcnow()
        db.commit()
        
        return ConnectionTestResponse(
            device_id=device.device_id,
            device_name=device.device_name,
            ip_address=device.ip_address,
            connection_status=connection_status,
            response_time_ms=response_time_ms,
            error_message=error_message,
            tested_at=datetime.utcnow()
        )
    
    @staticmethod
    def get_devices_by_location(db: Session, location: str) -> List[NetworkInventoryDevice]:
        """Get all devices in a specific location"""
        return db.query(NetworkInventoryDevice).options(
            joinedload(NetworkInventoryDevice.device_type)
        ).filter(
            and_(
                NetworkInventoryDevice.location.ilike(f"%{location}%"),
                NetworkInventoryDevice.is_active == True
            )
        ).all()
    
    @staticmethod
    def get_device_types(db: Session) -> List[DeviceType]:
        """Get all active device types"""
        return db.query(DeviceType).filter(DeviceType.is_active == True).all()