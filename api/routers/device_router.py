"""
Device Management Router
=======================

Handles network device CRUD operations, connection testing, and device management.
Integrates with scripts/ssh_connection.py for connection testing and validation.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_

from database import get_db, NetworkDevice, DeviceType, DeviceBackupInfo
from schemas import (
    NetworkDeviceCreate, NetworkDeviceUpdate, NetworkDeviceResponse,
    TestConnectionRequest, TestConnectionResponse, MessageResponse
)
from auth import get_current_user, get_admin_user
from config import settings

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.ssh_connection import SSHConnectionManager, create_device_credentials
from scripts.error_handling import error_manager
from cryptography.fernet import Fernet
import base64
import os

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize SSH manager for connection testing
ssh_manager = SSHConnectionManager()

# Encryption key for sensitive data (should be from environment in production)
def get_encryption_key():
    """Get or create encryption key for sensitive data."""
    key = os.environ.get('DEVICE_ENCRYPTION_KEY')
    if not key:
        key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        logger.warning("Using temporary encryption key. Set DEVICE_ENCRYPTION_KEY environment variable.")
    return key

def encrypt_password(password: str) -> str:
    """Encrypt password for storage."""
    if not password:
        return ""
    
    key = get_encryption_key()
    f = Fernet(key.encode())
    return f.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt password from storage."""
    if not encrypted_password:
        return ""
    
    try:
        key = get_encryption_key()
        f = Fernet(key.encode())
        return f.decrypt(encrypted_password.encode()).decode()
    except Exception as e:
        logger.error(f"Failed to decrypt password: {e}")
        return ""


@router.get("/", response_model=List[NetworkDeviceResponse])
async def get_devices(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    device_type_id: Optional[int] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of network devices with filtering options."""
    query = db.query(NetworkDevice).options(joinedload(NetworkDevice.device_type))
    
    # Apply filters
    if active_only:
        query = query.filter(NetworkDevice.is_active == True)
    
    if device_type_id:
        query = query.filter(NetworkDevice.device_type_id == device_type_id)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            and_(
                NetworkDevice.device_name.ilike(search_term) |
                NetworkDevice.ip_address.ilike(search_term) |
                NetworkDevice.hostname.ilike(search_term) |
                NetworkDevice.location.ilike(search_term)
            )
        )
    
    devices = query.offset(skip).limit(limit).all()
    
    return [
        NetworkDeviceResponse(
            **{key: getattr(device, key) for key in NetworkDeviceResponse.__annotations__.keys() if hasattr(device, key)}
        )
        for device in devices
    ]


@router.post("/", response_model=NetworkDeviceResponse)
async def create_device(
    device_data: NetworkDeviceCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Create a new network device."""
    # Check if device with same name or IP already exists
    existing_device = db.query(NetworkDevice).filter(
        and_(
            NetworkDevice.device_name == device_data.device_name,
            NetworkDevice.ip_address == device_data.ip_address
        )
    ).first()
    
    if existing_device:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device with same name and IP address already exists"
        )
    
    # Verify device type exists
    device_type = db.query(DeviceType).filter(DeviceType.id == device_data.device_type_id).first()
    if not device_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device type not found"
        )
    
    # Encrypt passwords if provided
    ssh_password_encrypted = encrypt_password(device_data.ssh_password) if device_data.ssh_password else None
    enable_password_encrypted = encrypt_password(device_data.enable_password) if device_data.enable_password else None
    
    # Create device
    new_device = NetworkDevice(
        device_name=device_data.device_name,
        ip_address=device_data.ip_address,
        device_type_id=device_data.device_type_id,
        hostname=device_data.hostname,
        location=device_data.location,
        management_ip=device_data.management_ip,
        snmp_community=device_data.snmp_community,
        ssh_username=device_data.ssh_username,
        ssh_password_encrypted=ssh_password_encrypted,
        ssh_key_file=device_data.ssh_key_file,
        ssh_port=device_data.ssh_port,
        enable_password_encrypted=enable_password_encrypted,
        description=device_data.description
    )
    
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    
    logger.info(f"Created new device: {new_device.device_name} ({new_device.ip_address})")
    
    return NetworkDeviceResponse(
        **{key: getattr(new_device, key) for key in NetworkDeviceResponse.__annotations__.keys() if hasattr(new_device, key)}
    )


@router.get("/{device_id}", response_model=NetworkDeviceResponse)
async def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific device by ID."""
    device = db.query(NetworkDevice).options(joinedload(NetworkDevice.device_type)).filter(
        NetworkDevice.id == device_id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    return NetworkDeviceResponse(
        **{key: getattr(device, key) for key in NetworkDeviceResponse.__annotations__.keys() if hasattr(device, key)}
    )


@router.put("/{device_id}", response_model=NetworkDeviceResponse)
async def update_device(
    device_id: int,
    device_data: NetworkDeviceUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Update existing device."""
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Check for conflicts if name or IP is being changed
    if device_data.device_name or device_data.ip_address:
        conflict_query = db.query(NetworkDevice).filter(NetworkDevice.id != device_id)
        
        if device_data.device_name:
            device_name = device_data.device_name
        else:
            device_name = device.device_name
            
        if device_data.ip_address:
            ip_address = device_data.ip_address
        else:
            ip_address = device.ip_address
        
        existing_device = conflict_query.filter(
            and_(
                NetworkDevice.device_name == device_name,
                NetworkDevice.ip_address == ip_address
            )
        ).first()
        
        if existing_device:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Another device with same name and IP address already exists"
            )
    
    # Update device fields
    update_data = device_data.dict(exclude_unset=True)
    
    # Handle password encryption
    if 'ssh_password' in update_data and update_data['ssh_password']:
        update_data['ssh_password_encrypted'] = encrypt_password(update_data['ssh_password'])
        del update_data['ssh_password']
    
    if 'enable_password' in update_data and update_data['enable_password']:
        update_data['enable_password_encrypted'] = encrypt_password(update_data['enable_password'])
        del update_data['enable_password']
    
    for field, value in update_data.items():
        if hasattr(device, field):
            setattr(device, field, value)
    
    db.commit()
    db.refresh(device)
    
    logger.info(f"Updated device: {device.device_name} ({device.ip_address})")
    
    return NetworkDeviceResponse(
        **{key: getattr(device, key) for key in NetworkDeviceResponse.__annotations__.keys() if hasattr(device, key)}
    )


@router.delete("/{device_id}", response_model=MessageResponse)
async def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Delete device (soft delete by setting is_active=False)."""
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Soft delete
    device.is_active = False
    db.commit()
    
    logger.info(f"Soft deleted device: {device.device_name} ({device.ip_address})")
    
    return MessageResponse(message="Device deleted successfully")


@router.post("/{device_id}/test-connection", response_model=TestConnectionResponse)
async def test_device_connection(
    device_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test connection to a specific device."""
    device = db.query(NetworkDevice).options(joinedload(NetworkDevice.device_type)).filter(
        NetworkDevice.id == device_id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    try:
        # Create device credentials
        device_info = {
            'id': device.id,
            'device_name': device.device_name,
            'ip_address': device.ip_address,
            'ssh_username': device.ssh_username,
            'ssh_password_decrypted': decrypt_password(device.ssh_password_encrypted or ""),
            'ssh_key_file': device.ssh_key_file,
            'ssh_port': device.ssh_port,
            'enable_password_decrypted': decrypt_password(device.enable_password_encrypted or ""),
            'netmiko_device_type': device.device_type.netmiko_device_type
        }
        
        credentials = create_device_credentials(device_info)
        
        # Test connection
        import time
        start_time = time.time()
        connection_result = ssh_manager.test_connection(credentials)
        connection_time = time.time() - start_time
        
        if connection_result.success:
            # Update device last backup status
            device.last_backup_status = "success"
            db.commit()
            
            return TestConnectionResponse(
                success=True,
                message="Connection successful",
                connection_time=connection_time,
                device_info={
                    'device_type': connection_result.device_info.get('device_type'),
                    'hostname': connection_result.device_info.get('hostname'),
                    'version': connection_result.device_info.get('version')
                }
            )
        else:
            # Log error
            error_manager.log_error(
                category="CONNECTION_TEST",
                message=f"Connection test failed for device {device.device_name}",
                details={
                    'device_id': device.id,
                    'ip_address': device.ip_address,
                    'error': connection_result.error_message
                }
            )
            
            return TestConnectionResponse(
                success=False,
                message=connection_result.error_message or "Connection failed",
                connection_time=connection_time
            )
    
    except Exception as e:
        logger.error(f"Connection test failed for device {device_id}: {e}")
        
        # Log error
        error_manager.log_error(
            category="CONNECTION_TEST",
            message=f"Connection test exception for device {device.device_name}",
            details={
                'device_id': device.id,
                'error': str(e)
            }
        )
        
        return TestConnectionResponse(
            success=False,
            message=f"Connection test failed: {str(e)}"
        )


@router.get("/{device_id}/backup-history")
async def get_device_backup_history(
    device_id: int,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get backup history for specific device."""
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    backup_history = db.query(DeviceBackupInfo).filter(
        DeviceBackupInfo.device_id == device_id
    ).order_by(DeviceBackupInfo.created_at.desc()).limit(limit).all()
    
    return {
        "device_id": device_id,
        "device_name": device.device_name,
        "backup_count": len(backup_history),
        "backups": [
            {
                "id": backup.id,
                "job_status": backup.job_status.value if backup.job_status else None,
                "backup_start_time": backup.backup_start_time,
                "backup_end_time": backup.backup_end_time,
                "backup_file_path": backup.backup_file_path,
                "backup_file_size_mb": float(backup.backup_file_size_mb) if backup.backup_file_size_mb else None,
                "error_message": backup.error_message,
                "retry_count": backup.retry_count,
                "created_at": backup.created_at
            }
            for backup in backup_history
        ]
    }


@router.post("/bulk-test")
async def bulk_test_connections(
    device_ids: List[int],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test connections to multiple devices."""
    if len(device_ids) > 50:  # Limit bulk operations
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 devices allowed for bulk testing"
        )
    
    devices = db.query(NetworkDevice).options(joinedload(NetworkDevice.device_type)).filter(
        NetworkDevice.id.in_(device_ids)
    ).all()
    
    if len(devices) != len(device_ids):
        found_ids = [d.id for d in devices]
        missing_ids = [did for did in device_ids if did not in found_ids]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Devices not found: {missing_ids}"
        )
    
    # Add bulk test task to background
    def run_bulk_test():
        """Background task for bulk connection testing."""
        results = []
        for device in devices:
            try:
                device_info = {
                    'id': device.id,
                    'device_name': device.device_name,
                    'ip_address': device.ip_address,
                    'ssh_username': device.ssh_username,
                    'ssh_password_decrypted': decrypt_password(device.ssh_password_encrypted or ""),
                    'ssh_key_file': device.ssh_key_file,
                    'ssh_port': device.ssh_port,
                    'enable_password_decrypted': decrypt_password(device.enable_password_encrypted or ""),
                    'netmiko_device_type': device.device_type.netmiko_device_type
                }
                
                credentials = create_device_credentials(device_info)
                connection_result = ssh_manager.test_connection(credentials)
                
                results.append({
                    'device_id': device.id,
                    'device_name': device.device_name,
                    'success': connection_result.success,
                    'message': connection_result.error_message if not connection_result.success else "Success"
                })
                
            except Exception as e:
                results.append({
                    'device_id': device.id,
                    'device_name': device.device_name,
                    'success': False,
                    'message': str(e)
                })
        
        logger.info(f"Bulk connection test completed for {len(device_ids)} devices")
        return results
    
    background_tasks.add_task(run_bulk_test)
    
    return MessageResponse(
        message=f"Bulk connection test started for {len(device_ids)} devices. Check logs for results."
    )