from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from ..database import get_db
from ..auth.jwt_handler import get_current_user
from ..schemas.device_schemas import (
    NetworkDeviceResponse, NetworkDeviceCreate, NetworkDeviceUpdate,
    DeviceListResponse, DeviceTypeResponse, ConnectionTestResponse
)
from ..services.device_service import DeviceService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter()

@router.get("/devices", response_model=DeviceListResponse, tags=["devices"])
async def get_all_devices(
    skip: int = Query(0, ge=0, description="Number of devices to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of devices to return"),
    active_only: bool = Query(True, description="Filter only active devices"),
    location: Optional[str] = Query(None, description="Filter by location"),
    device_type_id: Optional[int] = Query(None, description="Filter by device type ID"),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get all network devices with pagination and filtering options
    
    - **skip**: Number of devices to skip (for pagination)
    - **limit**: Maximum number of devices to return
    - **active_only**: Show only active devices
    - **location**: Filter devices by location (partial match)
    - **device_type_id**: Filter devices by device type
    """
    try:
        devices, total_count, active_count, offline_count = DeviceService.get_all_devices(
            db=db,
            skip=skip,
            limit=limit,
            active_only=active_only,
            location_filter=location,
            device_type_filter=device_type_id
        )
        
        logger.info(f"Retrieved {len(devices)} devices for user {current_user.get('user_id')}")
        
        return DeviceListResponse(
            devices=[NetworkDeviceResponse.from_orm(device) for device in devices],
            total_count=total_count,
            active_count=active_count,
            offline_count=offline_count
        )
        
    except Exception as e:
        logger.error(f"Error retrieving devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error retrieving devices")

@router.get("/network-devices", response_model=DeviceListResponse, tags=["devices"])
async def get_network_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    location: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Alias endpoint for /devices - Get network inventory devices
    """
    return await get_all_devices(
        skip=skip, 
        limit=limit, 
        active_only=True,
        location=location,
        device_type_id=None,
        db=db, 
        current_user=current_user
    )

@router.get("/inventory/devices", response_model=DeviceListResponse, tags=["inventory"])
async def get_inventory_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    include_inactive: bool = Query(False, description="Include inactive devices"),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """
    Get devices from network inventory with extended options
    """
    try:
        devices, total_count, active_count, offline_count = DeviceService.get_all_devices(
            db=db,
            skip=skip,
            limit=limit,
            active_only=not include_inactive
        )
        
        return DeviceListResponse(
            devices=[NetworkDeviceResponse.from_orm(device) for device in devices],
            total_count=total_count,
            active_count=active_count,
            offline_count=offline_count
        )
        
    except Exception as e:
        logger.error(f"Error retrieving inventory devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error retrieving inventory")

@router.get("/devices/{device_id}", response_model=NetworkDeviceResponse, tags=["devices"])
async def get_device_by_id(
    device_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get a specific device by ID"""
    
    device = DeviceService.get_device_by_id(db, device_id)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    
    logger.info(f"Retrieved device {device_id} for user {current_user.get('user_id')}")
    return NetworkDeviceResponse.from_orm(device)

@router.post("/devices", response_model=NetworkDeviceResponse, status_code=201, tags=["devices"])
async def create_device(
    device: NetworkDeviceCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Create a new network device"""
    
    try:
        # Check if device type exists
        device_types = DeviceService.get_device_types(db)
        if not any(dt.device_type_id == device.device_type_id for dt in device_types):
            raise HTTPException(status_code=400, detail="Invalid device type ID")
        
        # Check for duplicate IP address
        existing_device = db.query(NetworkInventoryDevice).filter(
            NetworkInventoryDevice.ip_address == device.ip_address
        ).first()
        if existing_device:
            raise HTTPException(status_code=400, detail="Device with this IP address already exists")
        
        created_device = DeviceService.create_device(
            db=db, 
            device=device, 
            created_by=current_user.get('user_id')
        )
        
        logger.info(f"Created device {created_device.device_id} by user {current_user.get('user_id')}")
        return NetworkDeviceResponse.from_orm(created_device)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating device: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error creating device")

@router.put("/devices/{device_id}", response_model=NetworkDeviceResponse, tags=["devices"])
async def update_device(
    device_id: str,
    device_update: NetworkDeviceUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Update an existing device"""
    
    try:
        updated_device = DeviceService.update_device(db, device_id, device_update)
        if not updated_device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        logger.info(f"Updated device {device_id} by user {current_user.get('user_id')}")
        return NetworkDeviceResponse.from_orm(updated_device)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating device {device_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error updating device")

@router.delete("/devices/{device_id}", status_code=204, tags=["devices"])
async def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Soft delete a device (sets is_active = False)"""
    
    success = DeviceService.delete_device(db, device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")
    
    logger.info(f"Deleted device {device_id} by user {current_user.get('user_id')}")

@router.post("/devices/{device_id}/test-connection", response_model=ConnectionTestResponse, tags=["devices"])
async def test_device_connection(
    device_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test connectivity to a specific device"""
    
    result = await DeviceService.test_device_connection(db, device_id)
    
    logger.info(f"Connection test for device {device_id}: {result.connection_status}")
    return result

@router.get("/devices/types", response_model=List[DeviceTypeResponse], tags=["device-types"])
async def get_device_types(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all available device types"""
    
    device_types = DeviceService.get_device_types(db)
    return [DeviceTypeResponse.from_orm(dt) for dt in device_types]

@router.get("/devices/location/{location}", response_model=List[NetworkDeviceResponse], tags=["devices"])
async def get_devices_by_location(
    location: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all devices in a specific location"""
    
    devices = DeviceService.get_devices_by_location(db, location)
    return [NetworkDeviceResponse.from_orm(device) for device in devices]