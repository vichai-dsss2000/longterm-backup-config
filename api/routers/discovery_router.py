"""
Network Discovery Router
=======================

Handles network device discovery, scanning, and inventory management.
Integrates with scripts/device_discovery.py for network discovery operations.
"""

import logging
from typing import List, Optional, Dict, Any
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import and_

from database import get_db, NetworkDevice, DeviceType
from schemas import NetworkDeviceCreate, MessageResponse
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.device_discovery import (
    DeviceDiscoveryManager, DiscoveredDevice, DiscoveryMethod
)
from scripts.error_handling import error_manager

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize discovery manager
discovery_manager = DeviceDiscoveryManager()


@router.post("/scan/network")
async def scan_network_range(
    network_range: str,
    discovery_methods: List[str] = ["ping", "snmp"],
    snmp_community: Optional[str] = "public",
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    timeout: int = 5,
    background_tasks: BackgroundTasks = None,
    current_user = Depends(get_current_user)
):
    """Scan a network range for devices."""
    try:
        # Validate network range
        try:
            network = IPv4Network(network_range, strict=False)
        except AddressValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid network range: {network_range}"
            )
        
        # Validate discovery methods
        valid_methods = ["ping", "snmp", "ssh"]
        invalid_methods = [method for method in discovery_methods if method not in valid_methods]
        if invalid_methods:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid discovery methods: {invalid_methods}. Valid methods: {valid_methods}"
            )
        
        # Limit network size for safety
        if network.num_addresses > 1024:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Network range too large. Maximum 1024 addresses allowed."
            )
        
        def run_network_scan():
            """Background task for network scanning."""
            try:
                logger.info(f"Starting network scan of {network_range}")
                
                discovered_devices = []
                scan_results = {
                    'network_range': network_range,
                    'methods_used': discovery_methods,
                    'total_addresses': network.num_addresses,
                    'discovered_devices': [],
                    'scan_errors': []
                }
                
                # Convert network to list of IP addresses
                ip_addresses = [str(ip) for ip in network.hosts()] if network.num_addresses > 2 else [str(network.network_address)]
                
                # Run discovery for each method
                for method in discovery_methods:
                    try:
                        if method == "ping":
                            # Ping scan
                            ping_results = discovery_manager.ping_discovery.discover_devices(
                                ip_addresses, timeout=timeout
                            )
                            for result in ping_results:
                                if result.is_reachable:
                                    discovered_devices.append(DiscoveredDevice(
                                        ip_address=result.ip_address,
                                        hostname=result.hostname,
                                        response_time=result.response_time,
                                        discovery_method=DiscoveryMethod.PING,
                                        device_info={"ping_response_time": result.response_time}
                                    ))
                        
                        elif method == "snmp" and snmp_community:
                            # SNMP scan
                            try:
                                snmp_results = discovery_manager.snmp_discovery.discover_devices(
                                    ip_addresses, community=snmp_community, timeout=timeout
                                )
                                for result in snmp_results:
                                    discovered_devices.append(DiscoveredDevice(
                                        ip_address=result.ip_address,
                                        hostname=result.hostname,
                                        vendor=result.vendor,
                                        model=result.model,
                                        system_description=result.system_description,
                                        discovery_method=DiscoveryMethod.SNMP,
                                        device_info=result.device_info or {}
                                    ))
                            except Exception as snmp_error:
                                logger.warning(f"SNMP discovery failed: {snmp_error}")
                                scan_results['scan_errors'].append(f"SNMP: {str(snmp_error)}")
                        
                        elif method == "ssh" and ssh_username:
                            # SSH scan (limited to responsive IPs from ping)
                            responsive_ips = [d.ip_address for d in discovered_devices 
                                            if d.discovery_method == DiscoveryMethod.PING]
                            
                            if responsive_ips:
                                try:
                                    ssh_results = discovery_manager.ssh_discovery.discover_devices(
                                        responsive_ips,
                                        username=ssh_username,
                                        password=ssh_password,
                                        timeout=timeout
                                    )
                                    for result in ssh_results:
                                        # Update existing device or add new
                                        existing_device = next(
                                            (d for d in discovered_devices if d.ip_address == result.ip_address),
                                            None
                                        )
                                        if existing_device:
                                            existing_device.vendor = result.vendor or existing_device.vendor
                                            existing_device.model = result.model or existing_device.model
                                            existing_device.os_version = result.os_version
                                            existing_device.device_info.update(result.device_info or {})
                                        else:
                                            discovered_devices.append(result)
                                
                                except Exception as ssh_error:
                                    logger.warning(f"SSH discovery failed: {ssh_error}")
                                    scan_results['scan_errors'].append(f"SSH: {str(ssh_error)}")
                    
                    except Exception as method_error:
                        logger.error(f"Discovery method {method} failed: {method_error}")
                        scan_results['scan_errors'].append(f"{method}: {str(method_error)}")
                
                # Format results
                scan_results['discovered_devices'] = [
                    {
                        'ip_address': device.ip_address,
                        'hostname': device.hostname,
                        'vendor': device.vendor,
                        'model': device.model,
                        'os_version': device.os_version,
                        'system_description': device.system_description,
                        'response_time': device.response_time,
                        'discovery_method': device.discovery_method.value if device.discovery_method else None,
                        'device_info': device.device_info,
                        'confidence_score': device.confidence_score
                    }
                    for device in discovered_devices
                ]
                
                scan_results['total_discovered'] = len(discovered_devices)
                scan_results['discovery_rate'] = (len(discovered_devices) / network.num_addresses * 100) if network.num_addresses > 0 else 0
                
                logger.info(f"Network scan completed: {len(discovered_devices)} devices discovered from {network.num_addresses} addresses")
                
                return scan_results
                
            except Exception as e:
                logger.error(f"Network scan failed: {e}")
                error_manager.log_error(
                    category="NETWORK_DISCOVERY",
                    message=f"Network scan failed for {network_range}",
                    details={'error': str(e), 'network_range': network_range}
                )
                return {'error': str(e)}
        
        if background_tasks:
            background_tasks.add_task(run_network_scan)
            return MessageResponse(
                message=f"Network scan started for {network_range}. Check logs for results."
            )
        else:
            # Run synchronously (for smaller networks)
            if network.num_addresses <= 64:
                return run_network_scan()
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Network range too large for synchronous scan. Use background task parameter."
                )
    
    except Exception as e:
        logger.error(f"Network scan request failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Network scan failed: {str(e)}"
        )


@router.post("/scan/single")
async def scan_single_device(
    ip_address: str,
    discovery_methods: List[str] = ["ping", "snmp"],
    snmp_community: Optional[str] = "public",
    ssh_username: Optional[str] = None,
    ssh_password: Optional[str] = None,
    timeout: int = 10,
    current_user = Depends(get_current_user)
):
    """Discover information about a single device."""
    try:
        # Validate IP address
        try:
            IPv4Address(ip_address)
        except AddressValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid IP address: {ip_address}"
            )
        
        discovered_device = None
        discovery_results = {
            'ip_address': ip_address,
            'discovery_methods': discovery_methods,
            'device_info': {},
            'errors': []
        }
        
        # Try each discovery method
        for method in discovery_methods:
            try:
                if method == "ping":
                    ping_results = discovery_manager.ping_discovery.discover_devices(
                        [ip_address], timeout=timeout
                    )
                    if ping_results and ping_results[0].is_reachable:
                        result = ping_results[0]
                        discovered_device = DiscoveredDevice(
                            ip_address=result.ip_address,
                            hostname=result.hostname,
                            response_time=result.response_time,
                            discovery_method=DiscoveryMethod.PING,
                            device_info={"ping_response_time": result.response_time}
                        )
                        discovery_results['device_info']['ping'] = {
                            'reachable': True,
                            'hostname': result.hostname,
                            'response_time': result.response_time
                        }
                    else:
                        discovery_results['device_info']['ping'] = {'reachable': False}
                
                elif method == "snmp" and snmp_community:
                    snmp_results = discovery_manager.snmp_discovery.discover_devices(
                        [ip_address], community=snmp_community, timeout=timeout
                    )
                    if snmp_results:
                        result = snmp_results[0]
                        if discovered_device:
                            discovered_device.vendor = result.vendor
                            discovered_device.model = result.model
                            discovered_device.system_description = result.system_description
                            discovered_device.device_info.update(result.device_info or {})
                        else:
                            discovered_device = result
                        
                        discovery_results['device_info']['snmp'] = {
                            'vendor': result.vendor,
                            'model': result.model,
                            'system_description': result.system_description,
                            'device_info': result.device_info
                        }
                    else:
                        discovery_results['device_info']['snmp'] = {'accessible': False}
                
                elif method == "ssh" and ssh_username:
                    ssh_results = discovery_manager.ssh_discovery.discover_devices(
                        [ip_address],
                        username=ssh_username,
                        password=ssh_password,
                        timeout=timeout
                    )
                    if ssh_results:
                        result = ssh_results[0]
                        if discovered_device:
                            discovered_device.vendor = result.vendor or discovered_device.vendor
                            discovered_device.model = result.model or discovered_device.model
                            discovered_device.os_version = result.os_version
                            discovered_device.device_info.update(result.device_info or {})
                        else:
                            discovered_device = result
                        
                        discovery_results['device_info']['ssh'] = {
                            'vendor': result.vendor,
                            'model': result.model,
                            'os_version': result.os_version,
                            'device_info': result.device_info
                        }
                    else:
                        discovery_results['device_info']['ssh'] = {'accessible': False}
            
            except Exception as method_error:
                logger.warning(f"Discovery method {method} failed for {ip_address}: {method_error}")
                discovery_results['errors'].append(f"{method}: {str(method_error)}")
        
        # Format final result
        if discovered_device:
            discovery_results['discovered_device'] = {
                'ip_address': discovered_device.ip_address,
                'hostname': discovered_device.hostname,
                'vendor': discovered_device.vendor,
                'model': discovered_device.model,
                'os_version': discovered_device.os_version,
                'system_description': discovered_device.system_description,
                'response_time': discovered_device.response_time,
                'discovery_method': discovered_device.discovery_method.value if discovered_device.discovery_method else None,
                'device_info': discovered_device.device_info,
                'confidence_score': discovered_device.confidence_score
            }
            discovery_results['status'] = 'discovered'
        else:
            discovery_results['status'] = 'not_found'
        
        return discovery_results
    
    except Exception as e:
        logger.error(f"Single device discovery failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Device discovery failed: {str(e)}"
        )


@router.post("/import")
async def import_discovered_devices(
    discovered_devices: List[Dict[str, Any]],
    auto_assign_device_types: bool = True,
    create_missing_device_types: bool = False,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Import discovered devices into the inventory."""
    if len(discovered_devices) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 devices allowed for import"
        )
    
    import_results = {
        'total_devices': len(discovered_devices),
        'imported_devices': [],
        'skipped_devices': [],
        'errors': []
    }
    
    for device_data in discovered_devices:
        try:
            ip_address = device_data.get('ip_address')
            if not ip_address:
                import_results['errors'].append("Missing IP address")
                continue
            
            # Check if device already exists
            existing_device = db.query(NetworkDevice).filter(
                NetworkDevice.ip_address == ip_address
            ).first()
            
            if existing_device:
                import_results['skipped_devices'].append({
                    'ip_address': ip_address,
                    'reason': 'Device already exists',
                    'existing_id': existing_device.id
                })
                continue
            
            # Determine device type
            device_type = None
            if auto_assign_device_types:
                vendor = device_data.get('vendor', '').lower()
                model = device_data.get('model', '').lower()
                
                if vendor and model:
                    # Try to find matching device type
                    device_type = db.query(DeviceType).filter(
                        and_(
                            DeviceType.vendor.ilike(f"%{vendor}%"),
                            DeviceType.model.ilike(f"%{model}%")
                        )
                    ).first()
                    
                    # Create device type if not found and allowed
                    if not device_type and create_missing_device_types:
                        # Determine netmiko device type
                        netmiko_type = "generic_termserver"  # Default
                        if "cisco" in vendor:
                            netmiko_type = "cisco_ios"
                        elif "juniper" in vendor:
                            netmiko_type = "juniper_junos"
                        elif "mikrotik" in vendor:
                            netmiko_type = "mikrotik_routeros"
                        
                        device_type = DeviceType(
                            vendor=vendor.title(),
                            model=model.title(),
                            device_category="Network Device",
                            netmiko_device_type=netmiko_type,
                            description=f"Auto-created from discovery: {vendor} {model}"
                        )
                        db.add(device_type)
                        db.commit()
                        db.refresh(device_type)
            
            if not device_type:
                # Use default device type or skip
                device_type = db.query(DeviceType).filter(
                    DeviceType.netmiko_device_type == "generic_termserver"
                ).first()
                
                if not device_type:
                    import_results['errors'].append(f"No suitable device type found for {ip_address}")
                    continue
            
            # Create device
            device_name = device_data.get('hostname') or f"device-{ip_address.replace('.', '-')}"
            
            new_device = NetworkDevice(
                device_name=device_name,
                ip_address=ip_address,
                device_type_id=device_type.id,
                hostname=device_data.get('hostname'),
                description=f"Imported from discovery: {device_data.get('system_description', '')}"
            )
            
            db.add(new_device)
            db.commit()
            db.refresh(new_device)
            
            import_results['imported_devices'].append({
                'id': new_device.id,
                'device_name': new_device.device_name,
                'ip_address': new_device.ip_address,
                'device_type': {
                    'vendor': device_type.vendor,
                    'model': device_type.model
                }
            })
            
            logger.info(f"Imported discovered device: {device_name} ({ip_address})")
        
        except Exception as device_error:
            logger.error(f"Failed to import device {device_data.get('ip_address', 'unknown')}: {device_error}")
            import_results['errors'].append(f"Import failed for {device_data.get('ip_address', 'unknown')}: {str(device_error)}")
    
    import_results['imported_count'] = len(import_results['imported_devices'])
    import_results['skipped_count'] = len(import_results['skipped_devices'])
    import_results['error_count'] = len(import_results['errors'])
    
    return import_results


@router.get("/device-types/suggestions")
async def suggest_device_types(
    vendor: Optional[str] = None,
    model: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get device type suggestions based on vendor/model."""
    query = db.query(DeviceType).filter(DeviceType.is_active == True)
    
    if vendor:
        query = query.filter(DeviceType.vendor.ilike(f"%{vendor}%"))
    
    if model:
        query = query.filter(DeviceType.model.ilike(f"%{model}%"))
    
    device_types = query.limit(20).all()
    
    return {
        'suggestions': [
            {
                'id': dt.id,
                'vendor': dt.vendor,
                'model': dt.model,
                'firmware_version': dt.firmware_version,
                'netmiko_device_type': dt.netmiko_device_type,
                'description': dt.description
            }
            for dt in device_types
        ],
        'total_suggestions': len(device_types)
    }


@router.get("/scan/history")
async def get_discovery_history(
    days_back: int = 7,
    current_user = Depends(get_current_user)
):
    """Get discovery scan history."""
    # This would typically read from a discovery history table
    # For now, return recent error logs related to discovery
    try:
        from datetime import timedelta
        
        time_window = timedelta(days=days_back)
        discovery_errors = error_manager.get_errors_by_category("NETWORK_DISCOVERY", time_window)
        
        return {
            'discovery_history': [
                {
                    'timestamp': error.timestamp.isoformat(),
                    'message': error.message,
                    'details': error.details,
                    'count': error.count
                }
                for error in discovery_errors
            ],
            'days_back': days_back,
            'total_entries': len(discovery_errors)
        }
    
    except Exception as e:
        logger.error(f"Failed to get discovery history: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get discovery history: {str(e)}"
        )