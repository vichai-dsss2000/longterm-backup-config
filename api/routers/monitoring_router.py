"""
System Monitoring Router
=======================

Handles system health checks, monitoring, testing, and diagnostics.
Integrates with scripts/test_validation.py for comprehensive system testing.
"""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, desc

from database import (
    get_db, NetworkDevice, BackupCommandTemplate, DeviceBackupInfo,
    DeviceType, JobStatus
)
from schemas import MessageResponse
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.test_validation import (
    SystemHealthMonitor, test_runner, ConnectionTester, 
    TemplateValidator, BackupTester, StorageTester, PerformanceTester
)
from scripts.error_handling import error_manager
from scripts.file_storage import storage_manager

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize testing components
health_monitor = SystemHealthMonitor()
connection_tester = ConnectionTester()
template_validator = TemplateValidator()
backup_tester = BackupTester()
storage_tester = StorageTester()
performance_tester = PerformanceTester()


@router.get("/health/comprehensive")
async def comprehensive_health_check(
    include_devices: bool = False,
    include_templates: bool = False,
    include_storage: bool = True,
    max_devices: int = 10,
    max_templates: int = 5,
    background_tasks: BackgroundTasks = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Run comprehensive system health check."""
    try:
        devices = []
        templates = []
        storage_backends = []
        
        # Get sample devices for testing
        if include_devices:
            devices = db.query(NetworkDevice).filter(
                NetworkDevice.is_active == True
            ).limit(max_devices).all()
            
            devices = [
                {
                    'id': device.id,
                    'device_name': device.device_name,
                    'ip_address': device.ip_address,
                    'ssh_username': device.ssh_username,
                    'ssh_port': device.ssh_port
                }
                for device in devices
            ]
        
        # Get sample templates for testing
        if include_templates:
            templates = db.query(BackupCommandTemplate).filter(
                BackupCommandTemplate.is_active == True
            ).limit(max_templates).all()
            
            templates = [
                {
                    'id': template.id,
                    'template_name': template.template_name,
                    'backup_command': template.backup_command,
                    'command_format': template.command_format,
                    'template_variables': template.template_variables or {}
                }
                for template in templates
            ]
        
        # Get storage backends
        if include_storage:
            storage_backends = list(storage_manager.backends.keys())
        
        # Run comprehensive health check
        health_status = health_monitor.run_comprehensive_health_check(
            devices=devices,
            templates=templates,
            storage_backends=storage_backends
        )
        
        return {
            "comprehensive_health": {
                "overall_status": health_status.overall_status,
                "timestamp": health_status.timestamp.isoformat(),
                "component_statuses": {
                    comp_id: {
                        "status": comp_result.status.value,
                        "test_name": comp_result.test_name,
                        "duration_seconds": comp_result.duration_seconds,
                        "error_message": comp_result.error_message,
                        "warnings": comp_result.warnings,
                        "recommendations": comp_result.recommendations
                    }
                    for comp_id, comp_result in health_status.component_statuses.items()
                },
                "performance_metrics": health_status.performance_metrics,
                "resource_usage": health_status.resource_usage,
                "recommendations": health_status.recommendations
            }
        }
    
    except Exception as e:
        logger.error(f"Comprehensive health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/health/quick")
async def quick_health_check(
    current_user = Depends(get_current_user)
):
    """Run quick health check for essential components."""
    try:
        health_result = health_monitor.run_quick_health_check()
        return {
            "quick_health": health_result
        }
    
    except Exception as e:
        logger.error(f"Quick health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Quick health check failed: {str(e)}"
        )


@router.post("/test/connectivity")
async def test_device_connectivity(
    device_ids: List[int],
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test connectivity to multiple devices."""
    if len(device_ids) > 50:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 50 devices allowed for bulk connectivity testing"
        )
    
    devices = db.query(NetworkDevice).filter(
        and_(
            NetworkDevice.id.in_(device_ids),
            NetworkDevice.is_active == True
        )
    ).all()
    
    if len(devices) != len(device_ids):
        found_ids = [d.id for d in devices]
        missing_ids = [did for did in device_ids if did not in found_ids]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Devices not found or inactive: {missing_ids}"
        )
    
    def run_connectivity_tests():
        """Background task for connectivity testing."""
        results = []
        for device in devices:
            try:
                device_info = {
                    'id': device.id,
                    'device_name': device.device_name,
                    'ip_address': device.ip_address,
                    'ssh_port': device.ssh_port
                }
                
                test_result = connection_tester.test_device_connectivity(device_info)
                
                results.append({
                    'device_id': device.id,
                    'device_name': device.device_name,
                    'test_result': {
                        'status': test_result.status.value,
                        'duration_seconds': test_result.duration_seconds,
                        'error_message': test_result.error_message,
                        'warnings': test_result.warnings,
                        'recommendations': test_result.recommendations,
                        'details': test_result.details
                    }
                })
                
            except Exception as e:
                results.append({
                    'device_id': device.id,
                    'device_name': device.device_name,
                    'test_result': {
                        'status': 'failed',
                        'error_message': str(e),
                        'recommendations': ['Check device configuration and network connectivity']
                    }
                })
        
        logger.info(f"Connectivity tests completed for {len(device_ids)} devices")
        return results
    
    background_tasks.add_task(run_connectivity_tests)
    
    return MessageResponse(
        message=f"Connectivity tests started for {len(device_ids)} devices. Check logs for results."
    )


@router.post("/test/templates")
async def test_template_validation(
    template_ids: List[int],
    test_device_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Test template validation and processing."""
    if len(template_ids) > 20:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 20 templates allowed for bulk testing"
        )
    
    templates = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.id.in_(template_ids)
    ).all()
    
    if len(templates) != len(template_ids):
        found_ids = [t.id for t in templates]
        missing_ids = [tid for tid in template_ids if tid not in found_ids]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Templates not found: {missing_ids}"
        )
    
    # Get test device if specified
    test_device_info = None
    if test_device_id:
        test_device = db.query(NetworkDevice).filter(
            NetworkDevice.id == test_device_id
        ).first()
        
        if test_device:
            test_device_info = {
                'id': test_device.id,
                'device_name': test_device.device_name,
                'ip_address': test_device.ip_address,
                'hostname': test_device.hostname or test_device.device_name
            }
    
    results = []
    for template in templates:
        try:
            template_data = {
                'id': template.id,
                'template_name': template.template_name,
                'backup_command': template.backup_command,
                'command_format': template.command_format,
                'template_variables': template.template_variables or {}
            }
            
            # Test syntax validation
            syntax_result = template_validator.validate_template_syntax(template_data)
            
            result_data = {
                'template_id': template.id,
                'template_name': template.template_name,
                'syntax_validation': {
                    'status': syntax_result.status.value,
                    'duration_seconds': syntax_result.duration_seconds,
                    'error_message': syntax_result.error_message,
                    'warnings': syntax_result.warnings,
                    'recommendations': syntax_result.recommendations,
                    'details': syntax_result.details
                }
            }
            
            # Test processing if test device provided
            if test_device_info:
                processing_result = template_validator.test_template_processing(
                    template_data, test_device_info
                )
                
                result_data['processing_test'] = {
                    'status': processing_result.status.value,
                    'duration_seconds': processing_result.duration_seconds,
                    'error_message': processing_result.error_message,
                    'warnings': processing_result.warnings,
                    'recommendations': processing_result.recommendations,
                    'details': processing_result.details
                }
            
            results.append(result_data)
            
        except Exception as e:
            results.append({
                'template_id': template.id,
                'template_name': template.template_name,
                'error': str(e)
            })
    
    return {
        'template_test_results': results,
        'test_device_used': test_device_info,
        'timestamp': datetime.now(timezone.utc).isoformat()
    }


@router.post("/test/storage")
async def test_storage_backends(
    backend_names: Optional[List[str]] = None,
    current_user = Depends(get_current_user)
):
    """Test storage backend functionality."""
    try:
        # Get backends to test
        if backend_names:
            # Validate requested backends exist
            available_backends = list(storage_manager.backends.keys())
            invalid_backends = [name for name in backend_names if name not in available_backends]
            if invalid_backends:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Storage backends not found: {invalid_backends}"
                )
            backends_to_test = backend_names
        else:
            # Test all configured backends
            backends_to_test = list(storage_manager.backends.keys())
        
        if not backends_to_test:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No storage backends configured"
            )
        
        results = []
        for backend_name in backends_to_test:
            try:
                test_result = storage_tester.test_storage_backend(backend_name)
                
                results.append({
                    'backend_name': backend_name,
                    'test_result': {
                        'status': test_result.status.value,
                        'duration_seconds': test_result.duration_seconds,
                        'error_message': test_result.error_message,
                        'warnings': test_result.warnings,
                        'recommendations': test_result.recommendations,
                        'details': test_result.details
                    }
                })
                
            except Exception as e:
                results.append({
                    'backend_name': backend_name,
                    'test_result': {
                        'status': 'failed',
                        'error_message': str(e)
                    }
                })
        
        return {
            'storage_test_results': results,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
    
    except Exception as e:
        logger.error(f"Storage backend testing failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage testing failed: {str(e)}"
        )


@router.get("/stats/system")
async def get_system_statistics(
    days_back: int = 30,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get comprehensive system statistics."""
    try:
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        # Device statistics
        total_devices = db.query(NetworkDevice).count()
        active_devices = db.query(NetworkDevice).filter(NetworkDevice.is_active == True).count()
        
        # Backup statistics
        total_backups = db.query(DeviceBackupInfo).filter(
            DeviceBackupInfo.created_at >= since_date
        ).count()
        
        successful_backups = db.query(DeviceBackupInfo).filter(
            and_(
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.completed
            )
        ).count()
        
        failed_backups = db.query(DeviceBackupInfo).filter(
            and_(
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.failed
            )
        ).count()
        
        # Storage statistics
        total_backup_size = db.query(
            func.sum(DeviceBackupInfo.backup_file_size_mb)
        ).filter(
            and_(
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.completed
            )
        ).scalar() or 0
        
        # Average backup duration
        avg_duration = db.query(
            func.avg(
                func.timestampdiff(
                    'SECOND',
                    DeviceBackupInfo.backup_start_time,
                    DeviceBackupInfo.backup_end_time
                )
            )
        ).filter(
            and_(
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.completed,
                DeviceBackupInfo.backup_start_time.isnot(None),
                DeviceBackupInfo.backup_end_time.isnot(None)
            )
        ).scalar() or 0
        
        # Device types breakdown
        device_types = db.query(
            DeviceType.vendor,
            DeviceType.model,
            func.count(NetworkDevice.id).label('count')
        ).join(NetworkDevice).filter(
            NetworkDevice.is_active == True
        ).group_by(DeviceType.vendor, DeviceType.model).all()
        
        # Recent backup trends (last 7 days)
        recent_backups = db.query(
            func.date(DeviceBackupInfo.created_at).label('backup_date'),
            func.count(DeviceBackupInfo.id).label('total'),
            func.sum(
                func.case([(DeviceBackupInfo.job_status == JobStatus.completed, 1)], else_=0)
            ).label('successful'),
            func.sum(
                func.case([(DeviceBackupInfo.job_status == JobStatus.failed, 1)], else_=0)
            ).label('failed')
        ).filter(
            DeviceBackupInfo.created_at >= datetime.now(timezone.utc) - timedelta(days=7)
        ).group_by(
            func.date(DeviceBackupInfo.created_at)
        ).order_by(desc('backup_date')).all()
        
        # Error statistics
        error_stats = error_manager.get_error_statistics(timedelta(days=days_back))
        
        return {
            "period_days": days_back,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_statistics": {
                "total_devices": total_devices,
                "active_devices": active_devices,
                "inactive_devices": total_devices - active_devices,
                "device_types": [
                    {
                        "vendor": dt.vendor,
                        "model": dt.model,
                        "count": dt.count
                    }
                    for dt in device_types
                ]
            },
            "backup_statistics": {
                "total_backups": total_backups,
                "successful_backups": successful_backups,
                "failed_backups": failed_backups,
                "success_rate": (successful_backups / total_backups * 100) if total_backups > 0 else 0,
                "total_backup_size_mb": float(total_backup_size),
                "average_duration_seconds": float(avg_duration)
            },
            "recent_backup_trends": [
                {
                    "date": trend.backup_date.isoformat(),
                    "total": trend.total,
                    "successful": trend.successful,
                    "failed": trend.failed
                }
                for trend in recent_backups
            ],
            "error_statistics": error_stats,
            "system_health": health_monitor.run_quick_health_check()
        }
    
    except Exception as e:
        logger.error(f"Failed to get system statistics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get system statistics: {str(e)}"
        )


@router.get("/errors/recent")
async def get_recent_errors(
    hours_back: int = 24,
    limit: int = 100,
    category: Optional[str] = None,
    current_user = Depends(get_current_user)
):
    """Get recent system errors."""
    try:
        time_window = timedelta(hours=hours_back)
        
        # Get errors from error manager
        if category:
            errors = error_manager.get_errors_by_category(category, time_window, limit)
        else:
            errors = error_manager.get_recent_errors(time_window, limit)
        
        return {
            "recent_errors": [
                {
                    "timestamp": error.timestamp.isoformat(),
                    "category": error.category.value,
                    "message": error.message,
                    "details": error.details,
                    "count": error.count
                }
                for error in errors
            ],
            "hours_back": hours_back,
            "category_filter": category,
            "total_errors": len(errors)
        }
    
    except Exception as e:
        logger.error(f"Failed to get recent errors: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get recent errors: {str(e)}"
        )


@router.post("/performance/benchmark")
async def run_performance_benchmark(
    device_id: int,
    template_id: int,
    iterations: int = 3,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Run performance benchmark for backup operations."""
    if iterations > 10:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 10 iterations allowed for benchmarking"
        )
    
    # Verify device and template exist
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    template = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.id == template_id
    ).first()
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    def run_benchmark():
        """Background task for performance benchmarking."""
        try:
            device_info = {
                'id': device.id,
                'device_name': device.device_name,
                'ip_address': device.ip_address
            }
            
            template_data = {
                'id': template.id,
                'template_name': template.template_name,
                'backup_command': template.backup_command
            }
            
            benchmark_result = performance_tester.benchmark_backup_performance(
                device_info, template_data, iterations
            )
            
            logger.info(f"Performance benchmark completed: {benchmark_result.status.value}")
            return benchmark_result
            
        except Exception as e:
            logger.error(f"Performance benchmark failed: {e}")
            return None
    
    background_tasks.add_task(run_benchmark)
    
    return MessageResponse(
        message=f"Performance benchmark started for device {device.device_name} with {iterations} iterations"
    )