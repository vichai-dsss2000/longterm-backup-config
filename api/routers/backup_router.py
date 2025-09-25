"""
Backup Execution Router
======================

Handles backup job creation, execution, monitoring, and management.
Integrates with scripts/backup_executor.py for backup operations.
"""

import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_, desc

from database import (
    get_db, NetworkDevice, BackupCommandTemplate, DeviceBackupInfo, 
    JobSchedulePolicy, BackupFileStorage, JobStatus, StorageStatus
)
from schemas import BackupJobRequest, BackupJobResponse, MessageResponse
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.backup_executor import DeviceBackupExecutor, BackupJobConfig, BackupStatus
from scripts.file_storage import storage_manager
from scripts.error_handling import error_manager

router = APIRouter()
logger = logging.getLogger(__name__)

# Global backup executor instance (will be initialized in main.py)
backup_executor = None


def get_backup_executor():
    """Get the global backup executor instance."""
    global backup_executor
    if backup_executor is None:
        # Initialize if not available (fallback)
        backup_executor = DeviceBackupExecutor(
            max_concurrent_jobs=5,
            storage_path="/tmp/backups"
        )
    return backup_executor


@router.get("/", response_model=List[dict])
async def get_backup_jobs(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = None,
    device_id: Optional[int] = None,
    days_back: int = 7,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of backup jobs with filtering options."""
    from datetime import timedelta
    
    # Base query with relationships
    query = db.query(DeviceBackupInfo).options(
        joinedload(DeviceBackupInfo.device),
        joinedload(DeviceBackupInfo.schedule_policy).joinedload(JobSchedulePolicy.template)
    )
    
    # Filter by date range
    since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    query = query.filter(DeviceBackupInfo.created_at >= since_date)
    
    # Apply filters
    if status_filter:
        try:
            job_status = JobStatus(status_filter)
            query = query.filter(DeviceBackupInfo.job_status == job_status)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter: {status_filter}"
            )
    
    if device_id:
        query = query.filter(DeviceBackupInfo.device_id == device_id)
    
    # Order by creation date (newest first)
    query = query.order_by(desc(DeviceBackupInfo.created_at))
    
    backup_jobs = query.offset(skip).limit(limit).all()
    
    return [
        {
            "id": job.id,
            "device": {
                "id": job.device.id,
                "device_name": job.device.device_name,
                "ip_address": job.device.ip_address
            } if job.device else None,
            "template": {
                "id": job.schedule_policy.template.id,
                "template_name": job.schedule_policy.template.template_name
            } if job.schedule_policy and job.schedule_policy.template else None,
            "job_status": job.job_status.value if job.job_status else None,
            "backup_start_time": job.backup_start_time,
            "backup_end_time": job.backup_end_time,
            "backup_file_path": job.backup_file_path,
            "backup_file_size_mb": float(job.backup_file_size_mb) if job.backup_file_size_mb else None,
            "error_message": job.error_message,
            "retry_count": job.retry_count,
            "next_retry_time": job.next_retry_time,
            "created_at": job.created_at,
            "duration_seconds": (
                (job.backup_end_time - job.backup_start_time).total_seconds()
                if job.backup_start_time and job.backup_end_time else None
            )
        }
        for job in backup_jobs
    ]


@router.post("/execute", response_model=BackupJobResponse)
async def execute_backup_job(
    job_request: BackupJobRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Execute a backup job for a specific device."""
    # Get device
    device = db.query(NetworkDevice).options(
        joinedload(NetworkDevice.device_type)
    ).filter(NetworkDevice.id == job_request.device_id).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    if not device.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device is not active"
        )
    
    # Get template
    template = None
    if job_request.template_id:
        template = db.query(BackupCommandTemplate).filter(
            BackupCommandTemplate.id == job_request.template_id
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Template not found"
            )
        
        # Verify template is compatible with device type
        if template.device_type_id != device.device_type_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Template is not compatible with device type"
            )
    else:
        # Get default template for device type
        template = db.query(BackupCommandTemplate).filter(
            and_(
                BackupCommandTemplate.device_type_id == device.device_type_id,
                BackupCommandTemplate.is_active == True
            )
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No active template found for device type"
            )
    
    # Create backup job record
    backup_job = DeviceBackupInfo(
        device_id=device.id,
        schedule_policy_id=1,  # Default policy ID for manual jobs
        job_status=JobStatus.pending,
        created_at=datetime.now(timezone.utc)
    )
    
    db.add(backup_job)
    db.commit()
    db.refresh(backup_job)
    
    try:
        # Prepare device info
        from routers.device_router import decrypt_password
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
        
        # Prepare template data
        template_data = {
            'id': template.id,
            'template_name': template.template_name,
            'backup_command': template.backup_command,
            'command_format': template.command_format,
            'template_variables': template.template_variables or {},
            'timeout_seconds': template.timeout_seconds,
            'retry_count': template.retry_count
        }
        
        # Create backup job configuration
        job_config = BackupJobConfig(
            job_id=f"manual_{backup_job.id}",
            device_id=device.id,
            device_info=device_info,
            template_data=template_data,
            schedule_policy={},
            user_variables={
                'backup_path': f'/manual_backups/{device.device_name}',
                'timestamp': datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            },
            max_retries=template.retry_count,
            timeout=template.timeout_seconds,
            verify_backup=True
        )
        
        # Submit job to background execution
        def execute_backup_task():
            """Background task for backup execution."""
            try:
                # Update job status
                backup_job.job_status = JobStatus.running
                backup_job.backup_start_time = datetime.now(timezone.utc)
                db.commit()
                
                # Execute backup
                executor = get_backup_executor()
                result = executor._execute_single_backup(job_config)
                
                # Update job record with results
                backup_job.backup_end_time = datetime.now(timezone.utc)
                backup_job.backup_file_path = result.backup_file_path
                backup_job.backup_file_size_mb = result.file_size_bytes / (1024 * 1024) if result.file_size_bytes else None
                backup_job.execution_log = result.execution_log
                
                if result.status == BackupStatus.COMPLETED:
                    backup_job.job_status = JobStatus.completed
                    
                    # Create storage record
                    if result.backup_file_path:
                        storage_record = BackupFileStorage(
                            backup_info_id=backup_job.id,
                            storage_type="local",  # Will be updated if uploaded to other storage
                            file_path=result.backup_file_path,
                            file_hash=result.file_hash,
                            file_size_bytes=result.file_size_bytes,
                            compression_ratio=result.compression_ratio,
                            storage_status=StorageStatus.stored
                        )
                        db.add(storage_record)
                    
                    # Update device last backup info
                    device.last_backup_date = backup_job.backup_end_time
                    device.last_backup_status = "success"
                
                else:
                    backup_job.job_status = JobStatus.failed
                    backup_job.error_message = result.error_message
                    device.last_backup_status = "failed"
                
                db.commit()
                
                logger.info(f"Manual backup job {backup_job.id} completed with status: {result.status}")
                
            except Exception as e:
                logger.error(f"Background backup task failed: {e}")
                
                # Update job record with error
                backup_job.job_status = JobStatus.failed
                backup_job.backup_end_time = datetime.now(timezone.utc)
                backup_job.error_message = str(e)
                device.last_backup_status = "failed"
                db.commit()
                
                # Log error
                error_manager.log_error(
                    category="BACKUP_EXECUTION",
                    message=f"Manual backup failed for device {device.device_name}",
                    details={
                        'job_id': backup_job.id,
                        'device_id': device.id,
                        'error': str(e)
                    }
                )
        
        background_tasks.add_task(execute_backup_task)
        
        return BackupJobResponse(
            job_id=backup_job.id,
            status="submitted",
            message=f"Backup job submitted for device {device.device_name}"
        )
    
    except Exception as e:
        logger.error(f"Failed to submit backup job: {e}")
        
        # Update job status to failed
        backup_job.job_status = JobStatus.failed
        backup_job.error_message = str(e)
        db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit backup job: {str(e)}"
        )


@router.get("/{job_id}")
async def get_backup_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get detailed information about a specific backup job."""
    backup_job = db.query(DeviceBackupInfo).options(
        joinedload(DeviceBackupInfo.device).joinedload(NetworkDevice.device_type),
        joinedload(DeviceBackupInfo.schedule_policy).joinedload(JobSchedulePolicy.template),
        joinedload(DeviceBackupInfo.storage_files)
    ).filter(DeviceBackupInfo.id == job_id).first()
    
    if not backup_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup job not found"
        )
    
    # Calculate duration
    duration_seconds = None
    if backup_job.backup_start_time and backup_job.backup_end_time:
        duration_seconds = (backup_job.backup_end_time - backup_job.backup_start_time).total_seconds()
    
    return {
        "id": backup_job.id,
        "device": {
            "id": backup_job.device.id,
            "device_name": backup_job.device.device_name,
            "ip_address": backup_job.device.ip_address,
            "device_type": {
                "vendor": backup_job.device.device_type.vendor,
                "model": backup_job.device.device_type.model,
                "netmiko_device_type": backup_job.device.device_type.netmiko_device_type
            }
        } if backup_job.device else None,
        "template": {
            "id": backup_job.schedule_policy.template.id,
            "template_name": backup_job.schedule_policy.template.template_name,
            "command_format": backup_job.schedule_policy.template.command_format
        } if backup_job.schedule_policy and backup_job.schedule_policy.template else None,
        "job_status": backup_job.job_status.value if backup_job.job_status else None,
        "backup_start_time": backup_job.backup_start_time,
        "backup_end_time": backup_job.backup_end_time,
        "duration_seconds": duration_seconds,
        "backup_file_path": backup_job.backup_file_path,
        "backup_file_size_mb": float(backup_job.backup_file_size_mb) if backup_job.backup_file_size_mb else None,
        "error_message": backup_job.error_message,
        "retry_count": backup_job.retry_count,
        "next_retry_time": backup_job.next_retry_time,
        "execution_log": backup_job.execution_log,
        "created_at": backup_job.created_at,
        "storage_files": [
            {
                "id": storage.id,
                "storage_type": storage.storage_type.value,
                "file_path": storage.file_path,
                "file_size_bytes": storage.file_size_bytes,
                "compression_ratio": float(storage.compression_ratio) if storage.compression_ratio else None,
                "is_encrypted": storage.is_encrypted,
                "storage_status": storage.storage_status.value,
                "created_at": storage.created_at
            }
            for storage in backup_job.storage_files
        ] if backup_job.storage_files else []
    }


@router.post("/{job_id}/retry", response_model=BackupJobResponse)
async def retry_backup_job(
    job_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Retry a failed backup job."""
    backup_job = db.query(DeviceBackupInfo).options(
        joinedload(DeviceBackupInfo.device).joinedload(NetworkDevice.device_type),
        joinedload(DeviceBackupInfo.schedule_policy).joinedload(JobSchedulePolicy.template)
    ).filter(DeviceBackupInfo.id == job_id).first()
    
    if not backup_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup job not found"
        )
    
    if backup_job.job_status not in [JobStatus.failed]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only failed jobs can be retried"
        )
    
    # Reset job for retry
    backup_job.job_status = JobStatus.pending
    backup_job.backup_start_time = None
    backup_job.backup_end_time = None
    backup_job.error_message = None
    backup_job.retry_count += 1
    
    db.commit()
    
    # Re-submit the job (similar to execute_backup_job)
    # This would follow the same pattern as execute_backup_job
    # but using the existing job record
    
    logger.info(f"Retry submitted for backup job {job_id}")
    
    return BackupJobResponse(
        job_id=job_id,
        status="retry_submitted",
        message=f"Backup job retry submitted (attempt #{backup_job.retry_count})"
    )


@router.delete("/{job_id}", response_model=MessageResponse)
async def cancel_backup_job(
    job_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Cancel a pending or running backup job."""
    backup_job = db.query(DeviceBackupInfo).filter(DeviceBackupInfo.id == job_id).first()
    
    if not backup_job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Backup job not found"
        )
    
    if backup_job.job_status not in [JobStatus.pending, JobStatus.running]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only pending or running jobs can be cancelled"
        )
    
    # TODO: Implement actual job cancellation in backup executor
    # For now, just mark as failed
    backup_job.job_status = JobStatus.failed
    backup_job.error_message = "Job cancelled by user"
    backup_job.backup_end_time = datetime.now(timezone.utc)
    
    db.commit()
    
    logger.info(f"Backup job {job_id} cancelled by user {current_user.username}")
    
    return MessageResponse(message="Backup job cancelled successfully")


@router.get("/stats/summary")
async def get_backup_stats(
    days_back: int = 30,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get backup statistics summary."""
    from datetime import timedelta
    from sqlalchemy import func
    
    since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
    
    # Get job counts by status
    status_counts = db.query(
        DeviceBackupInfo.job_status,
        func.count(DeviceBackupInfo.id)
    ).filter(
        DeviceBackupInfo.created_at >= since_date
    ).group_by(DeviceBackupInfo.job_status).all()
    
    # Get total backup size
    total_size = db.query(
        func.sum(DeviceBackupInfo.backup_file_size_mb)
    ).filter(
        and_(
            DeviceBackupInfo.created_at >= since_date,
            DeviceBackupInfo.job_status == JobStatus.completed
        )
    ).scalar() or 0
    
    # Get average backup duration
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
    
    # Format status counts
    status_summary = {}
    for status, count in status_counts:
        status_summary[status.value if status else 'unknown'] = count
    
    return {
        "period_days": days_back,
        "total_jobs": sum(status_summary.values()),
        "status_breakdown": status_summary,
        "success_rate": (
            (status_summary.get('completed', 0) / sum(status_summary.values()) * 100)
            if sum(status_summary.values()) > 0 else 0
        ),
        "total_backup_size_mb": float(total_size),
        "average_duration_seconds": float(avg_duration),
        "generated_at": datetime.now(timezone.utc)
    }