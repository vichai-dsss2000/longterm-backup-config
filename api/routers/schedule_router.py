"""
Schedule Management Router
=========================

Handles job schedule policies, cron management, and scheduled backup operations.
Integrates with scripts/job_scheduler.py for schedule management.
"""

import logging
from typing import List, Optional
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_

from database import (
    get_db, JobSchedulePolicy, BackupCommandTemplate, DeviceType, 
    JobCategory, NetworkDevice
)
from schemas import (
    JobSchedulePolicyCreate, JobSchedulePolicyUpdate, JobSchedulePolicyResponse,
    JobCategoryCreate, JobCategoryUpdate, JobCategoryResponse, MessageResponse
)
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.job_scheduler import BackupScheduler
from scripts.error_handling import error_manager

router = APIRouter()
logger = logging.getLogger(__name__)

# Global job scheduler instance (will be initialized in main.py)
job_scheduler = None


def get_job_scheduler():
    """Get the global job scheduler instance."""
    global job_scheduler
    if job_scheduler is None:
        logger.warning("Job scheduler not initialized")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Job scheduler not available"
        )
    return job_scheduler


def validate_cron_expression(cron_expr: str) -> bool:
    """Validate cron expression format."""
    try:
        from apscheduler.triggers.cron import CronTrigger
        CronTrigger.from_crontab(cron_expr)
        return True
    except Exception as e:
        logger.error(f"Invalid cron expression '{cron_expr}': {e}")
        return False


# Job Category endpoints
@router.get("/categories", response_model=List[JobCategoryResponse])
async def get_job_categories(
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of job categories."""
    query = db.query(JobCategory)
    
    if active_only:
        query = query.filter(JobCategory.is_active == True)
    
    categories = query.all()
    
    return [
        JobCategoryResponse(
            **{key: getattr(category, key) 
               for key in JobCategoryResponse.__annotations__.keys() 
               if hasattr(category, key)}
        )
        for category in categories
    ]


@router.post("/categories", response_model=JobCategoryResponse)
async def create_job_category(
    category_data: JobCategoryCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Create a new job category."""
    # Check if category name already exists
    existing_category = db.query(JobCategory).filter(
        JobCategory.category_name == category_data.category_name
    ).first()
    
    if existing_category:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Category name already exists"
        )
    
    new_category = JobCategory(
        category_name=category_data.category_name,
        description=category_data.description,
        color_code=category_data.color_code
    )
    
    db.add(new_category)
    db.commit()
    db.refresh(new_category)
    
    logger.info(f"Created job category: {new_category.category_name}")
    
    return JobCategoryResponse(
        **{key: getattr(new_category, key) 
           for key in JobCategoryResponse.__annotations__.keys() 
           if hasattr(new_category, key)}
    )


# Schedule Policy endpoints
@router.get("/", response_model=List[JobSchedulePolicyResponse])
async def get_schedule_policies(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    device_type_id: Optional[int] = None,
    category_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of job schedule policies with filtering options."""
    query = db.query(JobSchedulePolicy).options(
        joinedload(JobSchedulePolicy.template).joinedload(BackupCommandTemplate.device_type),
        joinedload(JobSchedulePolicy.job_category)
    )
    
    # Apply filters
    if active_only:
        query = query.filter(JobSchedulePolicy.is_active == True)
    
    if device_type_id:
        query = query.filter(JobSchedulePolicy.device_type_id == device_type_id)
    
    if category_id:
        query = query.filter(JobSchedulePolicy.job_category_id == category_id)
    
    policies = query.offset(skip).limit(limit).all()
    
    return [
        JobSchedulePolicyResponse(
            **{key: getattr(policy, key) 
               for key in JobSchedulePolicyResponse.__annotations__.keys() 
               if hasattr(policy, key)}
        )
        for policy in policies
    ]


@router.post("/", response_model=JobSchedulePolicyResponse)
async def create_schedule_policy(
    policy_data: JobSchedulePolicyCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Create a new job schedule policy."""
    # Validate cron expression
    if not validate_cron_expression(policy_data.cron_expression):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid cron expression"
        )
    
    # Verify template exists and is active
    template = db.query(BackupCommandTemplate).filter(
        and_(
            BackupCommandTemplate.id == policy_data.template_id,
            BackupCommandTemplate.is_active == True
        )
    ).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Template not found or inactive"
        )
    
    # Verify device type compatibility if specified
    if policy_data.device_type_id:
        if policy_data.device_type_id != template.device_type_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device type does not match template device type"
            )
    
    # Verify job category exists if specified
    if policy_data.job_category_id:
        category = db.query(JobCategory).filter(
            JobCategory.id == policy_data.job_category_id
        ).first()
        if not category:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Job category not found"
            )
    
    # Encrypt SFTP password if provided
    sftp_password_encrypted = None
    if policy_data.sftp_password:
        from routers.device_router import encrypt_password
        sftp_password_encrypted = encrypt_password(policy_data.sftp_password)
    
    # Create schedule policy
    new_policy = JobSchedulePolicy(
        policy_name=policy_data.policy_name,
        device_type_id=policy_data.device_type_id,
        template_id=policy_data.template_id,
        job_category_id=policy_data.job_category_id,
        cron_expression=policy_data.cron_expression,
        backup_path=policy_data.backup_path,
        sftp_server_ip=policy_data.sftp_server_ip,
        sftp_username=policy_data.sftp_username,
        sftp_password_encrypted=sftp_password_encrypted,
        sftp_port=policy_data.sftp_port,
        retention_days=policy_data.retention_days,
        compression_enabled=policy_data.compression_enabled,
        encryption_enabled=policy_data.encryption_enabled,
        notification_enabled=policy_data.notification_enabled,
        notification_emails=policy_data.notification_emails,
        created_by=current_user.id
    )
    
    db.add(new_policy)
    db.commit()
    db.refresh(new_policy)
    
    # Add job to scheduler
    try:
        scheduler = get_job_scheduler()
        await scheduler.add_schedule_policy(new_policy)
        logger.info(f"Added schedule policy to job scheduler: {new_policy.policy_name}")
    except Exception as e:
        logger.error(f"Failed to add schedule policy to scheduler: {e}")
        # Don't fail the creation, but log the error
        error_manager.log_error(
            category="SCHEDULER",
            message=f"Failed to add schedule policy to scheduler",
            details={
                'policy_id': new_policy.id,
                'error': str(e)
            }
        )
    
    logger.info(f"Created schedule policy: {new_policy.policy_name}")
    
    return JobSchedulePolicyResponse(
        **{key: getattr(new_policy, key) 
           for key in JobSchedulePolicyResponse.__annotations__.keys() 
           if hasattr(new_policy, key)}
    )


@router.get("/{policy_id}", response_model=JobSchedulePolicyResponse)
async def get_schedule_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific schedule policy by ID."""
    policy = db.query(JobSchedulePolicy).options(
        joinedload(JobSchedulePolicy.template).joinedload(BackupCommandTemplate.device_type),
        joinedload(JobSchedulePolicy.job_category)
    ).filter(JobSchedulePolicy.id == policy_id).first()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule policy not found"
        )
    
    return JobSchedulePolicyResponse(
        **{key: getattr(policy, key) 
           for key in JobSchedulePolicyResponse.__annotations__.keys() 
           if hasattr(policy, key)}
    )


@router.put("/{policy_id}", response_model=JobSchedulePolicyResponse)
async def update_schedule_policy(
    policy_id: int,
    policy_data: JobSchedulePolicyUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Update existing schedule policy."""
    policy = db.query(JobSchedulePolicy).filter(
        JobSchedulePolicy.id == policy_id
    ).first()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule policy not found"
        )
    
    update_data = policy_data.dict(exclude_unset=True)
    
    # Validate cron expression if being updated
    if 'cron_expression' in update_data:
        if not validate_cron_expression(update_data['cron_expression']):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid cron expression"
            )
    
    # Verify template compatibility if being updated
    if 'template_id' in update_data:
        template = db.query(BackupCommandTemplate).filter(
            and_(
                BackupCommandTemplate.id == update_data['template_id'],
                BackupCommandTemplate.is_active == True
            )
        ).first()
        
        if not template:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Template not found or inactive"
            )
    
    # Handle password encryption
    if 'sftp_password' in update_data and update_data['sftp_password']:
        from routers.device_router import encrypt_password
        update_data['sftp_password_encrypted'] = encrypt_password(update_data['sftp_password'])
        del update_data['sftp_password']
    
    # Update policy fields
    for field, value in update_data.items():
        if hasattr(policy, field):
            setattr(policy, field, value)
    
    db.commit()
    db.refresh(policy)
    
    # Update job in scheduler
    try:
        scheduler = get_job_scheduler()
        await scheduler.update_schedule_policy(policy)
        logger.info(f"Updated schedule policy in job scheduler: {policy.policy_name}")
    except Exception as e:
        logger.error(f"Failed to update schedule policy in scheduler: {e}")
        error_manager.log_error(
            category="SCHEDULER",
            message=f"Failed to update schedule policy in scheduler",
            details={
                'policy_id': policy.id,
                'error': str(e)
            }
        )
    
    logger.info(f"Updated schedule policy: {policy.policy_name}")
    
    return JobSchedulePolicyResponse(
        **{key: getattr(policy, key) 
           for key in JobSchedulePolicyResponse.__annotations__.keys() 
           if hasattr(policy, key)}
    )


@router.delete("/{policy_id}", response_model=MessageResponse)
async def delete_schedule_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Delete schedule policy (soft delete by setting is_active=False)."""
    policy = db.query(JobSchedulePolicy).filter(
        JobSchedulePolicy.id == policy_id
    ).first()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule policy not found"
        )
    
    # Soft delete
    policy.is_active = False
    db.commit()
    
    # Remove job from scheduler
    try:
        scheduler = get_job_scheduler()
        await scheduler.remove_schedule_policy(policy_id)
        logger.info(f"Removed schedule policy from job scheduler: {policy.policy_name}")
    except Exception as e:
        logger.error(f"Failed to remove schedule policy from scheduler: {e}")
        error_manager.log_error(
            category="SCHEDULER",
            message=f"Failed to remove schedule policy from scheduler",
            details={
                'policy_id': policy_id,
                'error': str(e)
            }
        )
    
    logger.info(f"Soft deleted schedule policy: {policy.policy_name}")
    
    return MessageResponse(message="Schedule policy deleted successfully")


@router.post("/{policy_id}/trigger")
async def trigger_schedule_policy(
    policy_id: int,
    device_ids: Optional[List[int]] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Manually trigger a schedule policy for specific devices."""
    policy = db.query(JobSchedulePolicy).options(
        joinedload(JobSchedulePolicy.template)
    ).filter(
        and_(
            JobSchedulePolicy.id == policy_id,
            JobSchedulePolicy.is_active == True
        )
    ).first()
    
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Schedule policy not found or inactive"
        )
    
    # Get target devices
    if device_ids:
        # Specific devices
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
    else:
        # All devices matching policy device type
        query = db.query(NetworkDevice).filter(NetworkDevice.is_active == True)
        
        if policy.device_type_id:
            query = query.filter(NetworkDevice.device_type_id == policy.device_type_id)
        
        devices = query.all()
    
    if not devices:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No eligible devices found for this policy"
        )
    
    # Trigger jobs manually
    try:
        scheduler = get_job_scheduler()
        triggered_jobs = await scheduler.trigger_policy_for_devices(policy, devices)
        
        logger.info(f"Manually triggered {len(triggered_jobs)} jobs for policy {policy.policy_name}")
        
        return {
            "policy_id": policy_id,
            "policy_name": policy.policy_name,
            "triggered_devices": len(devices),
            "triggered_jobs": triggered_jobs,
            "message": f"Successfully triggered {len(triggered_jobs)} backup jobs"
        }
    
    except Exception as e:
        logger.error(f"Failed to trigger schedule policy: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to trigger schedule policy: {str(e)}"
        )


@router.get("/scheduler/status")
async def get_scheduler_status(
    current_user = Depends(get_current_user)
):
    """Get job scheduler status and statistics."""
    try:
        scheduler = get_job_scheduler()
        
        # Get scheduler status
        is_running = scheduler.scheduler.running if hasattr(scheduler, 'scheduler') else False
        
        # Get job counts
        if is_running and hasattr(scheduler, 'scheduler'):
            jobs = scheduler.scheduler.get_jobs()
            job_count = len(jobs)
            
            # Get next run times
            next_runs = []
            for job in jobs[:10]:  # Limit to next 10 jobs
                if job.next_run_time:
                    next_runs.append({
                        'job_id': job.id,
                        'job_name': job.name,
                        'next_run_time': job.next_run_time.isoformat() if job.next_run_time else None
                    })
        else:
            job_count = 0
            next_runs = []
        
        return {
            "scheduler_status": "running" if is_running else "stopped",
            "total_scheduled_jobs": job_count,
            "next_scheduled_runs": next_runs,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    except Exception as e:
        logger.error(f"Failed to get scheduler status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scheduler status: {str(e)}"
        )


@router.post("/scheduler/reload")
async def reload_scheduler_jobs(
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Reload all schedule policies into the job scheduler."""
    try:
        scheduler = get_job_scheduler()
        
        # Clear existing jobs
        if hasattr(scheduler, 'scheduler'):
            scheduler.scheduler.remove_all_jobs()
        
        # Reload jobs from database
        await scheduler.load_jobs_from_database()
        
        logger.info("Job scheduler reloaded successfully")
        
        return MessageResponse(
            message="Job scheduler reloaded successfully"
        )
    
    except Exception as e:
        logger.error(f"Failed to reload scheduler: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to reload scheduler: {str(e)}"
        )