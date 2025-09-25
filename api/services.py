"""
Database Service Layer
=====================

Service layer classes that bridge FastAPI endpoints with script modules 
and database models. Provides business logic and data access patterns.
"""

import logging
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from database import (
    NetworkDevice, DeviceType, BackupCommandTemplate, JobSchedulePolicy,
    DeviceBackupInfo, BackupFileStorage, JobCategory, User, LoginSession,
    JobStatus, BackupStatus, StorageStatus, StorageType
)

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent / "scripts"))

from scripts.backup_executor import BackupJobConfig, DeviceBackupExecutor
from scripts.job_scheduler import BackupScheduler
from scripts.error_handling import error_manager
from scripts.file_storage import storage_manager

logger = logging.getLogger(__name__)


class DeviceService:
    """Service class for device management operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_devices_with_filters(
        self,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = True,
        device_type_id: Optional[int] = None,
        search: Optional[str] = None,
        location: Optional[str] = None
    ) -> Tuple[List[NetworkDevice], int]:
        """Get devices with advanced filtering."""
        query = self.db.query(NetworkDevice)
        
        # Apply filters
        conditions = []
        
        if active_only:
            conditions.append(NetworkDevice.is_active == True)
        
        if device_type_id:
            conditions.append(NetworkDevice.device_type_id == device_type_id)
        
        if location:
            conditions.append(NetworkDevice.location.ilike(f"%{location}%"))
        
        if search:
            search_term = f"%{search}%"
            search_conditions = [
                NetworkDevice.device_name.ilike(search_term),
                NetworkDevice.ip_address.ilike(search_term),
                NetworkDevice.hostname.ilike(search_term),
                NetworkDevice.description.ilike(search_term)
            ]
            conditions.append(or_(*search_conditions))
        
        if conditions:
            query = query.filter(and_(*conditions))
        
        # Get total count
        total_count = query.count()
        
        # Apply pagination
        devices = query.offset(skip).limit(limit).all()
        
        return devices, total_count
    
    def get_device_with_backup_history(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get device with its backup history."""
        device = self.db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
        
        if not device:
            return None
        
        # Get recent backup history
        backup_history = self.db.query(DeviceBackupInfo).filter(
            DeviceBackupInfo.device_id == device_id
        ).order_by(desc(DeviceBackupInfo.created_at)).limit(10).all()
        
        # Calculate backup statistics
        total_backups = self.db.query(DeviceBackupInfo).filter(
            DeviceBackupInfo.device_id == device_id
        ).count()
        
        successful_backups = self.db.query(DeviceBackupInfo).filter(
            and_(
                DeviceBackupInfo.device_id == device_id,
                DeviceBackupInfo.job_status == JobStatus.completed
            )
        ).count()
        
        return {
            'device': device,
            'backup_history': backup_history,
            'backup_statistics': {
                'total_backups': total_backups,
                'successful_backups': successful_backups,
                'success_rate': (successful_backups / total_backups * 100) if total_backups > 0 else 0,
                'last_backup': backup_history[0] if backup_history else None
            }
        }
    
    def get_devices_by_location(self) -> Dict[str, List[NetworkDevice]]:
        """Group devices by location."""
        devices = self.db.query(NetworkDevice).filter(NetworkDevice.is_active == True).all()
        
        location_groups = {}
        for device in devices:
            location = device.location or "Unknown Location"
            if location not in location_groups:
                location_groups[location] = []
            location_groups[location].append(device)
        
        return location_groups
    
    def get_device_health_summary(self, days_back: int = 7) -> Dict[str, Any]:
        """Get device health summary."""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        # Total devices
        total_devices = self.db.query(NetworkDevice).filter(NetworkDevice.is_active == True).count()
        
        # Devices with recent successful backups
        devices_with_recent_backups = self.db.query(NetworkDevice).join(DeviceBackupInfo).filter(
            and_(
                NetworkDevice.is_active == True,
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.completed
            )
        ).distinct().count()
        
        # Devices with recent failures
        devices_with_failures = self.db.query(NetworkDevice).join(DeviceBackupInfo).filter(
            and_(
                NetworkDevice.is_active == True,
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.failed
            )
        ).distinct().count()
        
        # Devices never backed up
        devices_never_backed_up = self.db.query(NetworkDevice).outerjoin(DeviceBackupInfo).filter(
            and_(
                NetworkDevice.is_active == True,
                DeviceBackupInfo.id.is_(None)
            )
        ).count()
        
        return {
            'total_active_devices': total_devices,
            'devices_with_recent_backups': devices_with_recent_backups,
            'devices_with_failures': devices_with_failures,
            'devices_never_backed_up': devices_never_backed_up,
            'health_percentage': (devices_with_recent_backups / total_devices * 100) if total_devices > 0 else 0,
            'period_days': days_back
        }


class BackupService:
    """Service class for backup operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def create_backup_job(
        self,
        device_id: int,
        template_id: Optional[int] = None,
        user_variables: Optional[Dict[str, Any]] = None
    ) -> DeviceBackupInfo:
        """Create a new backup job."""
        # Get device
        device = self.db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
        if not device:
            raise ValueError("Device not found")
        
        # Get template
        if template_id:
            template = self.db.query(BackupCommandTemplate).filter(
                BackupCommandTemplate.id == template_id
            ).first()
            if not template:
                raise ValueError("Template not found")
        else:
            # Get default template for device type
            template = self.db.query(BackupCommandTemplate).filter(
                and_(
                    BackupCommandTemplate.device_type_id == device.device_type_id,
                    BackupCommandTemplate.is_active == True
                )
            ).first()
            if not template:
                raise ValueError("No active template found for device type")
        
        # Create backup job record
        backup_job = DeviceBackupInfo(
            device_id=device_id,
            schedule_policy_id=1,  # Default for manual jobs
            job_status=JobStatus.pending,
            created_at=datetime.now(timezone.utc)
        )
        
        self.db.add(backup_job)
        self.db.commit()
        self.db.refresh(backup_job)
        
        return backup_job
    
    def get_backup_jobs_with_filters(
        self,
        skip: int = 0,
        limit: int = 100,
        status_filter: Optional[JobStatus] = None,
        device_id: Optional[int] = None,
        days_back: int = 7
    ) -> Tuple[List[DeviceBackupInfo], int]:
        """Get backup jobs with filtering."""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        query = self.db.query(DeviceBackupInfo).filter(DeviceBackupInfo.created_at >= since_date)
        
        if status_filter:
            query = query.filter(DeviceBackupInfo.job_status == status_filter)
        
        if device_id:
            query = query.filter(DeviceBackupInfo.device_id == device_id)
        
        total_count = query.count()
        
        backup_jobs = query.order_by(desc(DeviceBackupInfo.created_at)).offset(skip).limit(limit).all()
        
        return backup_jobs, total_count
    
    def get_backup_statistics(self, days_back: int = 30) -> Dict[str, Any]:
        """Get comprehensive backup statistics."""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        # Status breakdown
        status_counts = self.db.query(
            DeviceBackupInfo.job_status,
            func.count(DeviceBackupInfo.id)
        ).filter(
            DeviceBackupInfo.created_at >= since_date
        ).group_by(DeviceBackupInfo.job_status).all()
        
        status_summary = {}
        for status, count in status_counts:
            status_summary[status.value if status else 'unknown'] = count
        
        # Size and duration statistics
        completed_jobs = self.db.query(DeviceBackupInfo).filter(
            and_(
                DeviceBackupInfo.created_at >= since_date,
                DeviceBackupInfo.job_status == JobStatus.completed,
                DeviceBackupInfo.backup_start_time.isnot(None),
                DeviceBackupInfo.backup_end_time.isnot(None)
            )
        ).all()
        
        total_size = sum(float(job.backup_file_size_mb or 0) for job in completed_jobs)
        
        durations = []
        for job in completed_jobs:
            if job.backup_start_time and job.backup_end_time:
                duration = (job.backup_end_time - job.backup_start_time).total_seconds()
                durations.append(duration)
        
        avg_duration = sum(durations) / len(durations) if durations else 0
        
        return {
            'period_days': days_back,
            'total_jobs': sum(status_summary.values()),
            'status_breakdown': status_summary,
            'success_rate': (
                (status_summary.get('completed', 0) / sum(status_summary.values()) * 100)
                if sum(status_summary.values()) > 0 else 0
            ),
            'total_backup_size_mb': total_size,
            'average_duration_seconds': avg_duration,
            'completed_jobs': len(completed_jobs)
        }
    
    def get_backup_trends(self, days_back: int = 14) -> List[Dict[str, Any]]:
        """Get daily backup trends."""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        daily_stats = self.db.query(
            func.date(DeviceBackupInfo.created_at).label('backup_date'),
            func.count(DeviceBackupInfo.id).label('total'),
            func.sum(
                func.case([(DeviceBackupInfo.job_status == JobStatus.completed, 1)], else_=0)
            ).label('successful'),
            func.sum(
                func.case([(DeviceBackupInfo.job_status == JobStatus.failed, 1)], else_=0)
            ).label('failed')
        ).filter(
            DeviceBackupInfo.created_at >= since_date
        ).group_by(
            func.date(DeviceBackupInfo.created_at)
        ).order_by(desc('backup_date')).all()
        
        return [
            {
                'date': stat.backup_date.isoformat(),
                'total': stat.total,
                'successful': stat.successful,
                'failed': stat.failed,
                'success_rate': (stat.successful / stat.total * 100) if stat.total > 0 else 0
            }
            for stat in daily_stats
        ]


class TemplateService:
    """Service class for template management."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_templates_by_device_type(self, device_type_id: int) -> List[BackupCommandTemplate]:
        """Get all active templates for a device type."""
        return self.db.query(BackupCommandTemplate).filter(
            and_(
                BackupCommandTemplate.device_type_id == device_type_id,
                BackupCommandTemplate.is_active == True
            )
        ).all()
    
    def get_template_usage_statistics(self) -> List[Dict[str, Any]]:
        """Get template usage statistics."""
        template_usage = self.db.query(
            BackupCommandTemplate.id,
            BackupCommandTemplate.template_name,
            func.count(DeviceBackupInfo.id).label('usage_count'),
            func.count(
                func.case([(DeviceBackupInfo.job_status == JobStatus.completed, 1)], else_=None)
            ).label('successful_count')
        ).outerjoin(
            JobSchedulePolicy, JobSchedulePolicy.template_id == BackupCommandTemplate.id
        ).outerjoin(
            DeviceBackupInfo, DeviceBackupInfo.schedule_policy_id == JobSchedulePolicy.id
        ).filter(
            BackupCommandTemplate.is_active == True
        ).group_by(
            BackupCommandTemplate.id, BackupCommandTemplate.template_name
        ).all()
        
        return [
            {
                'template_id': usage.id,
                'template_name': usage.template_name,
                'usage_count': usage.usage_count,
                'successful_count': usage.successful_count,
                'success_rate': (usage.successful_count / usage.usage_count * 100) if usage.usage_count > 0 else 0
            }
            for usage in template_usage
        ]
    
    def get_templates_needing_attention(self) -> List[Dict[str, Any]]:
        """Get templates that may need attention (unused, failing, etc.)."""
        # Templates never used
        unused_templates = self.db.query(BackupCommandTemplate).outerjoin(
            JobSchedulePolicy, JobSchedulePolicy.template_id == BackupCommandTemplate.id
        ).filter(
            and_(
                BackupCommandTemplate.is_active == True,
                JobSchedulePolicy.id.is_(None)
            )
        ).all()
        
        attention_templates = []
        
        for template in unused_templates:
            attention_templates.append({
                'template_id': template.id,
                'template_name': template.template_name,
                'issue': 'unused',
                'description': 'Template is not used by any schedule policy'
            })
        
        return attention_templates


class ScheduleService:
    """Service class for schedule management."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_schedule_policies_summary(self) -> Dict[str, Any]:
        """Get schedule policies summary."""
        total_policies = self.db.query(JobSchedulePolicy).count()
        active_policies = self.db.query(JobSchedulePolicy).filter(JobSchedulePolicy.is_active == True).count()
        
        # Policies by category
        category_breakdown = self.db.query(
            JobCategory.category_name,
            func.count(JobSchedulePolicy.id)
        ).outerjoin(
            JobSchedulePolicy, JobSchedulePolicy.job_category_id == JobCategory.id
        ).filter(
            JobSchedulePolicy.is_active == True
        ).group_by(JobCategory.category_name).all()
        
        return {
            'total_policies': total_policies,
            'active_policies': active_policies,
            'inactive_policies': total_policies - active_policies,
            'category_breakdown': [
                {
                    'category': cat.category_name,
                    'count': cat[1]
                }
                for cat in category_breakdown
            ]
        }
    
    def get_upcoming_scheduled_jobs(self, hours_ahead: int = 24) -> List[Dict[str, Any]]:
        """Get upcoming scheduled jobs (requires scheduler integration)."""
        # This would integrate with the job scheduler to get next run times
        # For now, return active policies that could potentially run
        
        active_policies = self.db.query(JobSchedulePolicy).filter(
            JobSchedulePolicy.is_active == True
        ).all()
        
        # In a real implementation, this would use the scheduler to get actual next run times
        upcoming_jobs = []
        for policy in active_policies:
            upcoming_jobs.append({
                'policy_id': policy.id,
                'policy_name': policy.policy_name,
                'cron_expression': policy.cron_expression,
                'estimated_devices': self._count_devices_for_policy(policy),
                'next_run_time': None  # Would be populated by scheduler
            })
        
        return upcoming_jobs
    
    def _count_devices_for_policy(self, policy: JobSchedulePolicy) -> int:
        """Count devices that would be affected by a policy."""
        query = self.db.query(NetworkDevice).filter(NetworkDevice.is_active == True)
        
        if policy.device_type_id:
            query = query.filter(NetworkDevice.device_type_id == policy.device_type_id)
        
        return query.count()


class SystemService:
    """Service class for system-wide operations."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def get_dashboard_summary(self) -> Dict[str, Any]:
        """Get comprehensive dashboard summary."""
        device_service = DeviceService(self.db)
        backup_service = BackupService(self.db)
        schedule_service = ScheduleService(self.db)
        
        return {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'device_health': device_service.get_device_health_summary(),
            'backup_statistics': backup_service.get_backup_statistics(),
            'schedule_summary': schedule_service.get_schedule_policies_summary(),
            'system_status': self._get_system_status()
        }
    
    def _get_system_status(self) -> Dict[str, Any]:
        """Get basic system status."""
        # Check database connectivity
        try:
            self.db.execute("SELECT 1")
            db_status = "healthy"
        except Exception:
            db_status = "unhealthy"
        
        # Get recent error count
        recent_errors = error_manager.get_error_statistics(timedelta(hours=1))
        
        return {
            'database': db_status,
            'recent_errors': recent_errors.get('total_errors', 0),
            'error_rate': 'normal' if recent_errors.get('total_errors', 0) < 10 else 'elevated'
        }
    
    def get_system_metrics(self, days_back: int = 7) -> Dict[str, Any]:
        """Get comprehensive system metrics."""
        since_date = datetime.now(timezone.utc) - timedelta(days=days_back)
        
        # Database metrics
        total_devices = self.db.query(NetworkDevice).count()
        total_templates = self.db.query(BackupCommandTemplate).count()
        total_policies = self.db.query(JobSchedulePolicy).count()
        
        # Activity metrics
        recent_backups = self.db.query(DeviceBackupInfo).filter(
            DeviceBackupInfo.created_at >= since_date
        ).count()
        
        recent_logins = self.db.query(LoginSession).filter(
            LoginSession.created_at >= since_date
        ).count()
        
        # Storage metrics
        total_backup_size = self.db.query(
            func.sum(BackupFileStorage.file_size_bytes)
        ).scalar() or 0
        
        return {
            'period_days': days_back,
            'database_metrics': {
                'total_devices': total_devices,
                'total_templates': total_templates,
                'total_policies': total_policies
            },
            'activity_metrics': {
                'recent_backups': recent_backups,
                'recent_logins': recent_logins,
                'avg_backups_per_day': recent_backups / days_back if days_back > 0 else 0
            },
            'storage_metrics': {
                'total_backup_size_bytes': int(total_backup_size),
                'total_backup_size_gb': round(total_backup_size / (1024**3), 2)
            }
        }


# Utility functions for service layer
def get_device_service(db: Session) -> DeviceService:
    """Get device service instance."""
    return DeviceService(db)


def get_backup_service(db: Session) -> BackupService:
    """Get backup service instance."""
    return BackupService(db)


def get_template_service(db: Session) -> TemplateService:
    """Get template service instance."""
    return TemplateService(db)


def get_schedule_service(db: Session) -> ScheduleService:
    """Get schedule service instance."""
    return ScheduleService(db)


def get_system_service(db: Session) -> SystemService:
    """Get system service instance."""
    return SystemService(db)