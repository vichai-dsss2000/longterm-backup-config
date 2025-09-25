"""
Job Scheduling Service for Network Device Backup System
======================================================

This module provides cron-based job scheduling using APScheduler with
background task management, job queue processing, and integration with
the backup execution engine.

Features:
- Cron-based scheduling with flexible expressions
- Background job processing with concurrent execution
- Job persistence and recovery after restarts
- Real-time job monitoring and status tracking
- Integration with database for schedule policies
- Email notifications for job completion/failures
- Resource management and throttling
- Job dependency and priority handling
"""

import logging
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
import threading
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.pool import ThreadPoolExecutor as APSThreadPoolExecutor
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED
from apscheduler.job import Job

from backup_executor import DeviceBackupExecutor, BackupJobConfig, BackupResult, BackupStatus

# Configure logging
logger = logging.getLogger(__name__)


class ScheduleStatus(Enum):
    """Schedule status enumeration."""
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    ERROR = "error"


class JobType(Enum):
    """Job type enumeration."""
    BACKUP = "backup"
    DISCOVERY = "discovery"
    MAINTENANCE = "maintenance"
    NOTIFICATION = "notification"


@dataclass
class ScheduledJobInfo:
    """Information about a scheduled job."""
    schedule_id: str
    job_type: JobType
    schedule_name: str
    cron_expression: str
    next_run_time: Optional[datetime]
    last_run_time: Optional[datetime]
    status: ScheduleStatus
    device_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    total_executions: int = 0
    last_error: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class NotificationConfig:
    """Configuration for job notifications."""
    enabled: bool = True
    email_addresses: List[str] = field(default_factory=list)
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notify_on_missed: bool = True
    include_logs: bool = True
    max_log_entries: int = 50


class DatabaseJobStore:
    """Custom job store integration with application database."""
    
    def __init__(self, database_url: str):
        self.database_url = database_url
        self.sqlalchemy_store = SQLAlchemyJobStore(url=database_url, tablename='scheduler_jobs')
    
    def get_store(self):
        """Get the SQLAlchemy job store."""
        return self.sqlalchemy_store


class NotificationManager:
    """Manages job completion notifications."""
    
    def __init__(self):
        self.notification_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
    
    def add_notification_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Add notification callback."""
        self.notification_callbacks.append(callback)
    
    def send_notification(self, notification_type: str, data: Dict[str, Any]):
        """Send notification to all registered callbacks."""
        for callback in self.notification_callbacks:
            try:
                callback(notification_type, data)
            except Exception as e:
                logger.error(f"Error in notification callback: {e}")
    
    def notify_job_success(self, job_info: Dict[str, Any], results: List[BackupResult]):
        """Send job success notification."""
        successful_devices = [r for r in results if r.status == BackupStatus.COMPLETED]
        failed_devices = [r for r in results if r.status == BackupStatus.FAILED]
        
        notification_data = {
            'job_name': job_info.get('schedule_name', 'Unknown Job'),
            'execution_time': datetime.now(timezone.utc).isoformat(),
            'total_devices': len(results),
            'successful_count': len(successful_devices),
            'failed_count': len(failed_devices),
            'successful_devices': [r.device_id for r in successful_devices],
            'failed_devices': [{'device_id': r.device_id, 'error': r.error_message} for r in failed_devices]
        }
        
        self.send_notification('job_success', notification_data)
    
    def notify_job_failure(self, job_info: Dict[str, Any], error_message: str):
        """Send job failure notification."""
        notification_data = {
            'job_name': job_info.get('schedule_name', 'Unknown Job'),
            'execution_time': datetime.now(timezone.utc).isoformat(),
            'error_message': error_message,
            'schedule_id': job_info.get('schedule_id')
        }
        
        self.send_notification('job_failure', notification_data)
    
    def notify_job_missed(self, job_info: Dict[str, Any]):
        """Send job missed notification."""
        notification_data = {
            'job_name': job_info.get('schedule_name', 'Unknown Job'),
            'scheduled_time': job_info.get('scheduled_time'),
            'schedule_id': job_info.get('schedule_id')
        }
        
        self.send_notification('job_missed', notification_data)


class BackupScheduler:
    """Main job scheduling service for backup operations."""
    
    def __init__(self, database_url: str, max_workers: int = 10, 
                 storage_path: str = "/backups"):
        self.database_url = database_url
        self.max_workers = max_workers
        self.storage_path = storage_path
        
        # Initialize components
        self.backup_executor = DeviceBackupExecutor(
            max_concurrent_jobs=max_workers,
            storage_path=storage_path
        )
        self.notification_manager = NotificationManager()
        
        # Job tracking
        self.active_schedules: Dict[str, ScheduledJobInfo] = {}
        self.running_jobs: Dict[str, Set[str]] = {}  # schedule_id -> set of job_ids
        self.job_statistics: Dict[str, Dict[str, int]] = {}
        
        # Scheduler setup
        self.job_store = DatabaseJobStore(database_url)
        self.scheduler = None
        self._setup_scheduler()
        
        # Thread safety
        self._lock = threading.RLock()
    
    def _setup_scheduler(self):
        """Initialize APScheduler with proper configuration."""
        jobstores = {
            'default': self.job_store.get_store()
        }
        
        executors = {
            'default': APSThreadPoolExecutor(max_workers=self.max_workers)
        }
        
        job_defaults = {
            'coalesce': True,  # Combine multiple pending executions
            'max_instances': 1,  # Only one instance of each job
            'misfire_grace_time': 300  # 5 minutes grace period
        }
        
        self.scheduler = BackgroundScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone='UTC'
        )
        
        # Add event listeners
        self.scheduler.add_listener(self._job_executed_listener, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(self._job_error_listener, EVENT_JOB_ERROR)
        self.scheduler.add_listener(self._job_missed_listener, EVENT_JOB_MISSED)
    
    def _job_executed_listener(self, event):
        """Handle job execution completion."""
        job_id = event.job_id
        logger.info(f"Job {job_id} executed successfully")
    
    def _job_error_listener(self, event):
        """Handle job execution errors."""
        job_id = event.job_id
        exception = event.exception
        logger.error(f"Job {job_id} failed with error: {exception}")
        
        # Update schedule statistics
        schedule_id = job_id.split('_')[0] if '_' in job_id else job_id
        if schedule_id in self.active_schedules:
            self.active_schedules[schedule_id].last_error = str(exception)
            self.active_schedules[schedule_id].updated_at = datetime.now(timezone.utc)
    
    def _job_missed_listener(self, event):
        """Handle missed job executions."""
        job_id = event.job_id
        scheduled_run_time = event.scheduled_run_time
        logger.warning(f"Job {job_id} missed execution at {scheduled_run_time}")
        
        # Send notification if configured
        schedule_id = job_id.split('_')[0] if '_' in job_id else job_id
        if schedule_id in self.active_schedules:
            job_info = {
                'schedule_id': schedule_id,
                'schedule_name': self.active_schedules[schedule_id].schedule_name,
                'scheduled_time': scheduled_run_time.isoformat()
            }
            self.notification_manager.notify_job_missed(job_info)
    
    def _execute_backup_schedule(self, schedule_policy: Dict[str, Any], 
                               devices: List[Dict[str, Any]]):
        """Execute backup job for a schedule policy."""
        schedule_id = str(schedule_policy['id'])
        schedule_name = schedule_policy.get('policy_name', f'Schedule {schedule_id}')
        
        logger.info(f"Executing backup schedule: {schedule_name} for {len(devices)} devices")
        
        try:
            with self._lock:
                if schedule_id not in self.running_jobs:
                    self.running_jobs[schedule_id] = set()
            
            # Update schedule info
            if schedule_id in self.active_schedules:
                self.active_schedules[schedule_id].last_run_time = datetime.now(timezone.utc)
                self.active_schedules[schedule_id].device_count = len(devices)
            
            # Submit backup jobs for all devices
            job_results = []
            submitted_jobs = []
            
            for device in devices:
                # Create backup job config
                job_config = BackupJobConfig(
                    job_id=f"{schedule_id}_{device['id']}_{int(datetime.now().timestamp())}",
                    device_id=device['id'],
                    device_info=device,
                    template_data=schedule_policy.get('template_data', {}),
                    schedule_policy=schedule_policy,
                    user_variables={
                        'sftp_server_ip': schedule_policy.get('sftp_server_ip'),
                        'sftp_username': schedule_policy.get('sftp_username'),
                        'sftp_password': schedule_policy.get('sftp_password_decrypted'),
                        'backup_path': schedule_policy.get('backup_path'),
                    },
                    max_retries=schedule_policy.get('retry_count', 5),
                    timeout=schedule_policy.get('timeout_seconds', 300),
                    compress_output=schedule_policy.get('compression_enabled', True),
                    verify_backup=True,
                    notification_enabled=schedule_policy.get('notification_enabled', True)
                )
                
                # Submit job
                job_id = self.backup_executor.submit_backup_job(job_config)
                submitted_jobs.append(job_id)
                
                with self._lock:
                    self.running_jobs[schedule_id].add(job_id)
            
            # Wait for jobs to complete or timeout
            self._wait_for_jobs_completion(schedule_id, submitted_jobs, timeout=3600)  # 1 hour timeout
            
            # Collect results
            successful_jobs = 0
            failed_jobs = 0
            
            for job_id in submitted_jobs:
                result = self.backup_executor.get_job_status(job_id)
                if result:
                    job_results.append(result)
                    if result.status == BackupStatus.COMPLETED:
                        successful_jobs += 1
                    elif result.status == BackupStatus.FAILED:
                        failed_jobs += 1
            
            # Update statistics
            if schedule_id in self.active_schedules:
                self.active_schedules[schedule_id].success_count += successful_jobs
                self.active_schedules[schedule_id].failure_count += failed_jobs
                self.active_schedules[schedule_id].total_executions += 1
                self.active_schedules[schedule_id].updated_at = datetime.now(timezone.utc)
            
            # Send notifications
            if schedule_policy.get('notification_enabled', True):
                if failed_jobs == 0:
                    self.notification_manager.notify_job_success(
                        {'schedule_id': schedule_id, 'schedule_name': schedule_name},
                        job_results
                    )
                else:
                    # If some jobs failed, send failure notification with details
                    error_details = [f"{r.device_id}: {r.error_message}" 
                                   for r in job_results if r.status == BackupStatus.FAILED]
                    self.notification_manager.notify_job_failure(
                        {'schedule_id': schedule_id, 'schedule_name': schedule_name},
                        f"Backup failed for {failed_jobs} devices: {'; '.join(error_details[:5])}"
                    )
            
            logger.info(f"Schedule {schedule_name} completed: {successful_jobs} successful, {failed_jobs} failed")
            
        except Exception as e:
            logger.error(f"Error executing backup schedule {schedule_name}: {e}")
            self.notification_manager.notify_job_failure(
                {'schedule_id': schedule_id, 'schedule_name': schedule_name},
                f"Schedule execution error: {str(e)}"
            )
        
        finally:
            # Clean up running jobs tracking
            with self._lock:
                if schedule_id in self.running_jobs:
                    del self.running_jobs[schedule_id]
    
    def _wait_for_jobs_completion(self, schedule_id: str, job_ids: List[str], timeout: int = 3600):
        """Wait for all jobs in a schedule to complete."""
        start_time = datetime.now()
        
        while True:
            # Check if all jobs are complete
            all_complete = True
            for job_id in job_ids:
                result = self.backup_executor.get_job_status(job_id)
                if result and result.status in [BackupStatus.PENDING, BackupStatus.RUNNING, BackupStatus.RETRYING]:
                    all_complete = False
                    break
            
            if all_complete:
                break
            
            # Check timeout
            if (datetime.now() - start_time).total_seconds() > timeout:
                logger.warning(f"Schedule {schedule_id} jobs timed out after {timeout} seconds")
                break
            
            # Wait a bit before checking again
            asyncio.sleep(5)
    
    def add_backup_schedule(self, schedule_policy: Dict[str, Any], 
                          device_query_func: Callable[[], List[Dict[str, Any]]]) -> str:
        """Add a new backup schedule."""
        schedule_id = str(schedule_policy['id'])
        schedule_name = schedule_policy.get('policy_name', f'Schedule {schedule_id}')
        cron_expression = schedule_policy.get('cron_expression', '0 2 * * *')  # Default: 2 AM daily
        
        logger.info(f"Adding backup schedule: {schedule_name} with cron: {cron_expression}")
        
        try:
            # Create schedule info
            schedule_info = ScheduledJobInfo(
                schedule_id=schedule_id,
                job_type=JobType.BACKUP,
                schedule_name=schedule_name,
                cron_expression=cron_expression,
                status=ScheduleStatus.ACTIVE,
                next_run_time=None
            )
            
            # Add to scheduler
            job = self.scheduler.add_job(
                func=self._execute_backup_schedule,
                trigger=CronTrigger.from_crontab(cron_expression),
                args=[schedule_policy, device_query_func()],
                id=schedule_id,
                name=schedule_name,
                replace_existing=True
            )
            
            schedule_info.next_run_time = job.next_run_time
            
            # Store schedule info
            with self._lock:
                self.active_schedules[schedule_id] = schedule_info
            
            logger.info(f"Schedule {schedule_name} added successfully, next run: {job.next_run_time}")
            return schedule_id
            
        except Exception as e:
            logger.error(f"Error adding backup schedule {schedule_name}: {e}")
            raise
    
    def remove_schedule(self, schedule_id: str) -> bool:
        """Remove a backup schedule."""
        try:
            self.scheduler.remove_job(schedule_id)
            
            with self._lock:
                if schedule_id in self.active_schedules:
                    del self.active_schedules[schedule_id]
                if schedule_id in self.running_jobs:
                    # Cancel running jobs
                    for job_id in self.running_jobs[schedule_id]:
                        self.backup_executor.cancel_job(job_id)
                    del self.running_jobs[schedule_id]
            
            logger.info(f"Schedule {schedule_id} removed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error removing schedule {schedule_id}: {e}")
            return False
    
    def pause_schedule(self, schedule_id: str) -> bool:
        """Pause a backup schedule."""
        try:
            self.scheduler.pause_job(schedule_id)
            
            with self._lock:
                if schedule_id in self.active_schedules:
                    self.active_schedules[schedule_id].status = ScheduleStatus.PAUSED
            
            logger.info(f"Schedule {schedule_id} paused")
            return True
            
        except Exception as e:
            logger.error(f"Error pausing schedule {schedule_id}: {e}")
            return False
    
    def resume_schedule(self, schedule_id: str) -> bool:
        """Resume a paused backup schedule."""
        try:
            self.scheduler.resume_job(schedule_id)
            
            with self._lock:
                if schedule_id in self.active_schedules:
                    self.active_schedules[schedule_id].status = ScheduleStatus.ACTIVE
            
            logger.info(f"Schedule {schedule_id} resumed")
            return True
            
        except Exception as e:
            logger.error(f"Error resuming schedule {schedule_id}: {e}")
            return False
    
    def trigger_schedule_now(self, schedule_id: str) -> bool:
        """Trigger a schedule to run immediately."""
        try:
            job = self.scheduler.get_job(schedule_id)
            if job:
                self.scheduler.modify_job(schedule_id, next_run_time=datetime.now(timezone.utc))
                logger.info(f"Schedule {schedule_id} triggered to run now")
                return True
            else:
                logger.warning(f"Schedule {schedule_id} not found")
                return False
                
        except Exception as e:
            logger.error(f"Error triggering schedule {schedule_id}: {e}")
            return False
    
    def get_schedule_info(self, schedule_id: str) -> Optional[ScheduledJobInfo]:
        """Get information about a specific schedule."""
        with self._lock:
            return self.active_schedules.get(schedule_id)
    
    def get_all_schedules(self) -> Dict[str, ScheduledJobInfo]:
        """Get information about all active schedules."""
        with self._lock:
            return self.active_schedules.copy()
    
    def get_running_jobs(self) -> Dict[str, List[BackupResult]]:
        """Get currently running jobs for all schedules."""
        running_jobs = {}
        
        with self._lock:
            for schedule_id, job_ids in self.running_jobs.items():
                schedule_jobs = []
                for job_id in job_ids:
                    result = self.backup_executor.get_job_status(job_id)
                    if result:
                        schedule_jobs.append(result)
                if schedule_jobs:
                    running_jobs[schedule_id] = schedule_jobs
        
        return running_jobs
    
    def start_scheduler(self):
        """Start the job scheduler."""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Backup scheduler started")
        else:
            logger.warning("Scheduler is already running")
    
    def stop_scheduler(self):
        """Stop the job scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            logger.info("Backup scheduler stopped")
        else:
            logger.warning("Scheduler is not running")
    
    def shutdown(self):
        """Shutdown scheduler and all components."""
        logger.info("Shutting down backup scheduler...")
        
        # Stop scheduler
        self.stop_scheduler()
        
        # Cancel all running jobs
        with self._lock:
            for schedule_id, job_ids in self.running_jobs.items():
                for job_id in job_ids:
                    self.backup_executor.cancel_job(job_id)
        
        # Shutdown backup executor
        self.backup_executor.shutdown()
        
        logger.info("Backup scheduler shutdown complete")


# Global scheduler instance
backup_scheduler: Optional[BackupScheduler] = None


def initialize_scheduler(database_url: str, max_workers: int = 10, 
                        storage_path: str = "/backups") -> BackupScheduler:
    """Initialize global backup scheduler."""
    global backup_scheduler
    
    if backup_scheduler is None:
        backup_scheduler = BackupScheduler(database_url, max_workers, storage_path)
        backup_scheduler.start_scheduler()
    
    return backup_scheduler


def get_scheduler() -> Optional[BackupScheduler]:
    """Get global backup scheduler instance."""
    return backup_scheduler


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.DEBUG)
    
    # Test database URL (use in-memory SQLite for testing)
    test_db_url = "sqlite:///test_scheduler.db"
    
    # Initialize scheduler
    scheduler = initialize_scheduler(test_db_url, max_workers=5)
    
    # Example schedule policy
    test_schedule = {
        'id': 1,
        'policy_name': 'Daily Network Backup',
        'cron_expression': '0 2 * * *',  # 2 AM daily
        'template_data': {
            'backup_command': 'show running-config',
            'command_format': 'TEXT'
        },
        'sftp_server_ip': '192.168.1.200',
        'sftp_username': 'backup_user',
        'backup_path': '/network-backups',
        'notification_enabled': True
    }
    
    # Example device query function
    def get_test_devices():
        return [
            {
                'id': 1,
                'device_name': 'test-switch-01',
                'ip_address': '192.168.1.100',
                'ssh_username': 'admin',
                'ssh_password_decrypted': 'password',
                'netmiko_device_type': 'cisco_ios'
            }
        ]
    
    # Add schedule
    schedule_id = scheduler.add_backup_schedule(test_schedule, get_test_devices)
    print(f"Added schedule: {schedule_id}")
    
    # Get schedule info
    info = scheduler.get_schedule_info(schedule_id)
    print(f"Schedule info: {info}")
    
    # Keep running for a while for testing
    import time
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.shutdown()