"""
Device Backup Execution Engine
=============================

This module provides the main backup execution engine that processes device
backup jobs using templates, handles different configuration formats, and 
manages file storage with comprehensive error handling and retry logic.

Features:
- Multi-format configuration backup (XML, YAML, JSON, TEXT)
- Template-based command execution
- Concurrent backup processing with job queuing
- Comprehensive error handling and retry mechanisms
- File storage management with integrity verification
- Progress tracking and status reporting
- Background job processing with APScheduler integration
"""

import logging
import asyncio
import time
import hashlib
import gzip
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import yaml
import xml.etree.ElementTree as ET

from ssh_connection import SSHConnectionManager, DeviceCredentials, create_device_credentials
from template_processor import BackupCommandTemplateManager, ProcessedTemplate

# Configure logging
logger = logging.getLogger(__name__)


class BackupStatus(Enum):
    """Backup job status enumeration."""
    PENDING = "pending"
    RUNNING = "running" 
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"


class BackupFormat(Enum):
    """Supported backup configuration formats."""
    TEXT = "TEXT"
    JSON = "JSON"
    XML = "XML"
    YAML = "YAML"


@dataclass
class BackupJobConfig:
    """Configuration for a backup job."""
    job_id: str
    device_id: int
    device_info: Dict[str, Any]
    template_data: Dict[str, Any]
    schedule_policy: Dict[str, Any]
    user_variables: Optional[Dict[str, Any]] = None
    priority: int = 5  # 1-10, lower is higher priority
    max_retries: int = 5
    retry_interval: int = 60  # seconds
    timeout: int = 300  # seconds
    compress_output: bool = True
    verify_backup: bool = True
    notification_enabled: bool = True


@dataclass
class BackupResult:
    """Result of a backup operation."""
    job_id: str
    device_id: int
    status: BackupStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    backup_content: Optional[str] = None
    backup_file_path: Optional[str] = None
    file_size_bytes: int = 0
    file_hash: Optional[str] = None
    compression_ratio: Optional[float] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    execution_log: List[Dict[str, Any]] = field(default_factory=list)
    template_processing_result: Optional[ProcessedTemplate] = None
    
    def add_log_entry(self, level: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Add entry to execution log."""
        entry = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'level': level,
            'message': message
        }
        if details:
            entry['details'] = details
        self.execution_log.append(entry)
        
        # Also log to system logger
        logger_method = getattr(logger, level.lower(), logger.info)
        logger_method(f"Job {self.job_id}: {message}")


class BackupConfigurationParser:
    """Parser for different configuration formats."""
    
    @staticmethod
    def parse_configuration(content: str, format_type: BackupFormat) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Parse configuration content based on format type."""
        try:
            if format_type == BackupFormat.JSON:
                parsed = json.loads(content)
                return True, {'parsed_config': parsed, 'format': 'json'}, None
                
            elif format_type == BackupFormat.YAML:
                parsed = yaml.safe_load(content)
                return True, {'parsed_config': parsed, 'format': 'yaml'}, None
                
            elif format_type == BackupFormat.XML:
                root = ET.fromstring(content)
                # Convert XML to dict representation
                parsed = BackupConfigurationParser._xml_to_dict(root)
                return True, {'parsed_config': parsed, 'format': 'xml'}, None
                
            else:  # TEXT format
                # For text format, perform basic analysis
                lines = content.split('\n')
                config_stats = {
                    'total_lines': len(lines),
                    'non_empty_lines': len([line for line in lines if line.strip()]),
                    'comment_lines': len([line for line in lines if line.strip().startswith('!')]),
                    'format': 'text'
                }
                return True, config_stats, None
                
        except (json.JSONDecodeError, yaml.YAMLError, ET.ParseError) as e:
            return False, {}, f"Configuration parsing error: {str(e)}"
        except Exception as e:
            return False, {}, f"Unexpected parsing error: {str(e)}"
    
    @staticmethod
    def _xml_to_dict(element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        
        # Add attributes
        if element.attrib:
            result['@attributes'] = element.attrib
        
        # Add text content
        if element.text and element.text.strip():
            if len(list(element)) == 0:
                return element.text.strip()
            else:
                result['text'] = element.text.strip()
        
        # Add children
        children = {}
        for child in element:
            child_data = BackupConfigurationParser._xml_to_dict(child)
            if child.tag in children:
                if not isinstance(children[child.tag], list):
                    children[child.tag] = [children[child.tag]]
                children[child.tag].append(child_data)
            else:
                children[child.tag] = child_data
        
        result.update(children)
        return result
    
    @staticmethod
    def validate_configuration(content: str, format_type: BackupFormat) -> Tuple[bool, List[str]]:
        """Validate configuration content."""
        warnings = []
        
        if not content or not content.strip():
            return False, ["Configuration content is empty"]
        
        # Format-specific validation
        success, parsed_data, error = BackupConfigurationParser.parse_configuration(content, format_type)
        if not success:
            return False, [error]
        
        # General validation checks
        if len(content) < 50:
            warnings.append("Configuration seems unusually short")
        
        if format_type == BackupFormat.TEXT:
            # Check for common configuration indicators
            common_keywords = ['interface', 'ip', 'router', 'vlan', 'access-list', 'route']
            found_keywords = [kw for kw in common_keywords if kw in content.lower()]
            if not found_keywords:
                warnings.append("No common network configuration keywords found")
        
        return True, warnings


class FileStorageManager:
    """Manages backup file storage operations."""
    
    def __init__(self, base_storage_path: str = "/backups"):
        self.base_storage_path = Path(base_storage_path)
        self.base_storage_path.mkdir(parents=True, exist_ok=True)
    
    def generate_backup_filename(self, device_name: str, timestamp: Optional[datetime] = None, 
                                file_extension: str = "cfg") -> str:
        """Generate standardized backup filename."""
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)
        
        # Sanitize device name
        safe_device_name = "".join(c for c in device_name if c.isalnum() or c in "-_")
        timestamp_str = timestamp.strftime("%Y%m%d_%H%M%S")
        
        return f"{safe_device_name}_{timestamp_str}.{file_extension}"
    
    def calculate_file_hash(self, content: str) -> str:
        """Calculate SHA256 hash of content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    def compress_content(self, content: str) -> Tuple[bytes, float]:
        """Compress content using gzip and return compressed data and ratio."""
        original_size = len(content.encode('utf-8'))
        compressed_data = gzip.compress(content.encode('utf-8'))
        compressed_size = len(compressed_data)
        
        compression_ratio = compressed_size / original_size if original_size > 0 else 1.0
        
        return compressed_data, compression_ratio
    
    def save_backup_file(self, content: str, device_name: str, job_id: str,
                        compress: bool = True) -> Tuple[str, Dict[str, Any]]:
        """Save backup content to file and return path and metadata."""
        timestamp = datetime.now(timezone.utc)
        
        # Create directory structure: /backups/YYYY/MM/DD/
        date_path = self.base_storage_path / timestamp.strftime("%Y") / timestamp.strftime("%m") / timestamp.strftime("%d")
        date_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        base_filename = self.generate_backup_filename(device_name, timestamp)
        
        if compress:
            filename = f"{base_filename}.gz"
            compressed_data, compression_ratio = self.compress_content(content)
            file_path = date_path / filename
            
            with open(file_path, 'wb') as f:
                f.write(compressed_data)
                
            file_size = len(compressed_data)
        else:
            filename = base_filename
            file_path = date_path / filename
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
                
            file_size = len(content.encode('utf-8'))
            compression_ratio = 1.0
        
        # Calculate hash of original content
        file_hash = self.calculate_file_hash(content)
        
        metadata = {
            'file_path': str(file_path),
            'file_size_bytes': file_size,
            'file_hash': file_hash,
            'compression_ratio': compression_ratio,
            'compressed': compress,
            'timestamp': timestamp.isoformat(),
            'job_id': job_id
        }
        
        logger.info(f"Saved backup file: {file_path} ({file_size} bytes, compression: {compression_ratio:.2f})")
        
        return str(file_path), metadata
    
    def verify_backup_file(self, file_path: str, expected_hash: str) -> Tuple[bool, Optional[str]]:
        """Verify backup file integrity."""
        try:
            path = Path(file_path)
            if not path.exists():
                return False, "File does not exist"
            
            # Read and decompress if needed
            if file_path.endswith('.gz'):
                with gzip.open(path, 'rt', encoding='utf-8') as f:
                    content = f.read()
            else:
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()
            
            # Calculate hash and compare
            actual_hash = self.calculate_file_hash(content)
            if actual_hash == expected_hash:
                return True, None
            else:
                return False, f"Hash mismatch: expected {expected_hash}, got {actual_hash}"
                
        except Exception as e:
            return False, f"Verification error: {str(e)}"


class DeviceBackupExecutor:
    """Main device backup execution engine."""
    
    def __init__(self, max_concurrent_jobs: int = 10, storage_path: str = "/backups"):
        self.max_concurrent_jobs = max_concurrent_jobs
        self.ssh_manager = SSHConnectionManager(max_concurrent_connections=max_concurrent_jobs)
        self.template_manager = BackupCommandTemplateManager()
        self.storage_manager = FileStorageManager(storage_path)
        self.config_parser = BackupConfigurationParser()
        
        # Job tracking
        self.active_jobs: Dict[str, BackupResult] = {}
        self.job_queue: List[BackupJobConfig] = []
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_jobs)
        
        # Callbacks for job status updates
        self.status_callbacks: List[Callable[[BackupResult], None]] = []
    
    def add_status_callback(self, callback: Callable[[BackupResult], None]):
        """Add callback for job status updates."""
        self.status_callbacks.append(callback)
    
    def _notify_status_change(self, result: BackupResult):
        """Notify all callbacks of status change."""
        for callback in self.status_callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Error in status callback: {e}")
    
    def _execute_backup_commands(self, job_config: BackupJobConfig) -> Tuple[bool, str, Optional[str]]:
        """Execute backup commands on device."""
        try:
            # Create device credentials
            credentials = create_device_credentials(job_config.device_info)
            
            # Process template to get backup commands
            template_result = self.template_manager.process_backup_command(
                job_config.template_data,
                job_config.device_info,
                job_config.user_variables
            )
            
            if not template_result.success:
                return False, "", f"Template processing failed: {template_result.error_message}"
            
            # Parse commands (might be multiple commands separated by newlines)
            commands = [cmd.strip() for cmd in template_result.processed_content.split('\n') if cmd.strip()]
            
            # Execute commands
            all_output = []
            with self.ssh_manager.get_connection(credentials, max_retries=3) as conn:
                for command in commands:
                    try:
                        # Execute command with timeout
                        output = conn.send_command(command, timeout=job_config.timeout)
                        all_output.append(f"Command: {command}\nOutput:\n{output}\n" + "="*50)
                        
                        # For file transfer commands, we might not get useful output
                        if 'copy' in command.lower() or 'sftp' in command.lower():
                            # Add a delay to allow file transfer to complete
                            time.sleep(2)
                    
                    except Exception as cmd_error:
                        error_msg = f"Error executing command '{command}': {str(cmd_error)}"
                        all_output.append(f"Command: {command}\nError: {error_msg}\n" + "="*50)
                        return False, '\n'.join(all_output), error_msg
            
            backup_content = '\n'.join(all_output)
            return True, backup_content, None
            
        except Exception as e:
            return False, "", f"Backup execution error: {str(e)}"
    
    def _execute_single_backup(self, job_config: BackupJobConfig) -> BackupResult:
        """Execute a single backup job."""
        result = BackupResult(
            job_id=job_config.job_id,
            device_id=job_config.device_id,
            status=BackupStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        result.add_log_entry("info", f"Starting backup for device {job_config.device_info.get('device_name')}")
        
        try:
            # Update status to running
            self.active_jobs[job_config.job_id] = result
            self._notify_status_change(result)
            
            # Execute backup commands
            success, backup_content, error_msg = self._execute_backup_commands(job_config)
            
            if not success:
                result.status = BackupStatus.FAILED
                result.error_message = error_msg
                result.add_log_entry("error", f"Backup execution failed: {error_msg}")
            else:
                # Parse and validate configuration
                format_type = BackupFormat(job_config.template_data.get('command_format', 'TEXT'))
                config_valid, warnings = self.config_parser.validate_configuration(backup_content, format_type)
                
                if not config_valid and job_config.verify_backup:
                    result.status = BackupStatus.FAILED
                    result.error_message = f"Configuration validation failed: {warnings}"
                    result.add_log_entry("error", f"Configuration validation failed: {warnings}")
                else:
                    if warnings:
                        result.add_log_entry("warning", f"Configuration warnings: {warnings}")
                    
                    # Save backup file
                    try:
                        file_path, metadata = self.storage_manager.save_backup_file(
                            backup_content,
                            job_config.device_info.get('device_name', f"device_{job_config.device_id}"),
                            job_config.job_id,
                            compress=job_config.compress_output
                        )
                        
                        result.backup_content = backup_content
                        result.backup_file_path = file_path
                        result.file_size_bytes = metadata['file_size_bytes']
                        result.file_hash = metadata['file_hash']
                        result.compression_ratio = metadata['compression_ratio']
                        
                        # Verify file if requested
                        if job_config.verify_backup:
                            verify_success, verify_error = self.storage_manager.verify_backup_file(
                                file_path, metadata['file_hash']
                            )
                            if not verify_success:
                                result.add_log_entry("warning", f"File verification failed: {verify_error}")
                        
                        result.status = BackupStatus.COMPLETED
                        result.add_log_entry("info", f"Backup completed successfully: {file_path}")
                        
                    except Exception as storage_error:
                        result.status = BackupStatus.FAILED
                        result.error_message = f"Storage error: {str(storage_error)}"
                        result.add_log_entry("error", f"Storage error: {str(storage_error)}")
            
        except Exception as e:
            result.status = BackupStatus.FAILED
            result.error_message = f"Unexpected error: {str(e)}"
            result.add_log_entry("error", f"Unexpected error: {str(e)}")
        
        finally:
            result.end_time = datetime.now(timezone.utc)
            self._notify_status_change(result)
        
        return result
    
    def _execute_backup_with_retry(self, job_config: BackupJobConfig) -> BackupResult:
        """Execute backup with retry logic."""
        last_result = None
        
        for attempt in range(job_config.max_retries + 1):
            if attempt > 0:
                # Wait before retry
                result = BackupResult(
                    job_id=job_config.job_id,
                    device_id=job_config.device_id,
                    status=BackupStatus.RETRYING,
                    start_time=datetime.now(timezone.utc),
                    retry_count=attempt
                )
                result.add_log_entry("info", f"Retrying backup (attempt {attempt + 1}/{job_config.max_retries + 1})")
                self._notify_status_change(result)
                
                time.sleep(job_config.retry_interval * (2 ** (attempt - 1)))  # Exponential backoff
            
            # Execute backup
            result = self._execute_single_backup(job_config)
            result.retry_count = attempt
            last_result = result
            
            # If successful, break out of retry loop
            if result.status == BackupStatus.COMPLETED:
                break
            
            # Log retry attempt
            if attempt < job_config.max_retries:
                result.add_log_entry("warning", f"Backup attempt {attempt + 1} failed, will retry")
        
        # Final status update
        if last_result and last_result.status != BackupStatus.COMPLETED:
            last_result.add_log_entry("error", f"Backup failed after {job_config.max_retries + 1} attempts")
        
        return last_result
    
    def submit_backup_job(self, job_config: BackupJobConfig) -> str:
        """Submit backup job for execution."""
        logger.info(f"Submitting backup job {job_config.job_id} for device {job_config.device_info.get('device_name')}")
        
        # Add job to queue
        self.job_queue.append(job_config)
        
        # Submit to executor
        future = self.executor.submit(self._execute_backup_with_retry, job_config)
        
        # Initial status
        initial_result = BackupResult(
            job_id=job_config.job_id,
            device_id=job_config.device_id,
            status=BackupStatus.PENDING,
            start_time=datetime.now(timezone.utc)
        )
        self.active_jobs[job_config.job_id] = initial_result
        self._notify_status_change(initial_result)
        
        return job_config.job_id
    
    def get_job_status(self, job_id: str) -> Optional[BackupResult]:
        """Get status of specific job."""
        return self.active_jobs.get(job_id)
    
    def get_all_active_jobs(self) -> Dict[str, BackupResult]:
        """Get all active job statuses."""
        return self.active_jobs.copy()
    
    def cancel_job(self, job_id: str) -> bool:
        """Cancel a pending or running job."""
        if job_id in self.active_jobs:
            result = self.active_jobs[job_id]
            if result.status in [BackupStatus.PENDING, BackupStatus.RUNNING, BackupStatus.RETRYING]:
                result.status = BackupStatus.CANCELLED
                result.add_log_entry("info", "Job cancelled by user")
                self._notify_status_change(result)
                return True
        return False
    
    def cleanup_completed_jobs(self, max_age_hours: int = 24):
        """Clean up old completed jobs from memory."""
        cutoff_time = datetime.now(timezone.utc).timestamp() - (max_age_hours * 3600)
        
        jobs_to_remove = []
        for job_id, result in self.active_jobs.items():
            if (result.status in [BackupStatus.COMPLETED, BackupStatus.FAILED, BackupStatus.CANCELLED] and
                result.end_time and result.end_time.timestamp() < cutoff_time):
                jobs_to_remove.append(job_id)
        
        for job_id in jobs_to_remove:
            del self.active_jobs[job_id]
        
        logger.info(f"Cleaned up {len(jobs_to_remove)} old job records")
    
    def shutdown(self):
        """Shutdown executor and cleanup resources."""
        logger.info("Shutting down backup executor...")
        self.executor.shutdown(wait=True)
        self.ssh_manager.close_all_connections()
        logger.info("Backup executor shutdown complete")


# Convenience function for single device backup
def backup_device(device_info: Dict[str, Any], template_data: Dict[str, Any],
                 user_variables: Optional[Dict[str, Any]] = None,
                 storage_path: str = "/backups") -> BackupResult:
    """Execute backup for single device (synchronous)."""
    
    executor = DeviceBackupExecutor(storage_path=storage_path)
    
    job_config = BackupJobConfig(
        job_id=f"manual_{device_info['device_name']}_{int(time.time())}",
        device_id=device_info.get('id', 0),
        device_info=device_info,
        template_data=template_data,
        schedule_policy={},
        user_variables=user_variables or {}
    )
    
    try:
        result = executor._execute_backup_with_retry(job_config)
        return result
    finally:
        executor.shutdown()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.DEBUG)
    
    # Test device info
    test_device = {
        'id': 1,
        'device_name': 'test-switch-01',
        'ip_address': '192.168.1.100',
        'hostname': 'sw01',
        'device_type': 'cisco_ios',
        'ssh_username': 'admin',
        'ssh_password_decrypted': 'password',
        'netmiko_device_type': 'cisco_ios'
    }
    
    # Test template
    test_template = {
        'backup_command': 'show running-config',
        'command_format': 'TEXT',
        'template_variables': json.dumps({})
    }
    
    # Test backup
    result = backup_device(test_device, test_template)
    print(f"Backup result: {result.status}")
    print(f"File path: {result.backup_file_path}")
    if result.error_message:
        print(f"Error: {result.error_message}")