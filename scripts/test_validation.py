"""
Testing and Validation Utilities
===============================

This module provides comprehensive testing, validation, and health check
utilities for the network device backup system. It includes connection
testing, template validation, backup verification, and system health
monitoring capabilities.

Features:
- Connection testing and device reachability verification
- Template syntax validation and variable checking
- Backup integrity verification and restoration testing
- System health monitoring and diagnostics
- Performance benchmarking and load testing
- Configuration validation and compliance checking
- Automated testing suites and regression testing
- Health dashboard and reporting
"""

import logging
import asyncio
import time
import json
import tempfile
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import statistics

from ssh_connection import SSHConnectionManager, DeviceCredentials, create_device_credentials
from template_processor import BackupCommandTemplateManager, TemplateContext, ProcessedTemplate
from backup_executor import DeviceBackupExecutor, BackupJobConfig, BackupResult, BackupStatus
from file_storage import storage_manager, StorageConfig, StorageType
from device_discovery import DeviceDiscoveryManager, DiscoveredDevice
from error_handling import error_manager, ErrorInfo, ErrorCategory

# Configure logging
logger = logging.getLogger(__name__)


class TestStatus(Enum):
    """Test execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"


class TestCategory(Enum):
    """Test category classification."""
    CONNECTIVITY = "connectivity"
    AUTHENTICATION = "authentication"
    TEMPLATE = "template"
    BACKUP = "backup"
    STORAGE = "storage"
    PERFORMANCE = "performance"
    SYSTEM = "system"
    INTEGRATION = "integration"


@dataclass
class TestResult:
    """Individual test result."""
    test_id: str
    test_name: str
    category: TestCategory
    status: TestStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    warnings: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


@dataclass
class TestSuite:
    """Collection of related tests."""
    suite_id: str
    suite_name: str
    description: str
    tests: List[Callable] = field(default_factory=list)
    setup_func: Optional[Callable] = None
    teardown_func: Optional[Callable] = None
    tags: Set[str] = field(default_factory=set)


@dataclass
class SystemHealthStatus:
    """Overall system health status."""
    overall_status: str  # healthy, warning, critical
    timestamp: datetime
    component_statuses: Dict[str, TestResult] = field(default_factory=dict)
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    resource_usage: Dict[str, float] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)


class ConnectionTester:
    """Tests network connectivity and device authentication."""
    
    def __init__(self):
        self.ssh_manager = SSHConnectionManager()
    
    def test_device_connectivity(self, device_info: Dict[str, Any]) -> TestResult:
        """Test basic connectivity to a device."""
        test_result = TestResult(
            test_id=f"connectivity_{device_info.get('id', 'unknown')}",
            test_name=f"Device Connectivity - {device_info.get('device_name', 'Unknown')}",
            category=TestCategory.CONNECTIVITY,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Test basic network reachability
            import subprocess
            import sys
            
            ip_address = device_info.get('ip_address')
            if not ip_address:
                raise ValueError("No IP address provided")
            
            # Ping test
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', '3000', ip_address]
            else:
                cmd = ['ping', '-c', '1', '-W', '3', ip_address]
            
            ping_result = subprocess.run(cmd, capture_output=True, timeout=5)
            
            if ping_result.returncode != 0:
                test_result.status = TestStatus.FAILED
                test_result.error_message = f"Ping failed to {ip_address}"
                test_result.recommendations.append("Check network connectivity and firewall rules")
            else:
                test_result.status = TestStatus.PASSED
                test_result.details['ping_success'] = True
                
                # Test port connectivity
                port_test = self._test_port_connectivity(ip_address, device_info.get('ssh_port', 22))
                test_result.details['port_test'] = port_test
                
                if not port_test['success']:
                    test_result.status = TestStatus.WARNING
                    test_result.warnings.append(f"SSH port {port_test['port']} is not reachable")
                    test_result.recommendations.append("Check SSH service status and port configuration")
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
            test_result.recommendations.append("Verify device IP address and network configuration")
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result
    
    def test_device_authentication(self, device_info: Dict[str, Any]) -> TestResult:
        """Test SSH authentication to a device."""
        test_result = TestResult(
            test_id=f"auth_{device_info.get('id', 'unknown')}",
            test_name=f"Device Authentication - {device_info.get('device_name', 'Unknown')}",
            category=TestCategory.AUTHENTICATION,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            credentials = create_device_credentials(device_info)
            
            # Test SSH connection and authentication
            connection_result = self.ssh_manager.test_connection(credentials)
            
            if connection_result.success:
                test_result.status = TestStatus.PASSED
                test_result.details['authentication_success'] = True
                test_result.details['device_info'] = connection_result.device_info
                
                # Test basic command execution
                try:
                    cmd_result = self.ssh_manager.execute_command(credentials, "show version", timeout=10)
                    if cmd_result['success']:
                        test_result.details['command_execution'] = True
                        test_result.details['command_output_length'] = len(cmd_result['output'])
                    else:
                        test_result.warnings.append("Basic command execution failed")
                        test_result.recommendations.append("Check user privileges and command authorization")
                except Exception as cmd_error:
                    test_result.warnings.append(f"Command execution test failed: {cmd_error}")
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = connection_result.error_message
                test_result.recommendations.extend([
                    "Verify username and password credentials",
                    "Check user account status and permissions",
                    "Verify SSH key configuration if using key-based auth"
                ])
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result
    
    def _test_port_connectivity(self, ip_address: str, port: int, timeout: int = 3) -> Dict[str, Any]:
        """Test connectivity to specific port."""
        import socket
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            
            return {
                'success': result == 0,
                'port': port,
                'response_time': timeout if result != 0 else None
            }
        except Exception as e:
            return {
                'success': False,
                'port': port,
                'error': str(e)
            }


class TemplateValidator:
    """Validates backup templates and command processing."""
    
    def __init__(self):
        self.template_manager = BackupCommandTemplateManager()
    
    def validate_template_syntax(self, template_data: Dict[str, Any]) -> TestResult:
        """Validate template syntax and structure."""
        test_result = TestResult(
            test_id=f"template_syntax_{template_data.get('id', 'unknown')}",
            test_name=f"Template Syntax - {template_data.get('template_name', 'Unknown')}",
            category=TestCategory.TEMPLATE,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Load template content
            template_content, template_variables = self.template_manager.load_template_from_db(template_data)
            
            if not template_content:
                test_result.status = TestStatus.FAILED
                test_result.error_message = "Template content is empty"
                test_result.recommendations.append("Provide valid template content")
                return test_result
            
            # Validate syntax
            syntax_valid, syntax_errors = self.template_manager.processor.validate_template_syntax(template_content)
            
            if syntax_valid:
                test_result.status = TestStatus.PASSED
                test_result.details['syntax_valid'] = True
                test_result.details['template_length'] = len(template_content)
                test_result.details['variable_count'] = len(template_variables)
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = f"Syntax errors: {'; '.join(syntax_errors)}"
                test_result.recommendations.append("Fix template syntax errors")
            
            # Extract and validate variables
            extracted_vars = self.template_manager.processor._extract_template_variables(template_content)
            test_result.details['extracted_variables'] = extracted_vars
            
            # Check for undefined variables
            defined_var_names = [var.name for var in template_variables]
            undefined_vars = [var for var in extracted_vars if var not in defined_var_names]
            
            if undefined_vars:
                test_result.warnings.append(f"Undefined variables found: {undefined_vars}")
                test_result.recommendations.append("Define all variables used in template")
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result
    
    def test_template_processing(self, template_data: Dict[str, Any], 
                               test_device_info: Dict[str, Any]) -> TestResult:
        """Test template processing with sample data."""
        test_result = TestResult(
            test_id=f"template_process_{template_data.get('id', 'unknown')}",
            test_name=f"Template Processing - {template_data.get('template_name', 'Unknown')}",
            category=TestCategory.TEMPLATE,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Create test variables
            test_variables = {
                'sftp_server_ip': '192.168.1.200',
                'sftp_username': 'test_user',
                'sftp_password': 'test_password',
                'backup_path': '/test/backups'
            }
            
            # Process template
            result = self.template_manager.process_backup_command(
                template_data, test_device_info, test_variables
            )
            
            if result.success:
                test_result.status = TestStatus.PASSED
                test_result.details['processing_success'] = True
                test_result.details['processed_content'] = result.processed_content
                test_result.details['variables_used'] = list(result.variables_used.keys())
                test_result.details['processing_time'] = result.processing_time
                
                if result.warnings:
                    test_result.warnings.extend(result.warnings)
                    test_result.recommendations.append("Address template processing warnings")
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = result.error_message
                test_result.recommendations.append("Fix template processing errors")
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result


class BackupTester:
    """Tests backup operations and verification."""
    
    def __init__(self):
        self.backup_executor = DeviceBackupExecutor(max_concurrent_jobs=1, storage_path="/tmp/test_backups")
    
    def test_backup_execution(self, device_info: Dict[str, Any], 
                            template_data: Dict[str, Any]) -> TestResult:
        """Test end-to-end backup execution."""
        test_result = TestResult(
            test_id=f"backup_exec_{device_info.get('id', 'unknown')}",
            test_name=f"Backup Execution - {device_info.get('device_name', 'Unknown')}",
            category=TestCategory.BACKUP,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Create test backup job
            job_config = BackupJobConfig(
                job_id=f"test_backup_{int(time.time())}",
                device_id=device_info.get('id', 0),
                device_info=device_info,
                template_data=template_data,
                schedule_policy={},
                user_variables={
                    'sftp_server_ip': '192.168.1.200',
                    'sftp_username': 'test_user',
                    'backup_path': '/test'
                },
                max_retries=1,
                timeout=30,
                verify_backup=False  # Skip verification for test
            )
            
            # Execute backup (synchronous for testing)
            backup_result = self.backup_executor._execute_single_backup(job_config)
            
            if backup_result.status == BackupStatus.COMPLETED:
                test_result.status = TestStatus.PASSED
                test_result.details['backup_success'] = True
                test_result.details['backup_file_path'] = backup_result.backup_file_path
                test_result.details['file_size_bytes'] = backup_result.file_size_bytes
                test_result.details['compression_ratio'] = backup_result.compression_ratio
                test_result.details['execution_log_entries'] = len(backup_result.execution_log)
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = backup_result.error_message
                test_result.details['execution_log'] = backup_result.execution_log
                test_result.recommendations.extend([
                    "Check device connectivity and credentials",
                    "Verify template command syntax",
                    "Check storage permissions and availability"
                ])
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result
    
    def test_backup_verification(self, backup_file_path: str, 
                               expected_content_type: str = "TEXT") -> TestResult:
        """Test backup file verification and integrity."""
        test_result = TestResult(
            test_id=f"backup_verify_{int(time.time())}",
            test_name=f"Backup Verification - {Path(backup_file_path).name}",
            category=TestCategory.BACKUP,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            if not Path(backup_file_path).exists():
                test_result.status = TestStatus.FAILED
                test_result.error_message = "Backup file does not exist"
                return test_result
            
            # Check file size
            file_size = Path(backup_file_path).stat().st_size
            test_result.details['file_size_bytes'] = file_size
            
            if file_size == 0:
                test_result.status = TestStatus.FAILED
                test_result.error_message = "Backup file is empty"
                return test_result
            
            # Read and analyze content
            try:
                # Handle compressed files
                if backup_file_path.endswith('.gz'):
                    import gzip
                    with gzip.open(backup_file_path, 'rt') as f:
                        content = f.read()
                else:
                    with open(backup_file_path, 'r') as f:
                        content = f.read()
                
                test_result.details['content_length'] = len(content)
                test_result.details['line_count'] = len(content.split('\n'))
                
                # Basic content validation
                if expected_content_type == "TEXT":
                    # Check for common configuration keywords
                    config_keywords = ['interface', 'ip', 'router', 'version', 'hostname']
                    found_keywords = [kw for kw in config_keywords if kw in content.lower()]
                    test_result.details['found_keywords'] = found_keywords
                    
                    if found_keywords:
                        test_result.status = TestStatus.PASSED
                        test_result.details['content_valid'] = True
                    else:
                        test_result.status = TestStatus.WARNING
                        test_result.warnings.append("No common configuration keywords found")
                else:
                    # For other formats, just check non-empty
                    test_result.status = TestStatus.PASSED
            
            except Exception as read_error:
                test_result.status = TestStatus.FAILED
                test_result.error_message = f"Failed to read backup file: {read_error}"
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result


class StorageTester:
    """Tests storage backend functionality."""
    
    def test_storage_backend(self, backend_name: str) -> TestResult:
        """Test storage backend operations."""
        test_result = TestResult(
            test_id=f"storage_{backend_name}",
            test_name=f"Storage Backend - {backend_name}",
            category=TestCategory.STORAGE,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            # Create test file
            test_content = "This is a test backup file for storage testing.\n" * 50
            test_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
            test_file.write(test_content)
            test_file.close()
            
            try:
                # Test upload
                upload_result = storage_manager.upload_file(
                    test_file.name, 
                    f'test/storage_test_{int(time.time())}.txt',
                    backend_name=backend_name
                )
                
                if upload_result.success:
                    test_result.details['upload_success'] = True
                    test_result.details['upload_time'] = upload_result.upload_time_seconds
                    test_result.details['bytes_transferred'] = upload_result.bytes_transferred
                    
                    # Test file listing
                    files = storage_manager.list_files('test/', backend_name=backend_name)
                    test_result.details['list_files_count'] = len(files)
                    
                    # Test download
                    download_file = tempfile.NamedTemporaryFile(delete=False, suffix='.txt')
                    download_file.close()
                    
                    download_success = storage_manager.download_file(
                        upload_result.storage_path.split('/')[-1] if '/' in upload_result.storage_path else upload_result.storage_path,
                        download_file.name,
                        backend_name=backend_name
                    )
                    
                    if download_success:
                        test_result.details['download_success'] = True
                        
                        # Verify content
                        with open(download_file.name, 'r') as f:
                            downloaded_content = f.read()
                        
                        if downloaded_content == test_content:
                            test_result.status = TestStatus.PASSED
                            test_result.details['content_verified'] = True
                        else:
                            test_result.status = TestStatus.WARNING
                            test_result.warnings.append("Downloaded content differs from original")
                    else:
                        test_result.status = TestStatus.FAILED
                        test_result.error_message = "Download failed"
                    
                    # Cleanup - delete test file
                    storage_manager.delete_file(
                        upload_result.storage_path.split('/')[-1] if '/' in upload_result.storage_path else upload_result.storage_path, 
                        backend_name=backend_name
                    )
                    
                    # Cleanup local download file
                    Path(download_file.name).unlink(missing_ok=True)
                
                else:
                    test_result.status = TestStatus.FAILED
                    test_result.error_message = upload_result.error_message
            
            finally:
                # Cleanup test file
                Path(test_file.name).unlink(missing_ok=True)
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result


class PerformanceTester:
    """Performance testing and benchmarking."""
    
    def benchmark_backup_performance(self, device_info: Dict[str, Any], 
                                   template_data: Dict[str, Any],
                                   iterations: int = 5) -> TestResult:
        """Benchmark backup operation performance."""
        test_result = TestResult(
            test_id=f"perf_backup_{device_info.get('id', 'unknown')}",
            test_name=f"Backup Performance - {device_info.get('device_name', 'Unknown')}",
            category=TestCategory.PERFORMANCE,
            status=TestStatus.RUNNING,
            start_time=datetime.now(timezone.utc)
        )
        
        try:
            backup_executor = DeviceBackupExecutor(max_concurrent_jobs=1, storage_path="/tmp/perf_test")
            execution_times = []
            file_sizes = []
            
            for i in range(iterations):
                job_config = BackupJobConfig(
                    job_id=f"perf_test_{i}_{int(time.time())}",
                    device_id=device_info.get('id', 0),
                    device_info=device_info,
                    template_data=template_data,
                    schedule_policy={},
                    user_variables={'backup_path': '/tmp/perf_test'},
                    timeout=60,
                    verify_backup=False
                )
                
                start = time.time()
                result = backup_executor._execute_single_backup(job_config)
                duration = time.time() - start
                
                if result.status == BackupStatus.COMPLETED:
                    execution_times.append(duration)
                    file_sizes.append(result.file_size_bytes)
            
            backup_executor.shutdown()
            
            if execution_times:
                test_result.status = TestStatus.PASSED
                test_result.details.update({
                    'iterations': len(execution_times),
                    'avg_execution_time': statistics.mean(execution_times),
                    'min_execution_time': min(execution_times),
                    'max_execution_time': max(execution_times),
                    'execution_times': execution_times,
                    'avg_file_size': statistics.mean(file_sizes) if file_sizes else 0,
                    'total_test_time': sum(execution_times)
                })
                
                # Performance thresholds
                avg_time = statistics.mean(execution_times)
                if avg_time > 60:  # More than 1 minute average
                    test_result.warnings.append("Average backup time exceeds 60 seconds")
                    test_result.recommendations.append("Consider optimizing template commands or network connectivity")
            else:
                test_result.status = TestStatus.FAILED
                test_result.error_message = "No successful backup executions"
        
        except Exception as e:
            test_result.status = TestStatus.FAILED
            test_result.error_message = str(e)
        
        finally:
            test_result.end_time = datetime.now(timezone.utc)
            test_result.duration_seconds = (test_result.end_time - test_result.start_time).total_seconds()
        
        return test_result


class SystemHealthMonitor:
    """System health monitoring and diagnostics."""
    
    def __init__(self):
        self.connection_tester = ConnectionTester()
        self.template_validator = TemplateValidator()
        self.backup_tester = BackupTester()
        self.storage_tester = StorageTester()
        self.performance_tester = PerformanceTester()
    
    def run_comprehensive_health_check(self, 
                                     devices: List[Dict[str, Any]] = None,
                                     templates: List[Dict[str, Any]] = None,
                                     storage_backends: List[str] = None) -> SystemHealthStatus:
        """Run comprehensive system health check."""
        logger.info("Starting comprehensive system health check")
        
        health_status = SystemHealthStatus(
            overall_status="healthy",
            timestamp=datetime.now(timezone.utc)
        )
        
        test_results = []
        
        # Test storage backends
        if storage_backends:
            for backend_name in storage_backends:
                try:
                    result = self.storage_tester.test_storage_backend(backend_name)
                    test_results.append(result)
                    health_status.component_statuses[f"storage_{backend_name}"] = result
                except Exception as e:
                    logger.error(f"Storage test failed for {backend_name}: {e}")
        
        # Test device connectivity and authentication
        if devices:
            with ThreadPoolExecutor(max_workers=5) as executor:
                connectivity_futures = []
                auth_futures = []
                
                for device in devices[:10]:  # Limit to first 10 devices for health check
                    connectivity_futures.append(
                        executor.submit(self.connection_tester.test_device_connectivity, device)
                    )
                    auth_futures.append(
                        executor.submit(self.connection_tester.test_device_authentication, device)
                    )
                
                # Collect connectivity results
                for future in as_completed(connectivity_futures):
                    try:
                        result = future.result()
                        test_results.append(result)
                        health_status.component_statuses[result.test_id] = result
                    except Exception as e:
                        logger.error(f"Connectivity test failed: {e}")
                
                # Collect authentication results
                for future in as_completed(auth_futures):
                    try:
                        result = future.result()
                        test_results.append(result)
                        health_status.component_statuses[result.test_id] = result
                    except Exception as e:
                        logger.error(f"Authentication test failed: {e}")
        
        # Test template validation
        if templates:
            for template in templates[:5]:  # Limit to first 5 templates
                try:
                    result = self.template_validator.validate_template_syntax(template)
                    test_results.append(result)
                    health_status.component_statuses[result.test_id] = result
                except Exception as e:
                    logger.error(f"Template validation failed: {e}")
        
        # Calculate overall health status
        failed_tests = [r for r in test_results if r.status == TestStatus.FAILED]
        warning_tests = [r for r in test_results if r.status == TestStatus.WARNING]
        
        if failed_tests:
            health_status.overall_status = "critical"
            health_status.recommendations.append(f"{len(failed_tests)} critical issues found - immediate attention required")
        elif warning_tests:
            health_status.overall_status = "warning"
            health_status.recommendations.append(f"{len(warning_tests)} warnings found - review recommended")
        
        # Calculate performance metrics
        execution_times = [r.duration_seconds for r in test_results if r.duration_seconds > 0]
        if execution_times:
            health_status.performance_metrics.update({
                'avg_test_duration': statistics.mean(execution_times),
                'max_test_duration': max(execution_times),
                'total_tests': len(test_results),
                'passed_tests': len([r for r in test_results if r.status == TestStatus.PASSED]),
                'failed_tests': len(failed_tests),
                'warning_tests': len(warning_tests)
            })
        
        # Add system resource metrics (basic)
        try:
            import psutil
            health_status.resource_usage.update({
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_percent': psutil.disk_usage('/').percent
            })
        except ImportError:
            logger.warning("psutil not available for system resource monitoring")
        
        logger.info(f"Health check completed: {health_status.overall_status} status with {len(test_results)} tests")
        
        return health_status
    
    def run_quick_health_check(self) -> Dict[str, Any]:
        """Run quick health check with essential tests only."""
        logger.info("Running quick health check")
        
        results = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'status': 'healthy',
            'tests': {}
        }
        
        # Test error manager health
        try:
            error_stats = error_manager.get_error_statistics(timedelta(hours=1))
            results['tests']['error_rate'] = {
                'status': 'warning' if error_stats['total_errors'] > 10 else 'healthy',
                'errors_last_hour': error_stats['total_errors']
            }
        except Exception as e:
            results['tests']['error_rate'] = {'status': 'failed', 'error': str(e)}
        
        # Test storage manager
        try:
            if storage_manager.backends:
                # Quick storage test with default backend
                test_result = self.storage_tester.test_storage_backend(storage_manager.default_backend)
                results['tests']['storage'] = {
                    'status': test_result.status.value,
                    'duration': test_result.duration_seconds
                }
            else:
                results['tests']['storage'] = {'status': 'skipped', 'reason': 'No storage backends configured'}
        except Exception as e:
            results['tests']['storage'] = {'status': 'failed', 'error': str(e)}
        
        # Determine overall status
        test_statuses = [test.get('status', 'unknown') for test in results['tests'].values()]
        if 'failed' in test_statuses:
            results['status'] = 'critical'
        elif 'warning' in test_statuses:
            results['status'] = 'warning'
        
        return results


class TestRunner:
    """Main test runner and orchestrator."""
    
    def __init__(self):
        self.health_monitor = SystemHealthMonitor()
        self.test_suites: Dict[str, TestSuite] = {}
        self.test_history: List[TestResult] = []
    
    def register_test_suite(self, suite: TestSuite):
        """Register a test suite."""
        self.test_suites[suite.suite_id] = suite
        logger.info(f"Registered test suite: {suite.suite_name}")
    
    def run_test_suite(self, suite_id: str, **kwargs) -> List[TestResult]:
        """Run specific test suite."""
        if suite_id not in self.test_suites:
            raise ValueError(f"Test suite '{suite_id}' not found")
        
        suite = self.test_suites[suite_id]
        results = []
        
        logger.info(f"Running test suite: {suite.suite_name}")
        
        try:
            # Run setup
            if suite.setup_func:
                suite.setup_func(**kwargs)
            
            # Run tests
            for test_func in suite.tests:
                try:
                    result = test_func(**kwargs)
                    results.append(result)
                    self.test_history.append(result)
                except Exception as e:
                    logger.error(f"Test failed with exception: {e}")
            
            # Run teardown
            if suite.teardown_func:
                suite.teardown_func(**kwargs)
        
        except Exception as e:
            logger.error(f"Test suite execution failed: {e}")
        
        logger.info(f"Test suite completed: {len(results)} tests executed")
        return results
    
    def generate_test_report(self, results: List[TestResult]) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        if not results:
            return {'error': 'No test results to report'}
        
        # Calculate statistics
        total_tests = len(results)
        passed_tests = len([r for r in results if r.status == TestStatus.PASSED])
        failed_tests = len([r for r in results if r.status == TestStatus.FAILED])
        warning_tests = len([r for r in results if r.status == TestStatus.WARNING])
        skipped_tests = len([r for r in results if r.status == TestStatus.SKIPPED])
        
        # Calculate durations
        durations = [r.duration_seconds for r in results if r.duration_seconds > 0]
        
        report = {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'warnings': warning_tests,
                'skipped': skipped_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                'total_duration': sum(durations),
                'avg_duration': statistics.mean(durations) if durations else 0
            },
            'by_category': {},
            'failed_tests': [],
            'recommendations': set(),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Group by category
        for category in TestCategory:
            category_results = [r for r in results if r.category == category]
            if category_results:
                report['by_category'][category.value] = {
                    'total': len(category_results),
                    'passed': len([r for r in category_results if r.status == TestStatus.PASSED]),
                    'failed': len([r for r in category_results if r.status == TestStatus.FAILED]),
                    'warnings': len([r for r in category_results if r.status == TestStatus.WARNING])
                }
        
        # Collect failed tests and recommendations
        for result in results:
            if result.status == TestStatus.FAILED:
                report['failed_tests'].append({
                    'test_name': result.test_name,
                    'error_message': result.error_message,
                    'category': result.category.value,
                    'duration': result.duration_seconds
                })
            
            if result.recommendations:
                report['recommendations'].update(result.recommendations)
        
        report['recommendations'] = list(report['recommendations'])
        
        return report


# Global test runner instance
test_runner = TestRunner()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Test device info
    test_device = {
        'id': 1,
        'device_name': 'test-switch-01',
        'ip_address': '192.168.1.100',
        'ssh_username': 'admin',
        'ssh_password_decrypted': 'password',
        'netmiko_device_type': 'cisco_ios'
    }
    
    # Test template
    test_template = {
        'id': 1,
        'template_name': 'Test Backup Template',
        'backup_command': 'show running-config',
        'command_format': 'TEXT',
        'template_variables': json.dumps({})
    }
    
    # Run individual tests
    print("Running connectivity test...")
    connectivity_test = ConnectionTester()
    result = connectivity_test.test_device_connectivity(test_device)
    print(f"Connectivity test: {result.status.value}")
    
    print("Running template validation...")
    template_validator = TemplateValidator()
    result = template_validator.validate_template_syntax(test_template)
    print(f"Template validation: {result.status.value}")
    
    # Run quick health check
    print("Running quick health check...")
    health_monitor = SystemHealthMonitor()
    health_result = health_monitor.run_quick_health_check()
    print(f"System health: {health_result['status']}")
    print(f"Test results: {json.dumps(health_result, indent=2)}")
    
    # Generate test report
    print("Generating test report...")
    test_results = [result]  # In real usage, collect all test results
    report = test_runner.generate_test_report(test_results)
    print(f"Test report: {json.dumps(report, indent=2)}")