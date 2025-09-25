"""
SSH Connection Manager for Network Device Backup System
======================================================

This module provides SSH connection management using Netmiko and Paramiko
for multi-vendor network device support with connection pooling, timeout
handling, and retry mechanisms.

Features:
- Multi-vendor device support (Cisco, Juniper, MikroTik, etc.)
- Connection pooling for performance optimization
- Configurable timeouts and retry logic
- Secure credential management
- Connection health monitoring
- Thread-safe connection handling
"""

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Union
from concurrent.futures import ThreadPoolExecutor
import hashlib

import paramiko
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
from netmiko.exceptions import NetmikoBaseException

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class DeviceCredentials:
    """Device connection credentials and parameters."""
    hostname: str
    ip_address: str
    username: str
    password: str
    device_type: str  # Netmiko device type
    port: int = 22
    enable_password: Optional[str] = None
    ssh_key_file: Optional[str] = None
    timeout: int = 30
    conn_timeout: int = 10
    auth_timeout: int = 10
    banner_timeout: int = 15


@dataclass
class ConnectionResult:
    """Connection attempt result."""
    success: bool
    connection: Optional[Any] = None
    error_message: Optional[str] = None
    connection_time: float = 0.0
    device_info: Optional[Dict[str, Any]] = None


class ConnectionPool:
    """Thread-safe connection pool for SSH connections."""
    
    def __init__(self, max_connections: int = 50, cleanup_interval: int = 300):
        self.max_connections = max_connections
        self.cleanup_interval = cleanup_interval
        self._connections: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._last_cleanup = time.time()
        
    def _generate_connection_key(self, credentials: DeviceCredentials) -> str:
        """Generate unique key for connection based on device credentials."""
        key_data = f"{credentials.ip_address}:{credentials.port}:{credentials.username}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _cleanup_expired_connections(self):
        """Remove expired connections from pool."""
        current_time = time.time()
        
        if current_time - self._last_cleanup < self.cleanup_interval:
            return
            
        with self._lock:
            expired_keys = []
            for key, conn_data in self._connections.items():
                if current_time - conn_data['last_used'] > self.cleanup_interval:
                    expired_keys.append(key)
                    
            for key in expired_keys:
                try:
                    self._connections[key]['connection'].disconnect()
                except Exception as e:
                    logger.warning(f"Error disconnecting expired connection {key}: {e}")
                finally:
                    del self._connections[key]
                    
            self._last_cleanup = current_time
            logger.debug(f"Cleaned up {len(expired_keys)} expired connections")
    
    def get_connection(self, credentials: DeviceCredentials) -> Optional[Any]:
        """Get existing connection from pool if available."""
        key = self._generate_connection_key(credentials)
        
        with self._lock:
            self._cleanup_expired_connections()
            
            if key in self._connections:
                conn_data = self._connections[key]
                connection = conn_data['connection']
                
                # Test if connection is still alive
                try:
                    if hasattr(connection, 'is_alive') and connection.is_alive():
                        conn_data['last_used'] = time.time()
                        logger.debug(f"Reusing pooled connection for {credentials.ip_address}")
                        return connection
                    else:
                        # Connection is dead, remove from pool
                        del self._connections[key]
                        logger.debug(f"Removed dead connection for {credentials.ip_address}")
                except Exception as e:
                    logger.warning(f"Error checking connection health: {e}")
                    del self._connections[key]
                    
        return None
    
    def add_connection(self, credentials: DeviceCredentials, connection: Any) -> bool:
        """Add new connection to pool."""
        if len(self._connections) >= self.max_connections:
            logger.warning("Connection pool is full, cannot add new connection")
            return False
            
        key = self._generate_connection_key(credentials)
        
        with self._lock:
            self._connections[key] = {
                'connection': connection,
                'created_at': time.time(),
                'last_used': time.time(),
                'credentials': credentials
            }
            logger.debug(f"Added connection to pool for {credentials.ip_address}")
            return True
    
    def remove_connection(self, credentials: DeviceCredentials):
        """Remove connection from pool."""
        key = self._generate_connection_key(credentials)
        
        with self._lock:
            if key in self._connections:
                try:
                    self._connections[key]['connection'].disconnect()
                except Exception as e:
                    logger.warning(f"Error disconnecting connection: {e}")
                finally:
                    del self._connections[key]
                    logger.debug(f"Removed connection from pool for {credentials.ip_address}")
    
    def close_all_connections(self):
        """Close all connections in the pool."""
        with self._lock:
            for key, conn_data in self._connections.items():
                try:
                    conn_data['connection'].disconnect()
                except Exception as e:
                    logger.warning(f"Error closing connection {key}: {e}")
            self._connections.clear()
            logger.info("Closed all connections in pool")


class SSHConnectionManager:
    """Main SSH connection manager for network devices."""
    
    def __init__(self, max_concurrent_connections: int = 10, use_connection_pool: bool = True):
        self.max_concurrent_connections = max_concurrent_connections
        self.use_connection_pool = use_connection_pool
        self.connection_pool = ConnectionPool() if use_connection_pool else None
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_connections)
        
    def _create_netmiko_connection(self, credentials: DeviceCredentials) -> ConnectionResult:
        """Create new Netmiko SSH connection."""
        start_time = time.time()
        
        try:
            device_params = {
                'device_type': credentials.device_type,
                'host': credentials.ip_address,
                'username': credentials.username,
                'password': credentials.password,
                'port': credentials.port,
                'timeout': credentials.timeout,
                'conn_timeout': credentials.conn_timeout,
                'auth_timeout': credentials.auth_timeout,
                'banner_timeout': credentials.banner_timeout,
                'verbose': False
            }
            
            # Add enable password if provided
            if credentials.enable_password:
                device_params['secret'] = credentials.enable_password
                
            # Add SSH key file if provided
            if credentials.ssh_key_file:
                device_params['key_file'] = credentials.ssh_key_file
                
            logger.debug(f"Attempting SSH connection to {credentials.ip_address}")
            connection = ConnectHandler(**device_params)
            
            # Test connection and gather device info
            device_info = self._gather_device_info(connection, credentials)
            
            connection_time = time.time() - start_time
            logger.info(f"Successfully connected to {credentials.ip_address} in {connection_time:.2f}s")
            
            return ConnectionResult(
                success=True,
                connection=connection,
                connection_time=connection_time,
                device_info=device_info
            )
            
        except NetmikoAuthenticationException as e:
            error_msg = f"Authentication failed for {credentials.ip_address}: {str(e)}"
            logger.error(error_msg)
            return ConnectionResult(success=False, error_message=error_msg)
            
        except NetmikoTimeoutException as e:
            error_msg = f"Connection timeout for {credentials.ip_address}: {str(e)}"
            logger.error(error_msg)
            return ConnectionResult(success=False, error_message=error_msg)
            
        except NetmikoBaseException as e:
            error_msg = f"Netmiko error for {credentials.ip_address}: {str(e)}"
            logger.error(error_msg)
            return ConnectionResult(success=False, error_message=error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error connecting to {credentials.ip_address}: {str(e)}"
            logger.error(error_msg)
            return ConnectionResult(success=False, error_message=error_msg)
    
    def _gather_device_info(self, connection: Any, credentials: DeviceCredentials) -> Dict[str, Any]:
        """Gather basic device information."""
        device_info = {
            'hostname': credentials.hostname,
            'ip_address': credentials.ip_address,
            'device_type': credentials.device_type
        }
        
        try:
            # Try to get hostname from device
            if hasattr(connection, 'find_prompt'):
                prompt = connection.find_prompt()
                device_info['detected_hostname'] = prompt.replace('#', '').replace('>', '')
                
            # Try to get version info based on device type
            if 'cisco' in credentials.device_type.lower():
                version_output = connection.send_command('show version', expect_string=r'#')
                device_info['version_output'] = version_output[:200]  # Truncate for storage
            elif 'juniper' in credentials.device_type.lower():
                version_output = connection.send_command('show version brief', expect_string=r'>')
                device_info['version_output'] = version_output[:200]
            elif 'mikrotik' in credentials.device_type.lower():
                version_output = connection.send_command('/system resource print', expect_string=r'>')
                device_info['version_output'] = version_output[:200]
                
        except Exception as e:
            logger.warning(f"Could not gather device info for {credentials.ip_address}: {e}")
            device_info['info_error'] = str(e)
            
        return device_info
    
    @contextmanager
    def get_connection(self, credentials: DeviceCredentials, max_retries: int = 3):
        """
        Context manager for getting SSH connections with automatic cleanup.
        Uses connection pool if enabled, otherwise creates new connections.
        """
        connection = None
        from_pool = False
        
        try:
            # Try to get from pool first
            if self.connection_pool:
                connection = self.connection_pool.get_connection(credentials)
                if connection:
                    from_pool = True
                    yield connection
                    return
            
            # Create new connection with retries
            for attempt in range(max_retries):
                try:
                    result = self._create_netmiko_connection(credentials)
                    if result.success:
                        connection = result.connection
                        
                        # Add to pool if enabled and connection is good
                        if self.connection_pool and connection:
                            self.connection_pool.add_connection(credentials, connection)
                            
                        yield connection
                        return
                    else:
                        if attempt == max_retries - 1:
                            raise Exception(result.error_message)
                        else:
                            logger.warning(f"Connection attempt {attempt + 1} failed for {credentials.ip_address}, retrying...")
                            time.sleep(2 ** attempt)  # Exponential backoff
                            
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    else:
                        logger.warning(f"Connection attempt {attempt + 1} failed: {e}, retrying...")
                        time.sleep(2 ** attempt)
                        
        finally:
            # Only disconnect if not from pool
            if connection and not from_pool:
                try:
                    connection.disconnect()
                    logger.debug(f"Disconnected from {credentials.ip_address}")
                except Exception as e:
                    logger.warning(f"Error disconnecting from {credentials.ip_address}: {e}")
    
    def test_connection(self, credentials: DeviceCredentials) -> ConnectionResult:
        """Test connection to device without keeping it open."""
        try:
            with self.get_connection(credentials) as conn:
                if conn:
                    return ConnectionResult(
                        success=True,
                        device_info=self._gather_device_info(conn, credentials)
                    )
                else:
                    return ConnectionResult(
                        success=False,
                        error_message="Failed to establish connection"
                    )
        except Exception as e:
            return ConnectionResult(
                success=False,
                error_message=str(e)
            )
    
    def execute_command(self, credentials: DeviceCredentials, command: str, 
                       expect_string: Optional[str] = None, 
                       timeout: int = 30) -> Dict[str, Any]:
        """Execute single command on device."""
        try:
            with self.get_connection(credentials) as conn:
                start_time = time.time()
                
                if expect_string:
                    output = conn.send_command(command, expect_string=expect_string, timeout=timeout)
                else:
                    output = conn.send_command(command, timeout=timeout)
                    
                execution_time = time.time() - start_time
                
                return {
                    'success': True,
                    'output': output,
                    'command': command,
                    'execution_time': execution_time,
                    'device_ip': credentials.ip_address
                }
                
        except Exception as e:
            logger.error(f"Error executing command '{command}' on {credentials.ip_address}: {e}")
            return {
                'success': False,
                'error': str(e),
                'command': command,
                'device_ip': credentials.ip_address
            }
    
    def execute_commands(self, credentials: DeviceCredentials, commands: List[str], 
                        timeout: int = 30) -> List[Dict[str, Any]]:
        """Execute multiple commands on device using single connection."""
        results = []
        
        try:
            with self.get_connection(credentials) as conn:
                for command in commands:
                    try:
                        start_time = time.time()
                        output = conn.send_command(command, timeout=timeout)
                        execution_time = time.time() - start_time
                        
                        results.append({
                            'success': True,
                            'output': output,
                            'command': command,
                            'execution_time': execution_time,
                            'device_ip': credentials.ip_address
                        })
                        
                    except Exception as e:
                        logger.error(f"Error executing command '{command}' on {credentials.ip_address}: {e}")
                        results.append({
                            'success': False,
                            'error': str(e),
                            'command': command,
                            'device_ip': credentials.ip_address
                        })
                        
        except Exception as e:
            logger.error(f"Error establishing connection to {credentials.ip_address}: {e}")
            # Return failed results for all commands
            for command in commands:
                results.append({
                    'success': False,
                    'error': f"Connection failed: {str(e)}",
                    'command': command,
                    'device_ip': credentials.ip_address
                })
                
        return results
    
    def close_all_connections(self):
        """Close all connections and cleanup resources."""
        if self.connection_pool:
            self.connection_pool.close_all_connections()
        
        self.executor.shutdown(wait=True)
        logger.info("SSH Connection Manager closed")


# Global connection manager instance
ssh_manager = SSHConnectionManager()


def create_device_credentials(device_data: Dict[str, Any]) -> DeviceCredentials:
    """Helper function to create DeviceCredentials from database record."""
    return DeviceCredentials(
        hostname=device_data.get('hostname', device_data['device_name']),
        ip_address=device_data['ip_address'],
        username=device_data.get('ssh_username', ''),
        password=device_data.get('ssh_password_decrypted', ''),  # Assume decrypted by caller
        device_type=device_data.get('netmiko_device_type', 'cisco_ios'),
        port=device_data.get('ssh_port', 22),
        enable_password=device_data.get('enable_password_decrypted'),
        ssh_key_file=device_data.get('ssh_key_file'),
        timeout=device_data.get('timeout', 30)
    )


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.DEBUG)
    
    # Test credentials (replace with actual device info)
    test_creds = DeviceCredentials(
        hostname="test-switch",
        ip_address="192.168.1.100",
        username="admin",
        password="password",
        device_type="cisco_ios"
    )
    
    # Test connection
    manager = SSHConnectionManager()
    result = manager.test_connection(test_creds)
    print(f"Connection test result: {result}")
    
    if result.success:
        # Test command execution
        cmd_result = manager.execute_command(test_creds, "show version")
        print(f"Command result: {cmd_result}")
    
    manager.close_all_connections()