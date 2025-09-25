"""
Network Device Discovery Utilities
=================================

This module provides network device discovery capabilities for automatic
device inventory population using SNMP, SSH, and network scanning
techniques. It includes device fingerprinting, capability detection,
and automated inventory management.

Features:
- SNMP-based device discovery and information gathering
- SSH-based device fingerprinting and capability detection
- Network scanning and device enumeration
- Vendor and model identification
- Automatic device type classification
- Inventory synchronization with database
- Bulk discovery operations
- Change detection and monitoring
"""

import logging
import asyncio
import socket
import struct
import threading
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from ipaddress import IPv4Network, IPv4Address, AddressValueError
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re

# SNMP imports
try:
    from pysnmp.hlapi import *
    from pysnmp.entity.rfc3413.oneliner import cmdgen
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    # logger.warning("SNMP libraries not available. Install pysnmp for SNMP discovery.")

# Network scanning imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    # logger.warning("python-nmap not available. Install for advanced network scanning.")

from ssh_connection import SSHConnectionManager, DeviceCredentials, create_device_credentials
from error_handling import error_manager, retry_with_backoff, RetryConfig

# Configure logging
logger = logging.getLogger(__name__)


class DiscoveryMethod(Enum):
    """Device discovery methods."""
    SNMP = "snmp"
    SSH = "ssh"
    ICMP = "icmp"
    TCP_SCAN = "tcp_scan"
    ARP = "arp"


class DeviceStatus(Enum):
    """Device status during discovery."""
    UNKNOWN = "unknown"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    AUTHENTICATED = "authenticated"
    ACCESS_DENIED = "access_denied"
    TIMEOUT = "timeout"


@dataclass
class NetworkRange:
    """Network range for discovery."""
    network: str
    description: Optional[str] = None
    discovery_methods: List[DiscoveryMethod] = field(default_factory=lambda: [DiscoveryMethod.ICMP, DiscoveryMethod.SNMP])
    credentials: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class DiscoveredDevice:
    """Information about a discovered device."""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    firmware_version: Optional[str] = None
    device_type: Optional[str] = None
    netmiko_device_type: Optional[str] = None
    snmp_community: Optional[str] = None
    ssh_credentials: Optional[Dict[str, str]] = None
    capabilities: List[str] = field(default_factory=list)
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    status: DeviceStatus = DeviceStatus.UNKNOWN
    discovery_method: Optional[DiscoveryMethod] = None
    discovery_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    additional_info: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 0.0  # 0.0 to 1.0


class SNMPDiscovery:
    """SNMP-based device discovery."""
    
    # Common SNMP OIDs
    OID_SYSTEM_DESC = '1.3.6.1.2.1.1.1.0'
    OID_SYSTEM_NAME = '1.3.6.1.2.1.1.5.0'
    OID_SYSTEM_UPTIME = '1.3.6.1.2.1.1.3.0'
    OID_SYSTEM_CONTACT = '1.3.6.1.2.1.1.4.0'
    OID_SYSTEM_LOCATION = '1.3.6.1.2.1.1.6.0'
    OID_INTERFACES_COUNT = '1.3.6.1.2.1.2.1.0'
    
    # Vendor-specific OIDs
    VENDOR_OIDS = {
        'cisco': '1.3.6.1.4.1.9',
        'juniper': '1.3.6.1.4.1.2636',
        'hp': '1.3.6.1.4.1.11',
        'dell': '1.3.6.1.4.1.674',
        'mikrotik': '1.3.6.1.4.1.14988'
    }
    
    def __init__(self, timeout: int = 5, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        
        if not SNMP_AVAILABLE:
            raise ImportError("SNMP libraries not available")
    
    @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=1.0))
    def discover_device(self, ip_address: str, community: str = 'public') -> Optional[DiscoveredDevice]:
        """Discover device using SNMP."""
        try:
            device = DiscoveredDevice(
                ip_address=ip_address,
                discovery_method=DiscoveryMethod.SNMP,
                snmp_community=community
            )
            
            # Get basic system information
            system_info = self._get_system_info(ip_address, community)
            if not system_info:
                return None
            
            device.hostname = system_info.get('hostname')
            device.additional_info.update(system_info)
            
            # Identify vendor and model from system description
            vendor_info = self._identify_vendor(system_info.get('description', ''))
            device.vendor = vendor_info.get('vendor')
            device.model = vendor_info.get('model')
            device.firmware_version = vendor_info.get('firmware')
            device.device_type = vendor_info.get('device_type')
            device.netmiko_device_type = vendor_info.get('netmiko_type')
            
            # Get interface information
            device.interfaces = self._get_interface_info(ip_address, community)
            
            # Calculate confidence score
            device.confidence_score = self._calculate_confidence_score(device)
            device.status = DeviceStatus.REACHABLE
            
            logger.info(f"SNMP discovery successful for {ip_address}: {device.vendor} {device.model}")
            return device
            
        except Exception as e:
            logger.debug(f"SNMP discovery failed for {ip_address}: {e}")
            return None
    
    def _get_system_info(self, ip_address: str, community: str) -> Optional[Dict[str, Any]]:
        """Get basic system information via SNMP."""
        try:
            cmdGen = cmdgen.CommandGenerator()
            
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData(community),
                cmdgen.UdpTransportTarget((ip_address, 161), timeout=self.timeout, retries=self.retries),
                self.OID_SYSTEM_DESC,
                self.OID_SYSTEM_NAME,
                self.OID_SYSTEM_UPTIME,
                self.OID_SYSTEM_CONTACT,
                self.OID_SYSTEM_LOCATION
            )
            
            if errorIndication or errorStatus:
                return None
            
            system_info = {}
            for oid, value in varBinds:
                oid_str = str(oid)
                value_str = str(value)
                
                if oid_str == self.OID_SYSTEM_DESC:
                    system_info['description'] = value_str
                elif oid_str == self.OID_SYSTEM_NAME:
                    system_info['hostname'] = value_str
                elif oid_str == self.OID_SYSTEM_UPTIME:
                    system_info['uptime'] = value_str
                elif oid_str == self.OID_SYSTEM_CONTACT:
                    system_info['contact'] = value_str
                elif oid_str == self.OID_SYSTEM_LOCATION:
                    system_info['location'] = value_str
            
            return system_info
            
        except Exception as e:
            logger.debug(f"Failed to get system info for {ip_address}: {e}")
            return None
    
    def _get_interface_info(self, ip_address: str, community: str) -> List[Dict[str, Any]]:
        """Get interface information via SNMP."""
        interfaces = []
        try:
            # This is a simplified version - full implementation would walk interface tables
            cmdGen = cmdgen.CommandGenerator()
            
            errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
                cmdgen.CommunityData(community),
                cmdgen.UdpTransportTarget((ip_address, 161), timeout=self.timeout, retries=self.retries),
                self.OID_INTERFACES_COUNT
            )
            
            if not errorIndication and not errorStatus:
                interface_count = int(str(varBinds[0][1]))
                interfaces.append({
                    'count': interface_count,
                    'discovery_method': 'snmp_basic'
                })
            
        except Exception as e:
            logger.debug(f"Failed to get interface info for {ip_address}: {e}")
        
        return interfaces
    
    def _identify_vendor(self, system_description: str) -> Dict[str, Optional[str]]:
        """Identify vendor, model, and device type from system description."""
        desc_lower = system_description.lower()
        
        # Cisco devices
        if 'cisco' in desc_lower:
            vendor_info = {'vendor': 'Cisco'}
            
            if 'ios-xe' in desc_lower:
                vendor_info['netmiko_type'] = 'cisco_xe'
                vendor_info['device_type'] = 'router'
            elif 'ios' in desc_lower:
                vendor_info['netmiko_type'] = 'cisco_ios'
                if 'switch' in desc_lower or 'catalyst' in desc_lower:
                    vendor_info['device_type'] = 'switch'
                else:
                    vendor_info['device_type'] = 'router'
            elif 'nx-os' in desc_lower:
                vendor_info['netmiko_type'] = 'cisco_nxos'
                vendor_info['device_type'] = 'switch'
            elif 'asa' in desc_lower:
                vendor_info['netmiko_type'] = 'cisco_asa'
                vendor_info['device_type'] = 'firewall'
            
            # Extract model information
            model_patterns = [
                r'catalyst (\w+)',
                r'(asr\d+)',
                r'(isr\d+)',
                r'(c\d+[a-z]*)',
                r'(ws-c\d+[a-z]*)'
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, desc_lower)
                if match:
                    vendor_info['model'] = match.group(1).upper()
                    break
            
            return vendor_info
        
        # Juniper devices
        elif 'juniper' in desc_lower or 'junos' in desc_lower:
            return {
                'vendor': 'Juniper',
                'netmiko_type': 'juniper_junos',
                'device_type': 'router' if 'mx' in desc_lower else 'switch'
            }
        
        # MikroTik devices
        elif 'mikrotik' in desc_lower or 'routeros' in desc_lower:
            return {
                'vendor': 'MikroTik',
                'netmiko_type': 'mikrotik_routeros',
                'device_type': 'router'
            }
        
        # HP/HPE devices
        elif any(keyword in desc_lower for keyword in ['hp', 'hpe', 'hewlett', 'procurve']):
            return {
                'vendor': 'HP',
                'netmiko_type': 'hp_procurve',
                'device_type': 'switch'
            }
        
        return {'vendor': None, 'model': None, 'device_type': None, 'netmiko_type': None}
    
    def _calculate_confidence_score(self, device: DiscoveredDevice) -> float:
        """Calculate confidence score for discovered device."""
        score = 0.0
        
        # Base score for successful SNMP response
        score += 0.3
        
        # Vendor identification
        if device.vendor:
            score += 0.2
        
        # Model identification
        if device.model:
            score += 0.2
        
        # Device type classification
        if device.device_type:
            score += 0.1
        
        # Netmiko type mapping
        if device.netmiko_device_type:
            score += 0.1
        
        # Interface information
        if device.interfaces:
            score += 0.1
        
        return min(score, 1.0)


class SSHDiscovery:
    """SSH-based device discovery and fingerprinting."""
    
    def __init__(self, ssh_manager: Optional[SSHConnectionManager] = None):
        self.ssh_manager = ssh_manager or SSHConnectionManager()
    
    @retry_with_backoff(RetryConfig(max_attempts=2, base_delay=2.0))
    def discover_device(self, ip_address: str, credentials: Dict[str, str]) -> Optional[DiscoveredDevice]:
        """Discover device using SSH."""
        try:
            device = DiscoveredDevice(
                ip_address=ip_address,
                discovery_method=DiscoveryMethod.SSH,
                ssh_credentials=credentials
            )
            
            # Create SSH credentials
            ssh_creds = DeviceCredentials(
                hostname=ip_address,
                ip_address=ip_address,
                username=credentials.get('username', ''),
                password=credentials.get('password', ''),
                device_type=credentials.get('device_type', 'cisco_ios')
            )
            
            # Test connection and gather information
            with self.ssh_manager.get_connection(ssh_creds) as conn:
                if not conn:
                    return None
                
                device.status = DeviceStatus.AUTHENTICATED
                
                # Get device information based on type
                device_info = self._identify_device_via_ssh(conn, ssh_creds.device_type)
                
                device.vendor = device_info.get('vendor')
                device.model = device_info.get('model')
                device.firmware_version = device_info.get('firmware')
                device.hostname = device_info.get('hostname')
                device.device_type = device_info.get('device_type')
                device.netmiko_device_type = ssh_creds.device_type
                device.capabilities = device_info.get('capabilities', [])
                device.additional_info.update(device_info)
                
                # Calculate confidence score
                device.confidence_score = self._calculate_ssh_confidence_score(device)
                
                logger.info(f"SSH discovery successful for {ip_address}: {device.vendor} {device.model}")
                return device
                
        except Exception as e:
            logger.debug(f"SSH discovery failed for {ip_address}: {e}")
            return None
    
    def _identify_device_via_ssh(self, connection, device_type: str) -> Dict[str, Any]:
        """Identify device characteristics via SSH commands."""
        device_info = {'capabilities': []}
        
        try:
            if 'cisco' in device_type.lower():
                device_info.update(self._identify_cisco_device(connection))
            elif 'juniper' in device_type.lower():
                device_info.update(self._identify_juniper_device(connection))
            elif 'mikrotik' in device_type.lower():
                device_info.update(self._identify_mikrotik_device(connection))
            else:
                # Generic identification
                device_info.update(self._generic_device_identification(connection))
        
        except Exception as e:
            logger.debug(f"Error during device identification: {e}")
        
        return device_info
    
    def _identify_cisco_device(self, connection) -> Dict[str, Any]:
        """Identify Cisco device characteristics."""
        info = {'vendor': 'Cisco', 'capabilities': ['cisco_commands']}
        
        try:
            # Get version information
            version_output = connection.send_command('show version', timeout=30)
            
            # Extract hostname
            hostname_match = re.search(r'(\S+) uptime is', version_output)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
            
            # Extract model
            model_patterns = [
                r'cisco (\S+) \(',
                r'Model number.*?(\S+)',
                r'Hardware:.*?(\S+)'
            ]
            
            for pattern in model_patterns:
                match = re.search(pattern, version_output, re.IGNORECASE)
                if match:
                    info['model'] = match.group(1)
                    break
            
            # Extract firmware version
            if 'IOS-XE' in version_output:
                info['device_type'] = 'router'
                version_match = re.search(r'IOS-XE Software.*?Version (\S+)', version_output)
            elif 'IOS Software' in version_output:
                version_match = re.search(r'IOS.*?Version (\S+)', version_output)
                info['device_type'] = 'switch' if 'switch' in version_output.lower() else 'router'
            else:
                version_match = None
            
            if version_match:
                info['firmware'] = version_match.group(1)
            
            # Get interface information
            try:
                int_output = connection.send_command('show ip interface brief', timeout=20)
                interface_count = len([line for line in int_output.split('\n') if 'up' in line.lower() or 'down' in line.lower()]) - 1
                info['interface_count'] = max(0, interface_count)
                info['capabilities'].append('ip_interfaces')
            except:
                pass
        
        except Exception as e:
            logger.debug(f"Error identifying Cisco device: {e}")
        
        return info
    
    def _identify_juniper_device(self, connection) -> Dict[str, Any]:
        """Identify Juniper device characteristics."""
        info = {'vendor': 'Juniper', 'capabilities': ['junos_commands']}
        
        try:
            # Get version information
            version_output = connection.send_command('show version', timeout=30)
            
            # Extract hostname
            hostname_match = re.search(r'Hostname: (\S+)', version_output)
            if hostname_match:
                info['hostname'] = hostname_match.group(1)
            
            # Extract model
            model_match = re.search(r'Model: (\S+)', version_output)
            if model_match:
                info['model'] = model_match.group(1)
            
            # Extract firmware version
            version_match = re.search(r'JUNOS.*?(\d+\.\d+\S*)', version_output)
            if version_match:
                info['firmware'] = version_match.group(1)
            
            info['device_type'] = 'router'  # Default for Juniper
        
        except Exception as e:
            logger.debug(f"Error identifying Juniper device: {e}")
        
        return info
    
    def _identify_mikrotik_device(self, connection) -> Dict[str, Any]:
        """Identify MikroTik device characteristics."""
        info = {'vendor': 'MikroTik', 'capabilities': ['routeros_commands']}
        
        try:
            # Get system information
            resource_output = connection.send_command('/system resource print', timeout=20)
            
            # Extract model and version
            version_match = re.search(r'version: (\S+)', resource_output)
            if version_match:
                info['firmware'] = version_match.group(1)
            
            board_match = re.search(r'board-name: (\S+)', resource_output)
            if board_match:
                info['model'] = board_match.group(1)
            
            info['device_type'] = 'router'
        
        except Exception as e:
            logger.debug(f"Error identifying MikroTik device: {e}")
        
        return info
    
    def _generic_device_identification(self, connection) -> Dict[str, Any]:
        """Generic device identification for unknown types."""
        info = {'capabilities': ['ssh_access']}
        
        try:
            # Try common commands
            commands = [
                'hostname',
                'uname -a',
                'cat /etc/os-release',
                'show version'
            ]
            
            for cmd in commands:
                try:
                    output = connection.send_command(cmd, timeout=10)
                    if output and not 'invalid' in output.lower():
                        info['capabilities'].append(f'supports_{cmd.replace(" ", "_")}')
                        if 'hostname' in cmd and output.strip():
                            info['hostname'] = output.strip()
                except:
                    continue
        
        except Exception as e:
            logger.debug(f"Error in generic device identification: {e}")
        
        return info
    
    def _calculate_ssh_confidence_score(self, device: DiscoveredDevice) -> float:
        """Calculate confidence score for SSH discovery."""
        score = 0.0
        
        # Base score for successful SSH authentication
        score += 0.4
        
        # Vendor identification
        if device.vendor:
            score += 0.2
        
        # Model identification
        if device.model:
            score += 0.2
        
        # Firmware version
        if device.firmware_version:
            score += 0.1
        
        # Capabilities
        if device.capabilities:
            score += min(len(device.capabilities) * 0.05, 0.1)
        
        return min(score, 1.0)


class NetworkScanner:
    """Network scanning utilities for device discovery."""
    
    def __init__(self, max_threads: int = 50):
        self.max_threads = max_threads
    
    def ping_sweep(self, network_range: str, timeout: int = 1) -> List[str]:
        """Perform ping sweep to find reachable hosts."""
        reachable_hosts = []
        
        try:
            network = IPv4Network(network_range, strict=False)
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Submit ping tasks for all hosts
                future_to_ip = {
                    executor.submit(self._ping_host, str(ip), timeout): str(ip)
                    for ip in network.hosts()
                }
                
                # Collect results
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        if future.result():
                            reachable_hosts.append(ip)
                    except Exception as e:
                        logger.debug(f"Ping failed for {ip}: {e}")
        
        except AddressValueError as e:
            logger.error(f"Invalid network range {network_range}: {e}")
        
        return reachable_hosts
    
    def _ping_host(self, ip_address: str, timeout: int) -> bool:
        """Ping single host to check reachability."""
        import subprocess
        import sys
        
        try:
            if sys.platform.startswith('win'):
                cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip_address]
            else:
                cmd = ['ping', '-c', '1', '-W', str(timeout), ip_address]
            
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
            return result.returncode == 0
        
        except (subprocess.TimeoutExpired, Exception):
            return False
    
    def port_scan(self, ip_address: str, ports: List[int], timeout: int = 3) -> List[int]:
        """Scan for open ports on a host."""
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=min(len(ports), 20)) as executor:
            future_to_port = {
                executor.submit(self._check_port, ip_address, port, timeout): port
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Port scan failed for {ip_address}:{port}: {e}")
        
        return sorted(open_ports)
    
    def _check_port(self, ip_address: str, port: int, timeout: int) -> bool:
        """Check if specific port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False


class DeviceDiscoveryManager:
    """Main device discovery manager."""
    
    def __init__(self, max_concurrent: int = 20):
        self.max_concurrent = max_concurrent
        self.snmp_discovery = SNMPDiscovery() if SNMP_AVAILABLE else None
        self.ssh_discovery = SSHDiscovery()
        self.network_scanner = NetworkScanner(max_concurrent)
        
        # Common SNMP communities and SSH credentials to try
        self.default_snmp_communities = ['public', 'private', 'community']
        self.default_ssh_credentials = [
            {'username': 'admin', 'password': 'admin', 'device_type': 'cisco_ios'},
            {'username': 'admin', 'password': 'password', 'device_type': 'cisco_ios'},
            {'username': 'cisco', 'password': 'cisco', 'device_type': 'cisco_ios'},
            {'username': 'admin', 'password': 'admin', 'device_type': 'juniper_junos'},
            {'username': 'admin', 'password': '', 'device_type': 'mikrotik_routeros'},
        ]
    
    def discover_network_range(self, network_range: NetworkRange) -> List[DiscoveredDevice]:
        """Discover all devices in a network range."""
        discovered_devices = []
        
        logger.info(f"Starting discovery for network range: {network_range.network}")
        
        # Step 1: Find reachable hosts
        logger.info("Performing ping sweep...")
        reachable_hosts = self.network_scanner.ping_sweep(network_range.network)
        logger.info(f"Found {len(reachable_hosts)} reachable hosts")
        
        # Step 2: Discover devices using configured methods
        with ThreadPoolExecutor(max_workers=self.max_concurrent) as executor:
            future_to_ip = {}
            
            for ip in reachable_hosts:
                future = executor.submit(self._discover_single_device, ip, network_range)
                future_to_ip[future] = ip
            
            # Collect results
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        discovered_devices.append(device)
                        logger.info(f"Discovered device: {ip} - {device.vendor} {device.model}")
                except Exception as e:
                    logger.error(f"Discovery failed for {ip}: {e}")
        
        logger.info(f"Discovery completed. Found {len(discovered_devices)} devices")
        return discovered_devices
    
    def _discover_single_device(self, ip_address: str, network_range: NetworkRange) -> Optional[DiscoveredDevice]:
        """Discover single device using multiple methods."""
        best_device = None
        highest_confidence = 0.0
        
        for method in network_range.discovery_methods:
            try:
                device = None
                
                if method == DiscoveryMethod.SNMP and self.snmp_discovery:
                    device = self._try_snmp_discovery(ip_address)
                elif method == DiscoveryMethod.SSH:
                    device = self._try_ssh_discovery(ip_address, network_range.credentials)
                elif method == DiscoveryMethod.TCP_SCAN:
                    # Port scan to identify device type
                    open_ports = self.network_scanner.port_scan(ip_address, [22, 23, 80, 443, 161, 514])
                    if open_ports:
                        device = DiscoveredDevice(
                            ip_address=ip_address,
                            discovery_method=DiscoveryMethod.TCP_SCAN,
                            status=DeviceStatus.REACHABLE,
                            additional_info={'open_ports': open_ports},
                            confidence_score=0.2
                        )
                
                if device and device.confidence_score > highest_confidence:
                    best_device = device
                    highest_confidence = device.confidence_score
                    
                    # If we have high confidence, no need to try other methods
                    if highest_confidence >= 0.8:
                        break
                        
            except Exception as e:
                logger.debug(f"Discovery method {method} failed for {ip_address}: {e}")
        
        return best_device
    
    def _try_snmp_discovery(self, ip_address: str) -> Optional[DiscoveredDevice]:
        """Try SNMP discovery with multiple communities."""
        if not self.snmp_discovery:
            return None
        
        for community in self.default_snmp_communities:
            try:
                device = self.snmp_discovery.discover_device(ip_address, community)
                if device:
                    return device
            except Exception as e:
                logger.debug(f"SNMP discovery with community '{community}' failed for {ip_address}: {e}")
        
        return None
    
    def _try_ssh_discovery(self, ip_address: str, custom_credentials: List[Dict[str, str]]) -> Optional[DiscoveredDevice]:
        """Try SSH discovery with multiple credential sets."""
        # Combine custom credentials with defaults
        all_credentials = custom_credentials + self.default_ssh_credentials
        
        for creds in all_credentials:
            try:
                device = self.ssh_discovery.discover_device(ip_address, creds)
                if device:
                    return device
            except Exception as e:
                logger.debug(f"SSH discovery failed for {ip_address} with {creds.get('username')}: {e}")
        
        return None
    
    def discover_single_device(self, ip_address: str, 
                             methods: List[DiscoveryMethod] = None,
                             credentials: List[Dict[str, str]] = None) -> Optional[DiscoveredDevice]:
        """Discover single device with specified methods and credentials."""
        if methods is None:
            methods = [DiscoveryMethod.SNMP, DiscoveryMethod.SSH]
        
        if credentials is None:
            credentials = []
        
        network_range = NetworkRange(
            network=f"{ip_address}/32",
            discovery_methods=methods,
            credentials=credentials
        )
        
        return self._discover_single_device(ip_address, network_range)


# Convenience functions
def discover_network(network_range: str, 
                    methods: List[DiscoveryMethod] = None,
                    credentials: List[Dict[str, str]] = None) -> List[DiscoveredDevice]:
    """Convenience function to discover devices in network range."""
    if methods is None:
        methods = [DiscoveryMethod.ICMP, DiscoveryMethod.SNMP, DiscoveryMethod.SSH]
    
    if credentials is None:
        credentials = []
    
    network = NetworkRange(
        network=network_range,
        discovery_methods=methods,
        credentials=credentials
    )
    
    manager = DeviceDiscoveryManager()
    return manager.discover_network_range(network)


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    # Test single device discovery
    manager = DeviceDiscoveryManager()
    
    # Test credentials
    test_creds = [
        {'username': 'admin', 'password': 'admin', 'device_type': 'cisco_ios'}
    ]
    
    # Discover single device
    device = manager.discover_single_device(
        '192.168.1.100',
        methods=[DiscoveryMethod.SSH, DiscoveryMethod.SNMP],
        credentials=test_creds
    )
    
    if device:
        print(f"Discovered device: {device.ip_address}")
        print(f"Vendor: {device.vendor}")
        print(f"Model: {device.model}")
        print(f"Type: {device.device_type}")
        print(f"Confidence: {device.confidence_score}")
    else:
        print("No device discovered")
    
    # Test network range discovery
    print("\nTesting network discovery...")
    devices = discover_network(
        "192.168.1.0/24",
        methods=[DiscoveryMethod.ICMP, DiscoveryMethod.SNMP],
        credentials=test_creds
    )
    
    print(f"Discovered {len(devices)} devices in network")
    for dev in devices[:5]:  # Show first 5
        print(f"  {dev.ip_address}: {dev.vendor} {dev.model}")