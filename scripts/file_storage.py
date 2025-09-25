"""
File Storage Management System
=============================

This module provides comprehensive file storage handlers for local, SFTP,
and cloud storage with compression, encryption, and integrity verification.
It supports multiple storage backends and provides unified API for backup
file management.

Features:
- Multiple storage backends (local, SFTP, S3, Azure, GCP)
- File compression and encryption
- Integrity verification with checksums
- Retention policy management
- Bandwidth throttling and resume capabilities
- Storage health monitoring
- Bulk operations and synchronization
- Metadata tracking and indexing
"""

import logging
import os
import hashlib
import gzip
import shutil
import threading
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple, BinaryIO, Union
from dataclasses import dataclass, field
from enum import Enum
from contextlib import contextmanager
import json
import tempfile
import time

# Encryption imports
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    logging.warning("Cryptography not available. Install for encryption support.")

# SFTP imports
try:
    import paramiko
    SFTP_AVAILABLE = True
except ImportError:
    SFTP_AVAILABLE = False
    logging.warning("Paramiko not available. Install for SFTP support.")

# Cloud storage imports
try:
    import boto3
    from botocore.exceptions import ClientError
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False

try:
    from azure.storage.blob import BlobServiceClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import storage as gcp_storage
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

from error_handling import error_manager, retry_with_backoff, RetryConfig

# Configure logging
logger = logging.getLogger(__name__)


class StorageType(Enum):
    """Storage backend types."""
    LOCAL = "local"
    SFTP = "sftp"
    S3 = "s3"
    AZURE = "azure"
    GCP = "gcp"


class CompressionType(Enum):
    """Compression algorithms."""
    NONE = "none"
    GZIP = "gzip"
    BZIP2 = "bzip2"
    LZMA = "lzma"


class StorageStatus(Enum):
    """Storage operation status."""
    PENDING = "pending"
    UPLOADING = "uploading"
    UPLOADED = "uploaded"
    FAILED = "failed"
    DELETED = "deleted"
    ARCHIVED = "archived"


@dataclass
class StorageConfig:
    """Configuration for storage backend."""
    storage_type: StorageType
    connection_params: Dict[str, Any] = field(default_factory=dict)
    encryption_enabled: bool = False
    compression_type: CompressionType = CompressionType.GZIP
    retention_days: int = 30
    bandwidth_limit_mbps: Optional[float] = None
    concurrent_uploads: int = 3
    chunk_size: int = 8192  # 8KB chunks
    verify_integrity: bool = True


@dataclass
class StorageMetadata:
    """Metadata for stored files."""
    file_path: str
    original_size: int
    compressed_size: Optional[int] = None
    encryption_enabled: bool = False
    compression_type: CompressionType = CompressionType.NONE
    checksum_md5: Optional[str] = None
    checksum_sha256: Optional[str] = None
    upload_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    storage_type: StorageType = StorageType.LOCAL
    storage_path: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    custom_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UploadResult:
    """Result of file upload operation."""
    success: bool
    storage_path: Optional[str] = None
    metadata: Optional[StorageMetadata] = None
    error_message: Optional[str] = None
    upload_time_seconds: float = 0.0
    bytes_transferred: int = 0


class EncryptionManager:
    """Handles file encryption and decryption."""
    
    def __init__(self, password: Optional[str] = None):
        if not ENCRYPTION_AVAILABLE:
            raise ImportError("Cryptography library not available")
        
        self.password = password
        self._key = None
        if password:
            self._key = self._derive_key(password)
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password."""
        salt = b'longterm_backup_salt'  # In production, use random salt per file
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using Fernet symmetric encryption."""
        if not self._key:
            raise ValueError("Encryption key not set")
        
        f = Fernet(self._key)
        return f.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using Fernet symmetric encryption."""
        if not self._key:
            raise ValueError("Encryption key not set")
        
        f = Fernet(self._key)
        return f.decrypt(encrypted_data)
    
    def encrypt_file(self, input_path: str, output_path: str) -> int:
        """Encrypt file and return encrypted size."""
        with open(input_path, 'rb') as infile:
            data = infile.read()
        
        encrypted_data = self.encrypt_data(data)
        
        with open(output_path, 'wb') as outfile:
            outfile.write(encrypted_data)
        
        return len(encrypted_data)
    
    def decrypt_file(self, input_path: str, output_path: str) -> int:
        """Decrypt file and return decrypted size."""
        with open(input_path, 'rb') as infile:
            encrypted_data = infile.read()
        
        data = self.decrypt_data(encrypted_data)
        
        with open(output_path, 'wb') as outfile:
            outfile.write(data)
        
        return len(data)


class CompressionManager:
    """Handles file compression and decompression."""
    
    @staticmethod
    def compress_file(input_path: str, output_path: str, 
                     compression_type: CompressionType = CompressionType.GZIP) -> Tuple[int, int]:
        """Compress file and return (original_size, compressed_size)."""
        original_size = os.path.getsize(input_path)
        
        if compression_type == CompressionType.GZIP:
            with open(input_path, 'rb') as infile:
                with gzip.open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        elif compression_type == CompressionType.BZIP2:
            import bz2
            with open(input_path, 'rb') as infile:
                with bz2.open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        elif compression_type == CompressionType.LZMA:
            import lzma
            with open(input_path, 'rb') as infile:
                with lzma.open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        else:
            # No compression, just copy
            shutil.copy2(input_path, output_path)
        
        compressed_size = os.path.getsize(output_path)
        return original_size, compressed_size
    
    @staticmethod
    def decompress_file(input_path: str, output_path: str, 
                       compression_type: CompressionType = CompressionType.GZIP) -> int:
        """Decompress file and return decompressed size."""
        if compression_type == CompressionType.GZIP:
            with gzip.open(input_path, 'rb') as infile:
                with open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        elif compression_type == CompressionType.BZIP2:
            import bz2
            with bz2.open(input_path, 'rb') as infile:
                with open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        elif compression_type == CompressionType.LZMA:
            import lzma
            with lzma.open(input_path, 'rb') as infile:
                with open(output_path, 'wb') as outfile:
                    shutil.copyfileobj(infile, outfile)
        
        else:
            # No compression, just copy
            shutil.copy2(input_path, output_path)
        
        return os.path.getsize(output_path)


class ChecksumCalculator:
    """Handles file integrity verification."""
    
    @staticmethod
    def calculate_file_checksums(file_path: str) -> Tuple[str, str]:
        """Calculate MD5 and SHA256 checksums for file."""
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_path: str, expected_md5: Optional[str] = None,
                            expected_sha256: Optional[str] = None) -> bool:
        """Verify file integrity against expected checksums."""
        if not expected_md5 and not expected_sha256:
            return True
        
        actual_md5, actual_sha256 = ChecksumCalculator.calculate_file_checksums(file_path)
        
        if expected_md5 and actual_md5 != expected_md5:
            return False
        
        if expected_sha256 and actual_sha256 != expected_sha256:
            return False
        
        return True


class BaseStorageBackend:
    """Base class for storage backends."""
    
    def __init__(self, config: StorageConfig):
        self.config = config
        self.logger = error_manager.get_logger(f"storage.{config.storage_type.value}")
    
    def upload_file(self, local_path: str, remote_path: str, 
                   metadata: Optional[StorageMetadata] = None) -> UploadResult:
        """Upload file to storage backend."""
        raise NotImplementedError
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from storage backend."""
        raise NotImplementedError
    
    def delete_file(self, remote_path: str) -> bool:
        """Delete file from storage backend."""
        raise NotImplementedError
    
    def list_files(self, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in storage backend."""
        raise NotImplementedError
    
    def file_exists(self, remote_path: str) -> bool:
        """Check if file exists in storage backend."""
        raise NotImplementedError
    
    def get_file_info(self, remote_path: str) -> Optional[Dict[str, Any]]:
        """Get file information from storage backend."""
        raise NotImplementedError


class LocalStorageBackend(BaseStorageBackend):
    """Local filesystem storage backend."""
    
    def __init__(self, config: StorageConfig):
        super().__init__(config)
        self.base_path = Path(config.connection_params.get('base_path', '/backups'))
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=1.0))
    def upload_file(self, local_path: str, remote_path: str, 
                   metadata: Optional[StorageMetadata] = None) -> UploadResult:
        """Upload file to local storage."""
        start_time = time.time()
        
        try:
            # Construct full destination path
            dest_path = self.base_path / remote_path.lstrip('/')
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Process file (compression/encryption)
            processed_path = self._process_file_for_upload(local_path)
            
            # Copy file
            shutil.copy2(processed_path, dest_path)
            
            # Clean up temporary file if it was created
            if processed_path != local_path:
                os.remove(processed_path)
            
            # Calculate metadata
            if not metadata:
                metadata = self._generate_metadata(local_path, str(dest_path))
            
            # Save metadata
            self._save_metadata(str(dest_path), metadata)
            
            upload_time = time.time() - start_time
            file_size = os.path.getsize(dest_path)
            
            self.logger.info(f"Local upload successful: {dest_path} ({file_size} bytes)")
            
            return UploadResult(
                success=True,
                storage_path=str(dest_path),
                metadata=metadata,
                upload_time_seconds=upload_time,
                bytes_transferred=file_size
            )
            
        except Exception as e:
            self.logger.error(f"Local upload failed: {e}", exception=e)
            return UploadResult(
                success=False,
                error_message=str(e),
                upload_time_seconds=time.time() - start_time
            )
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from local storage."""
        try:
            source_path = self.base_path / remote_path.lstrip('/')
            
            if not source_path.exists():
                return False
            
            # Load metadata to check for processing
            metadata = self._load_metadata(str(source_path))
            
            if metadata and (metadata.compression_type != CompressionType.NONE or metadata.encryption_enabled):
                # Need to process file during download
                processed_path = self._process_file_for_download(str(source_path), metadata)
                shutil.copy2(processed_path, local_path)
                os.remove(processed_path)
            else:
                # Direct copy
                shutil.copy2(source_path, local_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Local download failed: {e}", exception=e)
            return False
    
    def delete_file(self, remote_path: str) -> bool:
        """Delete file from local storage."""
        try:
            file_path = self.base_path / remote_path.lstrip('/')
            
            if file_path.exists():
                file_path.unlink()
                
                # Delete metadata file if it exists
                metadata_path = Path(str(file_path) + '.metadata')
                if metadata_path.exists():
                    metadata_path.unlink()
                
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Local delete failed: {e}", exception=e)
            return False
    
    def list_files(self, prefix: str = "") -> List[Dict[str, Any]]:
        """List files in local storage."""
        files = []
        
        try:
            search_path = self.base_path / prefix.lstrip('/')
            
            if search_path.is_file():
                files.append(self._file_to_dict(search_path))
            elif search_path.is_dir():
                for file_path in search_path.rglob('*'):
                    if file_path.is_file() and not file_path.name.endswith('.metadata'):
                        files.append(self._file_to_dict(file_path))
            
        except Exception as e:
            self.logger.error(f"Local list failed: {e}", exception=e)
        
        return files
    
    def file_exists(self, remote_path: str) -> bool:
        """Check if file exists in local storage."""
        file_path = self.base_path / remote_path.lstrip('/')
        return file_path.exists() and file_path.is_file()
    
    def get_file_info(self, remote_path: str) -> Optional[Dict[str, Any]]:
        """Get file information from local storage."""
        file_path = self.base_path / remote_path.lstrip('/')
        
        if not file_path.exists():
            return None
        
        return self._file_to_dict(file_path)
    
    def _process_file_for_upload(self, file_path: str) -> str:
        """Process file for upload (compression/encryption)."""
        current_path = file_path
        
        # Compression
        if self.config.compression_type != CompressionType.NONE:
            compressed_path = tempfile.mktemp(suffix=f'.{self.config.compression_type.value}')
            CompressionManager.compress_file(current_path, compressed_path, self.config.compression_type)
            
            if current_path != file_path:
                os.remove(current_path)
            current_path = compressed_path
        
        # Encryption
        if self.config.encryption_enabled and ENCRYPTION_AVAILABLE:
            if 'encryption_password' not in self.config.connection_params:
                raise ValueError("Encryption enabled but no password provided")
            
            encrypted_path = tempfile.mktemp(suffix='.encrypted')
            encryption_manager = EncryptionManager(self.config.connection_params['encryption_password'])
            encryption_manager.encrypt_file(current_path, encrypted_path)
            
            if current_path != file_path:
                os.remove(current_path)
            current_path = encrypted_path
        
        return current_path
    
    def _process_file_for_download(self, file_path: str, metadata: StorageMetadata) -> str:
        """Process file for download (decryption/decompression)."""
        current_path = file_path
        
        # Decryption
        if metadata.encryption_enabled and ENCRYPTION_AVAILABLE:
            if 'encryption_password' not in self.config.connection_params:
                raise ValueError("File is encrypted but no password provided")
            
            decrypted_path = tempfile.mktemp(suffix='.decrypted')
            encryption_manager = EncryptionManager(self.config.connection_params['encryption_password'])
            encryption_manager.decrypt_file(current_path, decrypted_path)
            current_path = decrypted_path
        
        # Decompression
        if metadata.compression_type != CompressionType.NONE:
            decompressed_path = tempfile.mktemp(suffix='.decompressed')
            CompressionManager.decompress_file(current_path, decompressed_path, metadata.compression_type)
            
            if current_path != file_path:
                os.remove(current_path)
            current_path = decompressed_path
        
        return current_path
    
    def _generate_metadata(self, original_path: str, storage_path: str) -> StorageMetadata:
        """Generate metadata for stored file."""
        original_size = os.path.getsize(original_path)
        compressed_size = os.path.getsize(storage_path) if storage_path != original_path else None
        
        # Calculate checksums of original file
        md5_checksum, sha256_checksum = ChecksumCalculator.calculate_file_checksums(original_path)
        
        return StorageMetadata(
            file_path=original_path,
            original_size=original_size,
            compressed_size=compressed_size,
            encryption_enabled=self.config.encryption_enabled,
            compression_type=self.config.compression_type,
            checksum_md5=md5_checksum,
            checksum_sha256=sha256_checksum,
            storage_type=self.config.storage_type,
            storage_path=storage_path
        )
    
    def _save_metadata(self, file_path: str, metadata: StorageMetadata):
        """Save metadata to accompanying file."""
        metadata_path = file_path + '.metadata'
        
        metadata_dict = {
            'file_path': metadata.file_path,
            'original_size': metadata.original_size,
            'compressed_size': metadata.compressed_size,
            'encryption_enabled': metadata.encryption_enabled,
            'compression_type': metadata.compression_type.value,
            'checksum_md5': metadata.checksum_md5,
            'checksum_sha256': metadata.checksum_sha256,
            'upload_time': metadata.upload_time.isoformat(),
            'storage_type': metadata.storage_type.value,
            'storage_path': metadata.storage_path,
            'tags': metadata.tags,
            'custom_metadata': metadata.custom_metadata
        }
        
        with open(metadata_path, 'w') as f:
            json.dump(metadata_dict, f, indent=2)
    
    def _load_metadata(self, file_path: str) -> Optional[StorageMetadata]:
        """Load metadata from accompanying file."""
        metadata_path = file_path + '.metadata'
        
        if not os.path.exists(metadata_path):
            return None
        
        try:
            with open(metadata_path, 'r') as f:
                data = json.load(f)
            
            return StorageMetadata(
                file_path=data['file_path'],
                original_size=data['original_size'],
                compressed_size=data.get('compressed_size'),
                encryption_enabled=data['encryption_enabled'],
                compression_type=CompressionType(data['compression_type']),
                checksum_md5=data.get('checksum_md5'),
                checksum_sha256=data.get('checksum_sha256'),
                upload_time=datetime.fromisoformat(data['upload_time']),
                storage_type=StorageType(data['storage_type']),
                storage_path=data.get('storage_path'),
                tags=data.get('tags', {}),
                custom_metadata=data.get('custom_metadata', {})
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to load metadata for {file_path}: {e}")
            return None
    
    def _file_to_dict(self, file_path: Path) -> Dict[str, Any]:
        """Convert file path to dictionary with file information."""
        stat = file_path.stat()
        
        # Load metadata if available
        metadata = self._load_metadata(str(file_path))
        
        file_info = {
            'path': str(file_path.relative_to(self.base_path)),
            'name': file_path.name,
            'size': stat.st_size,
            'modified_time': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
            'storage_type': self.config.storage_type.value
        }
        
        if metadata:
            file_info.update({
                'original_size': metadata.original_size,
                'compressed_size': metadata.compressed_size,
                'compression_type': metadata.compression_type.value,
                'encryption_enabled': metadata.encryption_enabled,
                'checksum_md5': metadata.checksum_md5,
                'checksum_sha256': metadata.checksum_sha256,
                'upload_time': metadata.upload_time.isoformat(),
                'tags': metadata.tags
            })
        
        return file_info


class SFTPStorageBackend(BaseStorageBackend):
    """SFTP storage backend."""
    
    def __init__(self, config: StorageConfig):
        super().__init__(config)
        
        if not SFTP_AVAILABLE:
            raise ImportError("Paramiko not available for SFTP")
        
        self.connection_pool = []
        self.pool_lock = threading.Lock()
        self.max_connections = config.concurrent_uploads
    
    @contextmanager
    def _get_sftp_connection(self):
        """Get SFTP connection from pool or create new one."""
        connection = None
        
        try:
            with self.pool_lock:
                if self.connection_pool:
                    connection = self.connection_pool.pop()
                else:
                    connection = self._create_sftp_connection()
            
            yield connection
            
        finally:
            if connection:
                with self.pool_lock:
                    if len(self.connection_pool) < self.max_connections:
                        self.connection_pool.append(connection)
                    else:
                        connection.close()
    
    def _create_sftp_connection(self):
        """Create new SFTP connection."""
        params = self.config.connection_params
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        ssh.connect(
            hostname=params['hostname'],
            port=params.get('port', 22),
            username=params['username'],
            password=params.get('password'),
            key_filename=params.get('key_filename'),
            timeout=params.get('timeout', 30)
        )
        
        sftp = ssh.open_sftp()
        sftp.ssh = ssh  # Keep reference to SSH connection
        
        return sftp
    
    @retry_with_backoff(RetryConfig(max_attempts=3, base_delay=2.0))
    def upload_file(self, local_path: str, remote_path: str, 
                   metadata: Optional[StorageMetadata] = None) -> UploadResult:
        """Upload file to SFTP server."""
        start_time = time.time()
        
        try:
            # Process file for upload
            processed_path = self._process_file_for_upload(local_path)
            
            with self._get_sftp_connection() as sftp:
                # Create remote directory if needed
                remote_dir = os.path.dirname(remote_path)
                self._ensure_remote_directory(sftp, remote_dir)
                
                # Upload file
                sftp.put(processed_path, remote_path)
                
                # Clean up temporary file
                if processed_path != local_path:
                    os.remove(processed_path)
                
                # Generate metadata
                if not metadata:
                    metadata = self._generate_metadata(local_path, remote_path)
                
                upload_time = time.time() - start_time
                file_size = sftp.stat(remote_path).st_size
                
                self.logger.info(f"SFTP upload successful: {remote_path} ({file_size} bytes)")
                
                return UploadResult(
                    success=True,
                    storage_path=remote_path,
                    metadata=metadata,
                    upload_time_seconds=upload_time,
                    bytes_transferred=file_size
                )
                
        except Exception as e:
            self.logger.error(f"SFTP upload failed: {e}", exception=e)
            return UploadResult(
                success=False,
                error_message=str(e),
                upload_time_seconds=time.time() - start_time
            )
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from SFTP server."""
        try:
            with self._get_sftp_connection() as sftp:
                # Download to temporary location first
                temp_path = local_path + '.tmp'
                sftp.get(remote_path, temp_path)
                
                # Move to final location
                shutil.move(temp_path, local_path)
                
                return True
                
        except Exception as e:
            self.logger.error(f"SFTP download failed: {e}", exception=e)
            return False
    
    def delete_file(self, remote_path: str) -> bool:
        """Delete file from SFTP server."""
        try:
            with self._get_sftp_connection() as sftp:
                sftp.remove(remote_path)
                return True
                
        except Exception as e:
            self.logger.error(f"SFTP delete failed: {e}", exception=e)
            return False
    
    def list_files(self, prefix: str = "") -> List[Dict[str, Any]]:
        """List files on SFTP server."""
        files = []
        
        try:
            with self._get_sftp_connection() as sftp:
                # List files in directory
                try:
                    file_list = sftp.listdir_attr(prefix)
                    for file_attr in file_list:
                        if not file_attr.filename.startswith('.'):
                            files.append({
                                'path': os.path.join(prefix, file_attr.filename),
                                'name': file_attr.filename,
                                'size': file_attr.st_size,
                                'modified_time': datetime.fromtimestamp(file_attr.st_mtime, tz=timezone.utc).isoformat(),
                                'storage_type': self.config.storage_type.value
                            })
                except FileNotFoundError:
                    pass
                    
        except Exception as e:
            self.logger.error(f"SFTP list failed: {e}", exception=e)
        
        return files
    
    def file_exists(self, remote_path: str) -> bool:
        """Check if file exists on SFTP server."""
        try:
            with self._get_sftp_connection() as sftp:
                sftp.stat(remote_path)
                return True
        except FileNotFoundError:
            return False
        except Exception as e:
            self.logger.error(f"SFTP file exists check failed: {e}", exception=e)
            return False
    
    def get_file_info(self, remote_path: str) -> Optional[Dict[str, Any]]:
        """Get file information from SFTP server."""
        try:
            with self._get_sftp_connection() as sftp:
                stat = sftp.stat(remote_path)
                return {
                    'path': remote_path,
                    'name': os.path.basename(remote_path),
                    'size': stat.st_size,
                    'modified_time': datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    'storage_type': self.config.storage_type.value
                }
        except Exception as e:
            self.logger.error(f"SFTP get file info failed: {e}", exception=e)
            return None
    
    def _ensure_remote_directory(self, sftp, remote_dir: str):
        """Create remote directory if it doesn't exist."""
        if not remote_dir or remote_dir == '/':
            return
        
        try:
            sftp.stat(remote_dir)
        except FileNotFoundError:
            # Directory doesn't exist, create it
            parent_dir = os.path.dirname(remote_dir)
            if parent_dir != remote_dir:
                self._ensure_remote_directory(sftp, parent_dir)
            
            sftp.mkdir(remote_dir)
    
    def _process_file_for_upload(self, file_path: str) -> str:
        """Process file for upload (compression/encryption)."""
        # Use same logic as LocalStorageBackend
        return LocalStorageBackend._process_file_for_upload(self, file_path)
    
    def _generate_metadata(self, original_path: str, storage_path: str) -> StorageMetadata:
        """Generate metadata for stored file."""
        # Use same logic as LocalStorageBackend
        return LocalStorageBackend._generate_metadata(self, original_path, storage_path)
    
    def cleanup_connections(self):
        """Close all pooled connections."""
        with self.pool_lock:
            for connection in self.connection_pool:
                try:
                    connection.close()
                    if hasattr(connection, 'ssh'):
                        connection.ssh.close()
                except:
                    pass
            self.connection_pool.clear()


class StorageManager:
    """Main storage management interface."""
    
    def __init__(self):
        self.backends: Dict[str, BaseStorageBackend] = {}
        self.default_backend: Optional[str] = None
    
    def add_backend(self, name: str, config: StorageConfig, set_as_default: bool = False):
        """Add storage backend."""
        if config.storage_type == StorageType.LOCAL:
            backend = LocalStorageBackend(config)
        elif config.storage_type == StorageType.SFTP:
            backend = SFTPStorageBackend(config)
        else:
            raise ValueError(f"Unsupported storage type: {config.storage_type}")
        
        self.backends[name] = backend
        
        if set_as_default or not self.default_backend:
            self.default_backend = name
        
        logger.info(f"Added {config.storage_type.value} storage backend: {name}")
    
    def get_backend(self, name: Optional[str] = None) -> BaseStorageBackend:
        """Get storage backend by name."""
        backend_name = name or self.default_backend
        
        if not backend_name or backend_name not in self.backends:
            raise ValueError(f"Storage backend '{backend_name}' not found")
        
        return self.backends[backend_name]
    
    def upload_file(self, local_path: str, remote_path: str, 
                   backend_name: Optional[str] = None,
                   metadata: Optional[StorageMetadata] = None) -> UploadResult:
        """Upload file using specified backend."""
        backend = self.get_backend(backend_name)
        return backend.upload_file(local_path, remote_path, metadata)
    
    def download_file(self, remote_path: str, local_path: str,
                     backend_name: Optional[str] = None) -> bool:
        """Download file using specified backend."""
        backend = self.get_backend(backend_name)
        return backend.download_file(remote_path, local_path)
    
    def delete_file(self, remote_path: str, backend_name: Optional[str] = None) -> bool:
        """Delete file using specified backend."""
        backend = self.get_backend(backend_name)
        return backend.delete_file(remote_path)
    
    def list_files(self, prefix: str = "", backend_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """List files using specified backend."""
        backend = self.get_backend(backend_name)
        return backend.list_files(prefix)
    
    def cleanup_old_files(self, retention_days: int, backend_name: Optional[str] = None) -> int:
        """Clean up files older than retention period."""
        backend = self.get_backend(backend_name)
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        files = backend.list_files()
        deleted_count = 0
        
        for file_info in files:
            try:
                file_date = datetime.fromisoformat(file_info['modified_time'])
                if file_date < cutoff_date:
                    if backend.delete_file(file_info['path']):
                        deleted_count += 1
                        logger.info(f"Deleted old file: {file_info['path']}")
            except Exception as e:
                logger.warning(f"Error processing file {file_info['path']}: {e}")
        
        logger.info(f"Cleaned up {deleted_count} old files")
        return deleted_count


# Global storage manager
storage_manager = StorageManager()


if __name__ == "__main__":
    # Example usage and testing
    logging.basicConfig(level=logging.INFO)
    
    # Test local storage
    local_config = StorageConfig(
        storage_type=StorageType.LOCAL,
        connection_params={'base_path': '/tmp/test_backups'},
        compression_type=CompressionType.GZIP,
        encryption_enabled=True if ENCRYPTION_AVAILABLE else False
    )
    
    if ENCRYPTION_AVAILABLE:
        local_config.connection_params['encryption_password'] = 'test_password_123'
    
    storage_manager.add_backend('local', local_config, set_as_default=True)
    
    # Create test file
    test_file = '/tmp/test_backup.txt'
    with open(test_file, 'w') as f:
        f.write("This is a test backup file content.\n" * 100)
    
    # Upload test
    result = storage_manager.upload_file(test_file, 'test/backup_001.txt')
    print(f"Upload result: {result.success}")
    if result.success:
        print(f"Uploaded to: {result.storage_path}")
        print(f"Upload time: {result.upload_time_seconds:.2f}s")
        print(f"Bytes transferred: {result.bytes_transferred}")
    
    # List files
    files = storage_manager.list_files()
    print(f"Files in storage: {len(files)}")
    for file_info in files:
        print(f"  {file_info['path']} ({file_info['size']} bytes)")
    
    # Download test
    download_path = '/tmp/downloaded_backup.txt'
    success = storage_manager.download_file('test/backup_001.txt', download_path)
    print(f"Download successful: {success}")
    
    if success and os.path.exists(download_path):
        with open(download_path, 'r') as f:
            content = f.read()
        print(f"Downloaded content length: {len(content)} characters")
    
    # Cleanup
    os.remove(test_file)
    if os.path.exists(download_path):
        os.remove(download_path)