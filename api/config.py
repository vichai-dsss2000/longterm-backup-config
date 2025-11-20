from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    # Environment
    environment: str = "development"  # development or production
    
    # Database
    database_url: str = "sqlite:///./longterm_backup_config.db"
    
    # JWT Configuration
    secret_key: str = "longterm_backup_config-1234567890abcdef"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 720
    
    # Security - Encryption
    device_encryption_key: Optional[str] = os.getenv('DEVICE_ENCRYPTION_KEY')
    encryption_key: Optional[str] = None  # Fernet key for credential encryption
    
    # Security - Password Policy
    password_min_length: int = 12
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    
    # Security - Rate Limiting
    rate_limit_enabled: bool = True
    rate_limit_times: int = 100  # requests
    rate_limit_seconds: int = 60  # per 60 seconds
    login_rate_limit_times: int = 5  # login attempts
    login_rate_limit_seconds: int = 300  # per 5 minutes
    
    # Security - Account Lockout
    max_login_attempts: int = 5
    account_lockout_duration_minutes: int = 30
    
    # Security - Session Management
    session_timeout_minutes: int = 60
    max_concurrent_sessions: int = 3
    
    # SMTP Configuration
    smtp_server: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@yourdomain.com"
    smtp_use_tls: bool = True
    
    # SFTP Configuration
    default_sftp_server: str = "your-backup-server.com"
    default_sftp_username: str = "backup_user"
    default_sftp_password: str = "backup_password"
    default_sftp_port: int = 22
    default_backup_path: str = "/backups/network-devices"
    
    # Application Settings
    max_concurrent_backups: int = 10
    backup_retention_days: int = 90
    log_level: str = "INFO"
    cors_origins: str = "http://localhost:3000,http://localhost:8080"
    
    # Monitoring & Alerts
    alert_email: str = ""
    slack_webhook_url: str = ""
    
    class Config:
        env_file = ".env"
        extra = "ignore"
    
    def model_post_init(self, __context):
        """Validate security settings in production"""
        if self.environment == "production":
            # Validate JWT secret
            if self.secret_key == "your-secret-key-change-this-in-production" or len(self.secret_key) < 20:
                raise ValueError(
                    "CRITICAL: Must set SECRET_KEY in production environment. "
                    "Generate with: openssl rand -hex 32"
                )
            
            # Validate encryption key
            if not self.device_encryption_key or "change-this" in (self.device_encryption_key or ""):
                raise ValueError(
                    "CRITICAL: Must set DEVICE_ENCRYPTION_KEY in production environment. "
                    "Generate with: python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
                )
            
            # Warn about CORS in production
            if "localhost" in self.cors_origins:
                import warnings
                warnings.warn(
                    "WARNING: CORS origins contain 'localhost' in production environment. "
                    "Set CORS_ORIGINS to your actual frontend domain."
                )

settings = Settings()