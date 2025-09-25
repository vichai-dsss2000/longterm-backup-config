from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # Database
    database_url: str = "sqlite:///./longterm_backup_config.db"
    
    # JWT Configuration
    secret_key: str = "your-secret-key-change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 720
    
    # SMTP Configuration
    smtp_server: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = "noreply@yourdomain.com"
    
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
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()