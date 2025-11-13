# Security Policy and Best Practices

## 🔒 Security Overview

This document outlines security considerations, known vulnerabilities, and best practices for the Network Device Backup Management System.

---

## 📋 Table of Contents

1. [Critical Security Concerns](#-critical-security-concerns)
2. [Security Fixes Implemented](#-security-fixes-implemented)
3. [Recommended Security Enhancements](#-recommended-security-enhancements)
4. [Authentication & Authorization](#-authentication--authorization)
5. [Data Protection](#-data-protection)
6. [Network Security](#-network-security)
7. [Container Security](#-container-security)
8. [Reporting Security Issues](#-reporting-security-issues)

---

## 🚨 Critical Security Concerns

### 1. **Plaintext Password Storage** ⚠️ HIGH PRIORITY

**Issue:** Device SSH passwords are currently stored in plaintext in the database.

**Location:**
- `api/database.py` - `NetworkDevice` model: `ssh_password_encrypted` field
- `api/models/device_models.py` - Similar issue

**Impact:**
- Database breach exposes all device credentials
- Compliance violations (PCI DSS, GDPR)

**Fix Implemented:**
```python
# api/auth.py - Encryption utilities added
from cryptography.fernet import Fernet

class CredentialEncryption:
    """Encrypt/decrypt sensitive credentials"""
    
    def __init__(self, encryption_key: str):
        self.cipher_suite = Fernet(encryption_key.encode())
    
    def encrypt(self, plaintext: str) -> str:
        return self.cipher_suite.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        return self.cipher_suite.decrypt(ciphertext.encode()).decode()
```

**Usage:**
```python
# Before saving device
encryption = CredentialEncryption(settings.ENCRYPTION_KEY)
device.ssh_password_encrypted = encryption.encrypt(ssh_password)

# When using credentials
decrypted_password = encryption.decrypt(device.ssh_password_encrypted)
```

**Configuration Required:**
```bash
# In .env file - generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
ENCRYPTION_KEY=your-32-byte-base64-encoded-key-here
```

---

### 2. **Missing Input Validation** ⚠️ HIGH PRIORITY

**Issue:** User input not properly validated, susceptible to injection attacks.

**Location:**
- Device IP addresses
- Template backup commands
- Cron expressions
- File paths

**Impact:**
- Command injection via backup templates
- SQL injection (partially mitigated by SQLAlchemy ORM)
- Path traversal attacks

**Fix Required:**
```python
# api/schemas.py - Add validation
from pydantic import BaseModel, Field, validator
import ipaddress
import re

class NetworkDeviceCreate(BaseModel):
    ip_address: str = Field(..., description="Device IP address")
    
    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address format')

class BackupCommandTemplateCreate(BaseModel):
    backup_command: str = Field(..., max_length=2000)
    
    @validator('backup_command')
    def validate_command(cls, v):
        # Prevent dangerous commands
        dangerous_patterns = ['rm -rf', 'dd if=', '>/dev/', 'mkfs', 'format']
        if any(pattern in v.lower() for pattern in dangerous_patterns):
            raise ValueError('Command contains potentially dangerous operations')
        return v
```

---

### 3. **Weak JWT Configuration** ⚠️ MEDIUM PRIORITY

**Issue:** JWT secret key and token expiration not properly configured.

**Location:**
- `api/config.py` - `Settings` class
- `api/auth.py` - Token generation

**Current Implementation:**
```python
# api/auth.py
SECRET_KEY = "your-secret-key-here"  # ❌ Hardcoded
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # ⚠️ May be too short
```

**Recommended Fix:**
```python
# api/config.py
from pydantic_settings import BaseSettings
import secrets

class Settings(BaseSettings):
    # JWT Configuration
    jwt_secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60
    jwt_refresh_token_expire_days: int = 7
    
    # Require strong key in production
    class Config:
        env_file = ".env"
        
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if len(self.jwt_secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")
```

**Generate Strong Key:**
```bash
# Add to .env
python -c "import secrets; print(f'JWT_SECRET_KEY={secrets.token_urlsafe(32)}')"
```

---

### 4. **CORS Misconfiguration** ⚠️ MEDIUM PRIORITY

**Issue:** CORS allows all origins in development mode.

**Location:**
- `api/main.py` - CORS middleware configuration

**Current:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ❌ Allows all origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Recommended Fix:**
```python
# api/config.py
class Settings(BaseSettings):
    cors_origins: str = "http://localhost:3001"  # Comma-separated
    environment: str = "development"

# api/main.py
allowed_origins = settings.cors_origins.split(",")

if settings.environment == "production":
    # Strict CORS in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
else:
    # Permissive CORS for development
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
```

---

### 5. **Missing Rate Limiting** ⚠️ MEDIUM PRIORITY

**Issue:** No rate limiting on authentication endpoints.

**Impact:**
- Brute force attacks on login endpoint
- DoS attacks

**Recommended Implementation:**
```python
# api/main.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# api/routers/auth_router.py
@router.post("/login")
@limiter.limit("5/minute")  # 5 attempts per minute
async def login(request: Request, credentials: UserLogin, db: Session = Depends(get_db)):
    # ... login logic
```

**Install dependency:**
```bash
pip install slowapi
```

---

### 6. **SSH Key Management** ⚠️ HIGH PRIORITY

**Issue:** SSH private keys may be stored insecurely.

**Recommended Implementation:**
```python
# api/utils/ssh_key_manager.py
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class SSHKeyManager:
    """Secure SSH key storage and management"""
    
    def __init__(self, key_storage_path: str = "/app/secrets/ssh_keys"):
        self.storage_path = Path(key_storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    
    def generate_key_pair(self, device_id: str) -> tuple[str, str]:
        """Generate RSA key pair for device"""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Private key
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                os.environ['SSH_KEY_PASSPHRASE'].encode()
            )
        )
        
        # Public key
        public_key = key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        )
        
        # Save with restricted permissions
        private_key_path = self.storage_path / f"{device_id}_private.pem"
        private_key_path.write_bytes(private_pem)
        private_key_path.chmod(0o600)
        
        public_key_path = self.storage_path / f"{device_id}_public.pub"
        public_key_path.write_bytes(public_pem)
        public_key_path.chmod(0o644)
        
        return str(private_key_path), str(public_key_path)
```

---

### 7. **Backup File Access Control** ⚠️ MEDIUM PRIORITY

**Issue:** Backup files may be accessible without proper authorization.

**Recommended Implementation:**
```python
# api/routers/backup_router.py
from fastapi import HTTPException, status
from fastapi.responses import FileResponse
import os

@router.get("/{backup_id}/download")
async def download_backup(
    backup_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Verify backup ownership or admin access
    backup = db.query(DeviceBackupInfo).filter(DeviceBackupInfo.id == backup_id).first()
    
    if not backup:
        raise HTTPException(status_code=404, detail="Backup not found")
    
    # Check user permissions
    if not current_user['is_admin']:
        # Non-admin users can only access backups from their devices
        device = db.query(NetworkDevice).filter(NetworkDevice.id == backup.device_id).first()
        if not device or not user_has_access_to_device(current_user, device):
            raise HTTPException(status_code=403, detail="Access denied")
    
    # Validate file path (prevent path traversal)
    backup_path = os.path.abspath(backup.backup_file_path)
    allowed_dir = os.path.abspath(settings.backup_storage_path)
    
    if not backup_path.startswith(allowed_dir):
        raise HTTPException(status_code=403, detail="Invalid file path")
    
    if not os.path.exists(backup_path):
        raise HTTPException(status_code=404, detail="Backup file not found")
    
    return FileResponse(
        backup_path,
        media_type="application/octet-stream",
        filename=os.path.basename(backup_path)
    )
```

---

## ✅ Security Fixes Implemented

### 1. **Password Hashing**
- ✅ Using bcrypt with 12 rounds for user passwords
- ✅ Implemented in `api/auth.py`

### 2. **JWT Authentication**
- ✅ Token-based authentication
- ✅ Bearer token scheme
- ✅ Token expiration implemented

### 3. **SQL Injection Protection**
- ✅ SQLAlchemy ORM used (parameterized queries)
- ✅ No raw SQL execution with user input

### 4. **HTTPS Support**
- ✅ nginx configuration includes SSL/TLS setup
- ✅ Security headers configured

### 5. **Docker Security**
- ✅ Non-root user in containers
- ✅ Multi-stage builds
- ✅ Minimal base images

---

## 🛡️ Recommended Security Enhancements

### 1. **Add Secrets Management**

Use Docker secrets or Vault for sensitive data:

```yaml
# docker-compose.yml
secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

services:
  api:
    secrets:
      - db_password
      - jwt_secret
    environment:
      - DB_PASSWORD_FILE=/run/secrets/db_password
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
```

### 2. **Implement Audit Logging**

```python
# api/middleware/audit.py
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer)
    action = Column(String(100))
    resource_type = Column(String(50))
    resource_id = Column(Integer)
    ip_address = Column(String(45))
    user_agent = Column(String(255))
    changes = Column(JSON)
    status = Column(String(20))

@app.middleware("http")
async def audit_middleware(request: Request, call_next):
    # Log all API requests
    start_time = datetime.utcnow()
    response = await call_next(request)
    
    # Create audit log entry
    if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
        log_entry = AuditLog(
            timestamp=start_time,
            action=f"{request.method} {request.url.path}",
            ip_address=request.client.host,
            user_agent=request.headers.get("user-agent"),
            status=str(response.status_code)
        )
        # Save to database
    
    return response
```

### 3. **Enable 2FA (Two-Factor Authentication)**

```python
# api/auth.py
import pyotp

class TwoFactorAuth:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()
    
    @staticmethod
    def generate_qr_code(user_email: str, secret: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=user_email,
            issuer_name="Backup Management System"
        )
    
    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
```

### 4. **Implement Security Headers**

```python
# api/main.py
from fastapi.middleware.security import SecurityHeadersMiddleware

app.add_middleware(
    SecurityHeadersMiddleware,
    content_security_policy="default-src 'self'",
    x_content_type_options="nosniff",
    x_frame_options="DENY",
    x_xss_protection="1; mode=block",
    strict_transport_security="max-age=31536000; includeSubDomains"
)
```

### 5. **Add Input Sanitization**

```python
# api/utils/sanitize.py
import bleach
import re

class InputSanitizer:
    @staticmethod
    def sanitize_html(text: str) -> str:
        """Remove potentially dangerous HTML"""
        return bleach.clean(text, strip=True)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Remove dangerous characters from filenames"""
        # Remove path traversal attempts
        filename = filename.replace('..', '').replace('/', '').replace('\\', '')
        # Allow only alphanumeric, dash, underscore, dot
        return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
    
    @staticmethod
    def sanitize_shell_command(command: str) -> str:
        """Validate shell commands"""
        dangerous_chars = [';', '|', '&', '$', '`', '\n', '\r']
        for char in dangerous_chars:
            if char in command:
                raise ValueError(f"Dangerous character '{char}' detected in command")
        return command
```

---

## 🔐 Authentication & Authorization

### Current Implementation

✅ **Implemented:**
- JWT-based authentication
- Password hashing with bcrypt
- Token expiration
- Role-based access control (admin/user)

⚠️ **Missing:**
- Token refresh mechanism
- Session management
- Account lockout after failed attempts
- Password complexity requirements
- Password reset functionality

### Recommended Enhancements

```python
# api/auth.py
import re
from datetime import datetime, timedelta

class PasswordPolicy:
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    
    @classmethod
    def validate(cls, password: str) -> tuple[bool, list[str]]:
        errors = []
        
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain uppercase letter")
        
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain lowercase letter")
        
        if cls.REQUIRE_DIGIT and not re.search(r'\d', password):
            errors.append("Password must contain digit")
        
        if cls.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain special character")
        
        return len(errors) == 0, errors

class LoginAttemptTracker:
    """Track failed login attempts and implement account lockout"""
    
    MAX_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=30)
    
    def __init__(self, db: Session):
        self.db = db
    
    def record_failed_attempt(self, username: str, ip_address: str):
        # Record attempt in database
        pass
    
    def is_locked_out(self, username: str) -> bool:
        # Check if account is locked
        pass
    
    def reset_attempts(self, username: str):
        # Reset counter on successful login
        pass
```

---

## 🔒 Data Protection

### Encryption at Rest

**Recommended:**
```bash
# Enable MySQL encryption
[mysqld]
early-plugin-load=keyring_file.so
keyring_file_data=/var/lib/mysql-keyring/keyring

# Use encrypted tablespace
CREATE TABLESPACE encrypted_space
  ADD DATAFILE 'encrypted_space.ibd'
  ENCRYPTION='Y';
```

### Encryption in Transit

**Required Configuration:**
```nginx
# frontend/nginx.conf - Force HTTPS
server {
    listen 80;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
}
```

### Backup File Encryption

```python
# scripts/file_storage.py
from cryptography.fernet import Fernet

class SecureBackupStorage:
    def encrypt_backup_file(self, file_path: str, encryption_key: bytes):
        """Encrypt backup file before storage"""
        cipher = Fernet(encryption_key)
        
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        encrypted = cipher.encrypt(plaintext)
        
        with open(f"{file_path}.encrypted", 'wb') as f:
            f.write(encrypted)
        
        # Remove plaintext file
        os.remove(file_path)
```

---

## 🌐 Network Security

### Firewall Rules

**Recommended iptables configuration:**
```bash
# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (change port from 22 for security)
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow API port (only from frontend)
iptables -A INPUT -p tcp -s 172.18.0.0/16 --dport 8000 -j ACCEPT

# Drop all other incoming
iptables -A INPUT -j DROP
```

### Network Segmentation

**Docker network configuration:**
```yaml
networks:
  frontend-network:
    driver: bridge
    internal: false  # Accessible from outside
  backend-network:
    driver: bridge
    internal: true   # Not accessible from outside
  database-network:
    driver: bridge
    internal: true   # Only backend can access

services:
  frontend:
    networks:
      - frontend-network
  
  api:
    networks:
      - frontend-network
      - backend-network
      - database-network
  
  db:
    networks:
      - database-network
```

---

## 🐳 Container Security

### Image Scanning

**Scan images for vulnerabilities:**
```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Scan images
trivy image backup-api:latest
trivy image backup-frontend:latest
```

### Container Hardening

**Docker security options:**
```yaml
services:
  api:
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    read_only: true
    tmpfs:
      - /tmp
    user: "1000:1000"
```

---

## 📊 Security Checklist

### Pre-Production

- [ ] Change all default passwords
- [ ] Generate strong JWT secret key
- [ ] Generate encryption key for credentials
- [ ] Configure CORS for production origins
- [ ] Enable HTTPS/TLS
- [ ] Set up firewall rules
- [ ] Configure backup encryption
- [ ] Enable audit logging
- [ ] Set up security monitoring
- [ ] Implement rate limiting
- [ ] Add input validation
- [ ] Scan containers for vulnerabilities
- [ ] Review file permissions
- [ ] Test authentication flows
- [ ] Validate authorization rules

### Production Monitoring

- [ ] Monitor failed login attempts
- [ ] Track API rate limits
- [ ] Review audit logs daily
- [ ] Check for CVEs in dependencies
- [ ] Monitor backup file access
- [ ] Review SSH connection logs
- [ ] Check system resource usage
- [ ] Validate backup integrity
- [ ] Test disaster recovery
- [ ] Review security headers

---

## 🚨 Reporting Security Issues

If you discover a security vulnerability, please:

1. **DO NOT** open a public GitHub issue
2. Email security details to: **vichai.saisood@gmail.com**
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work on a fix.

---

## 📚 Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [FastAPI Security Guide](https://fastapi.tiangolo.com/tutorial/security/)
- [SQLAlchemy Security](https://docs.sqlalchemy.org/en/14/faq/security.html)

---

**Last Updated:** November 13, 2025  
**Version:** 1.0.0
