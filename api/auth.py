from datetime import datetime, timedelta
from typing import Optional
import re
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from cryptography.fernet import Fernet
import base64
import os

from database import get_db, User, LoginSession
from config import settings

# Password hashing
pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=12,
    bcrypt__ident="2b"
)

# JWT token security
security = HTTPBearer()

# Credential Encryption
class CredentialEncryption:
    """Encrypt/decrypt sensitive credentials using Fernet symmetric encryption"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        key = encryption_key or os.getenv('ENCRYPTION_KEY')
        if not key:
            # Generate a key if not provided (development only)
            key = Fernet.generate_key().decode()
            print(f"WARNING: Generated new encryption key. Set ENCRYPTION_KEY in .env: {key}")
        
        try:
            self.cipher_suite = Fernet(key.encode() if isinstance(key, str) else key)
        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string"""
        if not plaintext:
            return ""
        return self.cipher_suite.encrypt(plaintext.encode()).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt ciphertext string"""
        if not ciphertext:
            return ""
        try:
            return self.cipher_suite.decrypt(ciphertext.encode()).decode()
        except Exception:
            raise ValueError("Failed to decrypt credential")

# Password Policy
class PasswordPolicy:
    """Enforce strong password requirements"""
    
    MIN_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGIT = True
    REQUIRE_SPECIAL = True
    
    @classmethod
    def validate(cls, password: str) -> tuple[bool, list[str]]:
        """Validate password against policy"""
        errors = []
        
        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Password must be at least {cls.MIN_LENGTH} characters")
        
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if cls.REQUIRE_DIGIT and not re.search(r'\d', password):
            errors.append("Password must contain at least one digit")
        
        if cls.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        # Truncate password to 72 bytes for bcrypt compatibility
        password_bytes = plain_password.encode('utf-8')[:72]
        try:
            # Try passlib verification first
            return pwd_context.verify(password_bytes, hashed_password)
        except Exception:
            # Fallback to bcrypt module if passlib fails to identify hash
            try:
                import bcrypt as _bcrypt
                return _bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))
            except Exception:
                return False
    except Exception as e:
        print(f"Password verification error: {e}")
        return False

def get_password_hash(password: str) -> str:
    """Generate password hash."""
    # Truncate password to 72 bytes for bcrypt compatibility
    password_bytes = password.encode('utf-8')[:72]
    try:
        # Prefer passlib's context hashing
        return pwd_context.hash(password_bytes)
    except Exception:
        # Fallback to bcrypt module directly
        import bcrypt as _bcrypt
        return _bcrypt.hashpw(password_bytes, _bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt, expire

def verify_token(token: str) -> dict:
    """Verify JWT token and return payload."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def authenticate_user(db: Session, username: str, password: str):
    """Authenticate user with username and password."""
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False
    return user

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """Get current authenticated user from JWT token."""
    token = credentials.credentials
    payload = verify_token(token)
    username = payload.get("sub")
    
    # For now, just validate the JWT token without session tracking
    # Session tracking can be improved later with proper token storage
    user = db.query(User).filter(User.username == username, User.is_active == True).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

def get_admin_user(current_user: User = Depends(get_current_user)):
    """Ensure current user is admin."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

def create_user_session(db: Session, user: User, token: str, ip_address: str = None, user_agent: str = None):
    """Create a new user session."""
    # Store token directly for development (in production, use proper session management)
    expires_at = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    
    session = LoginSession(
        user_id=user.id,
        token_hash=token[:50],  # Store part of token for reference
        expires_at=expires_at,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    db.add(session)
    db.commit()
    return session

def invalidate_user_session(db: Session, token: str):
    """Invalidate a user session."""
    token_hash = get_password_hash(token)
    session = db.query(LoginSession).filter(
        LoginSession.token_hash == token_hash,
        LoginSession.is_active == True
    ).first()
    
    if session:
        session.is_active = False
        db.commit()
    return session