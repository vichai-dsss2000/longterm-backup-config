"""
Authentication Router
===================

Handles user authentication, login, logout, and token management.
Integrates with the auth.py module for JWT token handling.
"""

from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from database import get_db, User, UserProfile, LoginSession
from schemas import UserLogin, Token, UserCreate, UserResponse, MessageResponse
from auth import (
    authenticate_user, create_access_token, get_current_user, 
    get_password_hash, create_user_session, invalidate_user_session
)
from config import settings

router = APIRouter()
security = HTTPBearer()


@router.post("/login", response_model=Token)
async def login(
    user_credentials: UserLogin,
    request: Request,
    db: Session = Depends(get_db)
):
    """Authenticate user and return JWT token."""
    user = authenticate_user(db, user_credentials.username, user_credentials.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create access token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token, expires_at = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    # Create user session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    create_user_session(db, user, access_token, ip_address, user_agent)
    
    # Get user profile
    profile_data = None
    if user.profile:
        profile_data = {
            "first_name": user.profile.first_name,
            "last_name": user.profile.last_name,
            "phone": user.profile.phone,
            "department": user.profile.department
        }
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_at=expires_at,
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "is_admin": user.is_admin,
            "profile": profile_data
        }
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout user and invalidate token."""
    # Extract token from Authorization header
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        invalidate_user_session(db, token)
    
    return MessageResponse(message="Successfully logged out")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    profile_data = None
    if current_user.profile:
        profile_data = {
            "first_name": current_user.profile.first_name,
            "last_name": current_user.profile.last_name,
            "phone": current_user.profile.phone,
            "department": current_user.profile.department
        }
    
    return UserResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        is_active=current_user.is_active,
        is_admin=current_user.is_admin,
        created_at=current_user.created_at,
        profile=profile_data
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Refresh JWT token for current user."""
    # Invalidate current token
    auth_header = request.headers.get("authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        invalidate_user_session(db, token)
    
    # Create new token
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token, expires_at = create_access_token(
        data={"sub": current_user.username}, expires_delta=access_token_expires
    )
    
    # Create new session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    create_user_session(db, current_user, access_token, ip_address, user_agent)
    
    # Get user profile
    profile_data = None
    if current_user.profile:
        profile_data = {
            "first_name": current_user.profile.first_name,
            "last_name": current_user.profile.last_name,
            "phone": current_user.profile.phone,
            "department": current_user.profile.department
        }
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_at=expires_at,
        user={
            "id": current_user.id,
            "username": current_user.username,
            "email": current_user.email,
            "is_admin": current_user.is_admin,
            "profile": profile_data
        }
    )


@router.post("/register", response_model=UserResponse)
async def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Register a new user (admin only)."""
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can create new users"
        )
    
    # Check if username already exists
    existing_user = db.query(User).filter(User.username == user_data.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already exists"
        )
    
    # Check if email already exists
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already exists"
        )
    
    # Create new user
    password_hash = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=password_hash,
        is_admin=user_data.is_admin
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Create user profile if profile data provided
    if any([user_data.first_name, user_data.last_name, user_data.phone, user_data.department]):
        profile = UserProfile(
            user_id=new_user.id,
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            phone=user_data.phone,
            department=user_data.department
        )
        db.add(profile)
        db.commit()
        db.refresh(new_user)
    
    return UserResponse(
        id=new_user.id,
        username=new_user.username,
        email=new_user.email,
        is_active=new_user.is_active,
        is_admin=new_user.is_admin,
        created_at=new_user.created_at,
        profile={
            "first_name": new_user.profile.first_name if new_user.profile else None,
            "last_name": new_user.profile.last_name if new_user.profile else None,
            "phone": new_user.profile.phone if new_user.profile else None,
            "department": new_user.profile.department if new_user.profile else None
        } if hasattr(new_user, 'profile') and new_user.profile else None
    )


@router.get("/sessions")
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get active sessions for current user."""
    sessions = db.query(LoginSession).filter(
        LoginSession.user_id == current_user.id,
        LoginSession.is_active == True,
        LoginSession.expires_at > datetime.utcnow()
    ).all()
    
    return {
        "active_sessions": len(sessions),
        "sessions": [
            {
                "id": session.id,
                "ip_address": session.ip_address,
                "user_agent": session.user_agent,
                "created_at": session.created_at,
                "expires_at": session.expires_at
            }
            for session in sessions
        ]
    }