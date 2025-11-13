"""
Reset admin user with correct password
"""
import sys
from pathlib import Path

# Add api directory to path
api_path = Path(__file__).parent / "api"
sys.path.insert(0, str(api_path))

from database import SessionLocal, User
from auth import get_password_hash
from datetime import datetime

def reset_admin_user():
    """Delete and recreate admin user"""
    db = SessionLocal()
    try:
        # Delete existing admin user
        existing_user = db.query(User).filter(User.username == 'admin').first()
        if existing_user:
            db.delete(existing_user)
            db.commit()
            print("✓ Deleted existing admin user")
        
        # Create new admin user with correct password
        password = "admin123"
        password_hash = get_password_hash(password)
        
        new_user = User(
            username="admin",
            email="admin@example.com",
            password_hash=password_hash,
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        
        print("=" * 60)
        print("✓ Admin user created successfully!")
        print("=" * 60)
        print(f"  ID: {new_user.id}")
        print(f"  Username: {new_user.username}")
        print(f"  Email: {new_user.email}")
        print(f"  Password: {password}")
        print(f"  Is Admin: {new_user.is_admin}")
        print(f"  Is Active: {new_user.is_active}")
        print(f"  Hash length: {len(new_user.password_hash)} bytes")
        print("=" * 60)
        
        # Test password verification
        from auth import verify_password
        result = verify_password(password, new_user.password_hash)
        print(f"\n✓ Password verification test: {'PASSED' if result else 'FAILED'}")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    reset_admin_user()
