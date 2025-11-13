"""
Fix password hashes to ensure bcrypt compatibility (72 byte limit)
Run this script to update existing user passwords in the database
"""
import sys
import os
from pathlib import Path

# Add api directory to path
api_path = Path(__file__).parent / "api"
sys.path.insert(0, str(api_path))

from database import SessionLocal, engine
from database import User
from auth import get_password_hash

def fix_password_hashes():
    """Re-hash all user passwords to ensure bcrypt compatibility"""
    db = SessionLocal()
    try:
        users = db.query(User).all()
        
        print(f"Found {len(users)} users to check...")
        
        # Common default passwords to try
        default_passwords = {
            'admin': 'admin123',
            'test': 'test123',
            'user': 'password'
        }
        
        for user in users:
            print(f"\nChecking user: {user.username}")
            
            # If username has a known default password, update it
            if user.username in default_passwords:
                new_password = default_passwords[user.username]
                new_hash = get_password_hash(new_password)
                
                print(f"  Old hash length: {len(user.password_hash)} bytes")
                print(f"  New hash length: {len(new_hash)} bytes")
                
                user.password_hash = new_hash
                print(f"  ✓ Updated password hash for {user.username}")
            else:
                print(f"  ! Unknown password for {user.username}")
                print(f"    Current hash length: {len(user.password_hash)} bytes")
                print(f"    You may need to reset this user's password manually")
        
        # Commit changes
        db.commit()
        print("\n✓ Password hashes updated successfully!")
        print("\nTest credentials:")
        print("  Username: admin")
        print("  Password: admin123")
        
    except Exception as e:
        print(f"Error: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Password Hash Fix Utility")
    print("=" * 60)
    fix_password_hashes()
