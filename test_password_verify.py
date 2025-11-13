"""
Test password verification directly
"""
import sys
import os
from pathlib import Path

# Add api directory to path
api_path = Path(__file__).parent / "api"
sys.path.insert(0, str(api_path))

from database import SessionLocal
from database import User
from auth import verify_password, get_password_hash

def test_password():
    """Test password verification"""
    db = SessionLocal()
    try:
        # Get admin user
        user = db.query(User).filter(User.username == 'admin').first()
        
        if not user:
            print("❌ Admin user not found!")
            return
        
        print(f"✓ Found user: {user.username}")
        print(f"  Email: {user.email}")
        print(f"  Password hash length: {len(user.password_hash)} bytes")
        print(f"  Hash preview: {user.password_hash[:20]}...")
        
        # Test with correct password
        test_password = "admin123"
        print(f"\nTesting password: {test_password}")
        print(f"  Password length: {len(test_password)} chars / {len(test_password.encode('utf-8'))} bytes")
        
        result = verify_password(test_password, user.password_hash)
        
        if result:
            print("✓ Password verification SUCCESSFUL!")
        else:
            print("❌ Password verification FAILED!")
            
            # Try to create new hash and compare
            print("\nCreating new hash for comparison...")
            new_hash = get_password_hash(test_password)
            print(f"  New hash length: {len(new_hash)} bytes")
            print(f"  New hash preview: {new_hash[:20]}...")
            
            # Update user with new hash
            print("\nUpdating user with new hash...")
            user.password_hash = new_hash
            db.commit()
            print("✓ Password hash updated!")
            
            # Test again
            print("\nTesting with new hash...")
            result = verify_password(test_password, user.password_hash)
            if result:
                print("✓ Password verification SUCCESSFUL after update!")
            else:
                print("❌ Still failed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("Password Verification Test")
    print("=" * 60)
    test_password()
