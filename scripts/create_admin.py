"""
Create an admin user using SQLAlchemy session. Intended to be run inside the `api` container.
"""
from database import SessionLocal, User
from auth import get_password_hash
import os

def create_admin():
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == 'admin').first():
            print('Admin user already exists')
            return
        pwd = os.getenv('INITIAL_ADMIN_PASSWORD', 'AdminPass123!')[:72]
        user = User(username='admin', email='admin@example.com', password_hash=get_password_hash(pwd), is_active=True, is_admin=True)
        db.add(user)
        db.commit()
        print('Created admin user: admin')
        print('Password:', pwd)
    except Exception as e:
        print('Failed to create admin user:', e)
    finally:
        db.close()

if __name__ == '__main__':
    create_admin()
