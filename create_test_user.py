"""
Create test user for frontend testing
"""
import sqlite3
import bcrypt

def create_test_user():
    # Connect to SQLite database
    conn = sqlite3.connect('/workspaces/longterm-backup-config/api/longterm_backup_config.db')
    cursor = conn.cursor()
    
    # Hash the password using bcrypt
    password = "admin123"
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    # Insert test user
    try:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, is_active, is_admin)
            VALUES (?, ?, ?, ?, ?)
        """, ("admin", "admin@example.com", hashed_password, True, True))
        
        conn.commit()
        print("Test user created successfully!")
        print("Username: admin")
        print("Password: admin123")
        
    except sqlite3.IntegrityError:
        print("Test user already exists")
    
    finally:
        conn.close()

if __name__ == "__main__":
    create_test_user()