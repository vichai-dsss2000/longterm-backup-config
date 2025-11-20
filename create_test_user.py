"""
Create test user for frontend testing

This script will locate the SQLite database file in the `api` folder
(`longterm_backup_config.db` or `longterm_backup_config.db.backup`), create
the `users` table if it does not exist (SQLite-friendly schema), and insert
a test admin user (username: admin, password: admin123).
"""
import sqlite3
from pathlib import Path
import sys
try:
    # Prefer using the application's hashing function so hashes are compatible
    from api.auth import get_password_hash
except Exception:
    # Fallback: use bcrypt directly if importing app auth fails
    import bcrypt
    def get_password_hash(password: str) -> str:
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def find_db_path() -> Path:
    repo_root = Path(__file__).parent
    api_dir = repo_root / 'api'
    candidates = [
        api_dir / 'longterm_backup_config.db',
        api_dir / 'longterm_backup_config.db.backup',
        api_dir / 'longterm_backup_config.sqlite3',
    ]
    for p in candidates:
        if p.exists():
            return p
    # default to creating the canonical .db path
    return api_dir / 'longterm_backup_config.db'


def create_users_table_if_missing(cursor: sqlite3.Cursor):
    # Create a simple users table compatible with the app's expected columns
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def create_test_user():
    db_path = find_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"Using database file: {db_path}")

    conn = sqlite3.connect(str(db_path))
    cursor = conn.cursor()

    create_users_table_if_missing(cursor)

    # Hash the password using the app's hashing function
    password = "admin123"
    hashed_password = get_password_hash(password)

    # Insert test user
    try:
        cursor.execute(
            """
            INSERT INTO users (username, email, password_hash, is_active, is_admin)
            VALUES (?, ?, ?, ?, ?)
            """,
            ("admin", "admin@example.com", hashed_password, 1, 1),
        )

        conn.commit()
        print("Test user created successfully!")
        print("Username: admin")
        print("Password: admin123")

    except sqlite3.IntegrityError:
        # If user exists, update their password to the known test password
        try:
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (hashed_password, 'admin')
            )
            conn.commit()
            print("Test user already existed — password updated to 'admin123'")
        except Exception:
            print("Test user already exists and could not be updated")

    finally:
        conn.close()


if __name__ == "__main__":
    try:
        create_test_user()
    except Exception as exc:
        print(f"Failed to create test user: {exc}")
        sys.exit(1)