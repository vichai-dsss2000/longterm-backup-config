"""
Initialize SQLite database with schema
"""
import sqlite3

def create_sqlite_schema():
    conn = sqlite3.connect('/workspaces/longterm-backup-config/api/longterm_backup_config.db')
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_active BOOLEAN DEFAULT TRUE,
            is_admin BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Create device_types table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor TEXT NOT NULL,
            model TEXT NOT NULL,
            firmware_version TEXT,
            device_category TEXT,
            netmiko_device_type TEXT NOT NULL,
            description TEXT,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Insert sample device types
    cursor.execute("""
        INSERT OR IGNORE INTO device_types 
        (vendor, model, firmware_version, device_category, netmiko_device_type, description)
        VALUES 
        ('Cisco', 'Catalyst 2960', 'IOS 15.x', 'switch', 'cisco_ios', 'Cisco Catalyst 2960 Switch'),
        ('Cisco', 'ASR 1000', 'IOS-XE 16.x', 'router', 'cisco_xe', 'Cisco ASR 1000 Series Router'),
        ('Juniper', 'EX4200', 'Junos 18.x', 'switch', 'juniper_junos', 'Juniper EX4200 Switch')
    """)
    
    conn.commit()
    conn.close()
    print("SQLite database schema created successfully!")

if __name__ == "__main__":
    create_sqlite_schema()