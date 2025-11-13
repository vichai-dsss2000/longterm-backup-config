"""
Create test scheduler job data for frontend testing
"""
import sqlite3
from datetime import datetime

def create_test_schedule_data():
    # Connect to SQLite database
    conn = sqlite3.connect('/workspaces/longterm-backup-config/api/longterm_backup_config.db')
    cursor = conn.cursor()
    
    # Create test job category if not exists
    try:
        cursor.execute("""
            INSERT INTO job_categories (category_name, description, is_active)
            VALUES (?, ?, ?)
        """, ("test_backup", "Test backup category", True))
        
        category_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        # Category already exists, get its ID
        cursor.execute("SELECT category_id FROM job_categories WHERE category_name = 'test_backup'")
        result = cursor.fetchone()
        category_id = result[0] if result else 1
    
    # Create test device type if not exists
    try:
        cursor.execute("""
            INSERT INTO device_types (vendor, model, firmware_version, device_category, netmiko_device_type, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("Cisco", "Catalyst", "15.2", "switch", "cisco_ios", "Test Cisco device type"))
        
        device_type_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        # Device type already exists, get its ID
        cursor.execute("SELECT id FROM device_types WHERE vendor = 'Cisco' AND model = 'Catalyst'")
        result = cursor.fetchone()
        device_type_id = result[0] if result else 1
    
    # Create test backup template if not exists
    try:
        cursor.execute("""
            INSERT INTO backup_command_templates (
                device_type_id, template_name, template_description, backup_command,
                command_format, timeout_seconds, retry_count, retry_interval_seconds, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_type_id, "Cisco IOS Backup", "Standard Cisco IOS configuration backup",
            "copy running-config tftp://{backup_server}/{device_name}_{timestamp}.cfg",
            "TEXT", 300, 3, 60, True
        ))
        
        template_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        # Template already exists, get its ID
        cursor.execute("SELECT id FROM backup_command_templates WHERE template_name = 'Cisco IOS Backup'")
        result = cursor.fetchone()
        template_id = result[0] if result else 1
    
    # Create test schedule policies
    test_schedules = [
        {
            'policy_name': 'Daily Network Backup',
            'device_type_id': device_type_id,
            'template_id': template_id,
            'job_category_id': category_id,
            'cron_expression': '0 2 * * *',
            'backup_path': '/backups/daily/',
            'sftp_server_ip': '192.168.1.100',
            'sftp_username': 'backup_user',
            'sftp_port': 22,
            'retention_days': 30,
            'compression_enabled': True,
            'encryption_enabled': False,
            'notification_enabled': True,
            'is_active': True
        },
        {
            'policy_name': 'Weekly Config Archive', 
            'device_type_id': device_type_id,
            'template_id': template_id,
            'job_category_id': category_id,
            'cron_expression': '0 3 * * 0',
            'backup_path': '/backups/weekly/',
            'sftp_server_ip': '192.168.1.100',
            'sftp_username': 'backup_user',
            'sftp_port': 22,
            'retention_days': 90,
            'compression_enabled': True,
            'encryption_enabled': True,
            'notification_enabled': True,
            'is_active': True
        },
        {
            'policy_name': 'Hourly Core Switch Backup',
            'device_type_id': device_type_id,
            'template_id': template_id,
            'job_category_id': category_id,
            'cron_expression': '0 * * * *',
            'backup_path': '/backups/hourly/',
            'sftp_server_ip': '192.168.1.100',
            'sftp_username': 'backup_user',
            'sftp_port': 22,
            'retention_days': 7,
            'compression_enabled': False,
            'encryption_enabled': False,
            'notification_enabled': False,
            'is_active': False
        }
    ]
    
    created_count = 0
    for schedule in test_schedules:
        try:
            cursor.execute("""
                INSERT INTO job_schedule_policies (
                    policy_name, device_type_id, template_id, job_category_id,
                    cron_expression, backup_path, sftp_server_ip, sftp_username,
                    sftp_port, retention_days, compression_enabled, encryption_enabled,
                    notification_enabled, is_active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                schedule['policy_name'], schedule['device_type_id'],
                schedule['template_id'], schedule['job_category_id'],
                schedule['cron_expression'], schedule['backup_path'],
                schedule['sftp_server_ip'], schedule['sftp_username'],
                schedule['sftp_port'], schedule['retention_days'],
                schedule['compression_enabled'], schedule['encryption_enabled'],
                schedule['notification_enabled'], schedule['is_active'],
                datetime.now(), datetime.now()
            ))
            created_count += 1
        except sqlite3.IntegrityError as e:
            print(f"Schedule '{schedule['policy_name']}' already exists: {e}")
    
    conn.commit()
    conn.close()
    
    print(f"Created {created_count} test schedule policies")
    print("Test data created successfully!")

if __name__ == "__main__":
    create_test_schedule_data()