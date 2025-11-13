#!/usr/bin/env python3
"""
Seed Example Data for Long-term Backup Config System
Creates realistic example data for all tables
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from database import (
    User, UserProfile, DeviceType, NetworkDevice,
    BackupCommandTemplate, JobCategory, JobSchedulePolicy,
    DeviceBackupInfo, BackupFileStorage
)
from passlib.context import CryptContext
from datetime import datetime, timedelta
import json

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def seed_database():
    """Seed all tables with example data"""
    
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    
    try:
        print("🌱 Starting database seeding...")
        
        # 1. Seed Users
        print("\n👥 Seeding users...")
        users = [
            User(
                username="admin",
                email="admin@example.com",
                password_hash=hash_password("admin123"),
                is_active=True,
                is_admin=True
            ),
            User(
                username="operator1",
                email="operator1@example.com",
                password_hash=hash_password("operator123"),
                is_active=True,
                is_admin=False
            ),
            User(
                username="operator2",
                email="operator2@example.com",
                password_hash=hash_password("operator123"),
                is_active=True,
                is_admin=False
            ),
            User(
                username="viewer",
                email="viewer@example.com",
                password_hash=hash_password("viewer123"),
                is_active=True,
                is_admin=False
            ),
        ]
        
        # Check if users already exist
        existing_users = db.query(User).filter(User.username.in_([u.username for u in users])).all()
        if not existing_users:
            db.add_all(users)
            db.commit()
            print(f"   ✅ Created {len(users)} users")
        else:
            users = existing_users
            print(f"   ⚠️  Users already exist, using existing data")
        
        # Refresh to get IDs
        for user in users:
            db.refresh(user)
        
        # 2. Seed User Profiles
        print("\n👤 Seeding user profiles...")
        profiles = [
            UserProfile(
                user_id=users[0].id,
                first_name="System",
                last_name="Administrator",
                phone="+66-2-123-4567",
                department="IT Operations"
            ),
            UserProfile(
                user_id=users[1].id,
                first_name="John",
                last_name="Smith",
                phone="+66-2-234-5678",
                department="Network Operations"
            ),
            UserProfile(
                user_id=users[2].id,
                first_name="Jane",
                last_name="Doe",
                phone="+66-2-345-6789",
                department="Network Operations"
            ),
            UserProfile(
                user_id=users[3].id,
                first_name="Bob",
                last_name="Wilson",
                phone="+66-2-456-7890",
                department="Network Monitoring"
            ),
        ]
        
        existing_profiles = db.query(UserProfile).filter(UserProfile.user_id.in_([p.user_id for p in profiles])).all()
        if not existing_profiles:
            db.add_all(profiles)
            db.commit()
            print(f"   ✅ Created {len(profiles)} user profiles")
        else:
            print(f"   ⚠️  User profiles already exist")
        
        # 3. Seed Job Categories
        print("\n📂 Seeding job categories...")
        categories = [
            JobCategory(
                category_name="Daily Backup",
                description="Daily configuration backups",
                color_code="#28a745",
                is_active=True
            ),
            JobCategory(
                category_name="Weekly Backup",
                description="Weekly full configuration backups",
                color_code="#17a2b8",
                is_active=True
            ),
            JobCategory(
                category_name="Monthly Backup",
                description="Monthly archive backups",
                color_code="#ffc107",
                is_active=True
            ),
            JobCategory(
                category_name="Emergency Backup",
                description="On-demand emergency backups",
                color_code="#dc3545",
                is_active=True
            ),
        ]
        
        existing_categories = db.query(JobCategory).filter(JobCategory.category_name.in_([c.category_name for c in categories])).all()
        if not existing_categories:
            db.add_all(categories)
            db.commit()
            categories_list = categories
            print(f"   ✅ Created {len(categories)} job categories")
        else:
            categories_list = existing_categories
            print(f"   ⚠️  Job categories already exist")
        
        for cat in categories_list:
            db.refresh(cat)
        
        # 4. Seed Device Types
        print("\n🖥️  Seeding device types...")
        device_types = [
            DeviceType(
                vendor="Cisco",
                model="Catalyst 2960",
                firmware_version="IOS 15.x",
                device_category="switch",
                netmiko_device_type="cisco_ios",
                description="Cisco Catalyst 2960 Layer 2/3 Switch",
                is_active=True
            ),
            DeviceType(
                vendor="Cisco",
                model="ASR 1000",
                firmware_version="IOS-XE 16.x",
                device_category="router",
                netmiko_device_type="cisco_xe",
                description="Cisco ASR 1000 Series Router",
                is_active=True
            ),
            DeviceType(
                vendor="Cisco",
                model="ISR 4451",
                firmware_version="IOS-XE 17.x",
                device_category="router",
                netmiko_device_type="cisco_xe",
                description="Cisco ISR 4451 Integrated Services Router",
                is_active=True
            ),
            DeviceType(
                vendor="Juniper",
                model="EX4200",
                firmware_version="Junos 18.x",
                device_category="switch",
                netmiko_device_type="juniper_junos",
                description="Juniper EX4200 Ethernet Switch",
                is_active=True
            ),
            DeviceType(
                vendor="Juniper",
                model="MX Series",
                firmware_version="Junos 19.x",
                device_category="router",
                netmiko_device_type="juniper_junos",
                description="Juniper MX Series Universal Routing Platform",
                is_active=True
            ),
            DeviceType(
                vendor="MikroTik",
                model="RouterBoard RB4011",
                firmware_version="RouterOS 6.x",
                device_category="router",
                netmiko_device_type="mikrotik_routeros",
                description="MikroTik RouterBoard RB4011",
                is_active=True
            ),
            DeviceType(
                vendor="Huawei",
                model="S5700",
                firmware_version="VRP V200R019",
                device_category="switch",
                netmiko_device_type="huawei",
                description="Huawei S5700 Series Switch",
                is_active=True
            ),
        ]
        
        existing_types = db.query(DeviceType).all()
        if not existing_types:
            db.add_all(device_types)
            db.commit()
            device_types_list = device_types
            print(f"   ✅ Created {len(device_types)} device types")
        else:
            device_types_list = existing_types
            print(f"   ⚠️  Device types already exist")
        
        for dt in device_types_list:
            db.refresh(dt)
        
        # 5. Seed Backup Command Templates
        print("\n📝 Seeding backup command templates...")
        templates = [
            BackupCommandTemplate(
                device_type_id=device_types_list[0].id,  # Cisco Catalyst 2960
                template_name="Cisco IOS Running Config Backup",
                template_description="Backup running configuration from Cisco IOS devices",
                backup_command="copy running-config tftp://{tftp_server}/{device_name}_{timestamp}.cfg",
                command_format="TEXT",
                template_variables={
                    "tftp_server": {"type": "string", "required": True},
                    "device_name": {"type": "string", "required": True},
                    "timestamp": {"type": "datetime", "format": "%Y%m%d_%H%M%S"}
                },
                timeout_seconds=300,
                retry_count=3,
                retry_interval_seconds=60,
                is_active=True,
                version="1.0",
                created_by=users[0].id
            ),
            BackupCommandTemplate(
                device_type_id=device_types_list[1].id,  # Cisco ASR 1000
                template_name="Cisco ASR Full Configuration Backup",
                template_description="Complete configuration backup for Cisco ASR routers",
                backup_command="show running-config | redirect tftp://{tftp_server}/{device_name}_{timestamp}.cfg",
                command_format="TEXT",
                template_variables={
                    "tftp_server": {"type": "string", "required": True},
                    "device_name": {"type": "string", "required": True},
                    "timestamp": {"type": "datetime", "format": "%Y%m%d_%H%M%S"}
                },
                timeout_seconds=600,
                retry_count=5,
                retry_interval_seconds=120,
                is_active=True,
                version="1.0",
                created_by=users[0].id
            ),
            BackupCommandTemplate(
                device_type_id=device_types_list[3].id,  # Juniper EX4200
                template_name="Juniper Config Backup",
                template_description="Backup Juniper device configuration",
                backup_command="show configuration | display xml | save /var/tmp/{device_name}_{timestamp}.xml",
                command_format="XML",
                template_variables={
                    "device_name": {"type": "string", "required": True},
                    "timestamp": {"type": "datetime", "format": "%Y%m%d_%H%M%S"}
                },
                timeout_seconds=300,
                retry_count=3,
                retry_interval_seconds=60,
                is_active=True,
                version="1.0",
                created_by=users[0].id
            ),
            BackupCommandTemplate(
                device_type_id=device_types_list[5].id,  # MikroTik RB4011
                template_name="MikroTik Full Backup",
                template_description="Complete MikroTik RouterOS backup",
                backup_command="/export file={device_name}_{timestamp}",
                command_format="TEXT",
                template_variables={
                    "device_name": {"type": "string", "required": True},
                    "timestamp": {"type": "datetime", "format": "%Y%m%d_%H%M%S"}
                },
                timeout_seconds=180,
                retry_count=3,
                retry_interval_seconds=60,
                is_active=True,
                version="1.0",
                created_by=users[0].id
            ),
        ]
        
        existing_templates = db.query(BackupCommandTemplate).all()
        if not existing_templates:
            db.add_all(templates)
            db.commit()
            templates_list = templates
            print(f"   ✅ Created {len(templates)} backup templates")
        else:
            templates_list = existing_templates
            print(f"   ⚠️  Backup templates already exist")
        
        for tmpl in templates_list:
            db.refresh(tmpl)
        
        # 6. Seed Network Devices
        print("\n🌐 Seeding network devices...")
        devices = [
            NetworkDevice(
                device_name="BKK-CORE-SW01",
                ip_address="10.10.1.1",
                device_type_id=device_types_list[0].id,
                hostname="bkk-core-sw01.example.com",
                location="Bangkok Data Center - Rack A1",
                management_ip="10.10.1.1",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="Core Switch - Bangkok Primary DC",
                is_active=True,
                last_backup_status="success"
            ),
            NetworkDevice(
                device_name="BKK-CORE-SW02",
                ip_address="10.10.1.2",
                device_type_id=device_types_list[0].id,
                hostname="bkk-core-sw02.example.com",
                location="Bangkok Data Center - Rack A2",
                management_ip="10.10.1.2",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="Core Switch - Bangkok Secondary DC",
                is_active=True,
                last_backup_status="success"
            ),
            NetworkDevice(
                device_name="BKK-EDGE-RTR01",
                ip_address="10.10.2.1",
                device_type_id=device_types_list[1].id,
                hostname="bkk-edge-rtr01.example.com",
                location="Bangkok Data Center - Network Room",
                management_ip="10.10.2.1",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="Edge Router - Internet Gateway",
                is_active=True,
                last_backup_status="success"
            ),
            NetworkDevice(
                device_name="CNX-BRANCH-SW01",
                ip_address="10.20.1.1",
                device_type_id=device_types_list[3].id,
                hostname="cnx-branch-sw01.example.com",
                location="Chiang Mai Branch Office",
                management_ip="10.20.1.1",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="Branch Office Switch - Chiang Mai",
                is_active=True,
                last_backup_status="pending"
            ),
            NetworkDevice(
                device_name="HKT-BRANCH-RTR01",
                ip_address="10.30.1.1",
                device_type_id=device_types_list[5].id,
                hostname="hkt-branch-rtr01.example.com",
                location="Phuket Branch Office",
                management_ip="10.30.1.1",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="Branch Router - Phuket Office",
                is_active=True,
                last_backup_status="failed"
            ),
            NetworkDevice(
                device_name="BKK-DMZ-SW01",
                ip_address="172.16.1.1",
                device_type_id=device_types_list[6].id,
                hostname="bkk-dmz-sw01.example.com",
                location="Bangkok Data Center - DMZ Zone",
                management_ip="172.16.1.1",
                ssh_username="admin",
                ssh_password_encrypted="encrypted_password_here",
                ssh_port=22,
                description="DMZ Zone Switch",
                is_active=True,
                last_backup_status="running"
            ),
        ]
        
        existing_devices = db.query(NetworkDevice).all()
        if not existing_devices:
            db.add_all(devices)
            db.commit()
            devices_list = devices
            print(f"   ✅ Created {len(devices)} network devices")
        else:
            devices_list = existing_devices
            print(f"   ⚠️  Network devices already exist")
        
        for dev in devices_list:
            db.refresh(dev)
        
        # 7. Seed Job Schedule Policies
        print("\n⏰ Seeding job schedule policies...")
        schedules = [
            JobSchedulePolicy(
                policy_name="Daily Backup - Core Switches",
                device_type_id=device_types_list[0].id,
                template_id=templates_list[0].id,
                job_category_id=categories_list[0].id,
                cron_expression="0 2 * * *",  # Daily at 2 AM
                backup_path="/backups/daily/switches",
                sftp_server_ip="10.10.100.10",
                sftp_username="backup_user",
                sftp_password_encrypted="encrypted_sftp_password",
                sftp_port=22,
                retention_days=30,
                compression_enabled=True,
                encryption_enabled=False,
                notification_enabled=True,
                notification_emails=["netops@example.com"],
                is_active=True,
                created_by=users[0].id
            ),
            JobSchedulePolicy(
                policy_name="Daily Backup - Edge Routers",
                device_type_id=device_types_list[1].id,
                template_id=templates_list[1].id,
                job_category_id=categories_list[0].id,
                cron_expression="0 3 * * *",  # Daily at 3 AM
                backup_path="/backups/daily/routers",
                sftp_server_ip="10.10.100.10",
                sftp_username="backup_user",
                sftp_password_encrypted="encrypted_sftp_password",
                sftp_port=22,
                retention_days=30,
                compression_enabled=True,
                encryption_enabled=True,
                notification_enabled=True,
                notification_emails=["netops@example.com"],
                is_active=True,
                created_by=users[0].id
            ),
            JobSchedulePolicy(
                policy_name="Weekly Backup - All Juniper Devices",
                device_type_id=device_types_list[3].id,
                template_id=templates_list[2].id,
                job_category_id=categories_list[1].id,
                cron_expression="0 1 * * 0",  # Weekly on Sunday at 1 AM
                backup_path="/backups/weekly/juniper",
                sftp_server_ip="10.10.100.10",
                sftp_username="backup_user",
                sftp_password_encrypted="encrypted_sftp_password",
                sftp_port=22,
                retention_days=90,
                compression_enabled=True,
                encryption_enabled=True,
                notification_enabled=True,
                notification_emails=["netops@example.com", "admin@example.com"],
                is_active=True,
                created_by=users[0].id
            ),
            JobSchedulePolicy(
                policy_name="Monthly Archive - MikroTik Devices",
                device_type_id=device_types_list[5].id,
                template_id=templates_list[3].id,
                job_category_id=categories_list[2].id,
                cron_expression="0 0 1 * *",  # Monthly on 1st at midnight
                backup_path="/backups/monthly/mikrotik",
                sftp_server_ip="10.10.100.10",
                sftp_username="backup_user",
                sftp_password_encrypted="encrypted_sftp_password",
                sftp_port=22,
                retention_days=365,
                compression_enabled=True,
                encryption_enabled=True,
                notification_enabled=True,
                notification_emails=["netops@example.com", "admin@example.com"],
                is_active=True,
                created_by=users[0].id
            ),
        ]
        
        existing_schedules = db.query(JobSchedulePolicy).all()
        if not existing_schedules:
            db.add_all(schedules)
            db.commit()
            schedules_list = schedules
            print(f"   ✅ Created {len(schedules)} job schedules")
        else:
            schedules_list = existing_schedules
            print(f"   ⚠️  Job schedules already exist")
        
        for sched in schedules_list:
            db.refresh(sched)
        
        # 8. Seed Device Backup Info (Job History)
        print("\n📊 Seeding backup job history...")
        now = datetime.now()
        
        # Update devices last backup date for completed jobs
        devices_list[0].last_backup_date = now - timedelta(hours=2)
        devices_list[1].last_backup_date = now - timedelta(hours=2)
        db.commit()
        
        backup_jobs = [
            # Successful backup
            DeviceBackupInfo(
                device_id=devices_list[0].id,
                schedule_policy_id=schedules_list[0].id,
                job_status="completed",
                backup_start_time=now - timedelta(hours=2),
                backup_end_time=now - timedelta(hours=2, minutes=-5),
                backup_file_path="/backups/daily/switches/BKK-CORE-SW01_20250113.cfg",
                backup_file_size_mb=2.3,
                retry_count=0,
                execution_log=json.dumps({"status": "success", "commands_executed": 5})
            ),
            # Another successful backup
            DeviceBackupInfo(
                device_id=devices_list[1].id,
                schedule_policy_id=schedules_list[0].id,
                job_status="completed",
                backup_start_time=now - timedelta(hours=2),
                backup_end_time=now - timedelta(hours=2, minutes=-6),
                backup_file_path="/backups/daily/switches/BKK-CORE-SW02_20250113.cfg",
                backup_file_size_mb=2.5,
                retry_count=0,
                execution_log=json.dumps({"status": "success", "commands_executed": 5})
            ),
            # Running backup
            DeviceBackupInfo(
                device_id=devices_list[2].id,
                schedule_policy_id=schedules_list[1].id,
                job_status="running",
                backup_start_time=now - timedelta(minutes=5),
                retry_count=0,
                execution_log=json.dumps({"status": "in_progress", "current_step": "connecting"})
            ),
            # Failed backup
            DeviceBackupInfo(
                device_id=devices_list[4].id,
                schedule_policy_id=schedules_list[3].id,
                job_status="failed",
                backup_start_time=now - timedelta(hours=1),
                backup_end_time=now - timedelta(hours=1, minutes=-2),
                error_message="SSH connection timeout - device unreachable",
                retry_count=3,
                next_retry_time=now + timedelta(minutes=30),
                execution_log=json.dumps({"status": "failed", "error": "Connection timeout", "retries": 3})
            ),
            # Pending backup
            DeviceBackupInfo(
                device_id=devices_list[3].id,
                schedule_policy_id=schedules_list[2].id,
                job_status="pending",
                retry_count=0
            ),
            # Old successful backup (for history)
            DeviceBackupInfo(
                device_id=devices_list[0].id,
                schedule_policy_id=schedules_list[0].id,
                job_status="completed",
                backup_start_time=now - timedelta(days=1, hours=2),
                backup_end_time=now - timedelta(days=1, hours=2, minutes=-5),
                backup_file_path="/backups/daily/switches/BKK-CORE-SW01_20250112.cfg",
                backup_file_size_mb=2.3,
                retry_count=0,
                execution_log=json.dumps({"status": "success", "commands_executed": 5})
            ),
        ]
        
        existing_jobs = db.query(DeviceBackupInfo).all()
        if not existing_jobs:
            db.add_all(backup_jobs)
            db.commit()
            backup_jobs_list = backup_jobs
            print(f"   ✅ Created {len(backup_jobs)} backup job records")
        else:
            backup_jobs_list = existing_jobs
            print(f"   ⚠️  Backup jobs already exist")
        
        for job in backup_jobs_list:
            db.refresh(job)
        
        # 9. Seed Backup File Storage
        print("\n💾 Seeding backup file storage records...")
        storage_records = [
            BackupFileStorage(
                backup_info_id=backup_jobs_list[0].id,
                storage_type="sftp",
                file_path="/backups/daily/switches/BKK-CORE-SW01_20250113.cfg",
                file_hash="a3b2c1d4e5f6789012345678901234567890123456789012345678901234abcd",
                file_size_bytes=2411520,  # ~2.3 MB
                compression_ratio=0.35,
                is_encrypted=False,
                storage_status="stored"
            ),
            BackupFileStorage(
                backup_info_id=backup_jobs_list[1].id,
                storage_type="sftp",
                file_path="/backups/daily/switches/BKK-CORE-SW02_20250113.cfg",
                file_hash="b4c3d2e1f0a9876543210987654321098765432109876543210987654321bcde",
                file_size_bytes=2621440,  # ~2.5 MB
                compression_ratio=0.38,
                is_encrypted=False,
                storage_status="stored"
            ),
            BackupFileStorage(
                backup_info_id=backup_jobs_list[5].id,
                storage_type="sftp",
                file_path="/backups/daily/switches/BKK-CORE-SW01_20250112.cfg",
                file_hash="c5d4e3f2a1b0987654321098765432109876543210987654321098765432cdef",
                file_size_bytes=2411520,
                compression_ratio=0.35,
                is_encrypted=False,
                storage_status="stored"
            ),
        ]
        
        existing_storage = db.query(BackupFileStorage).all()
        if not existing_storage:
            db.add_all(storage_records)
            db.commit()
            print(f"   ✅ Created {len(storage_records)} storage records")
        else:
            print(f"   ⚠️  Storage records already exist")
        
        print("\n✅ Database seeding completed successfully!")
        print("\n" + "="*60)
        print("📊 Summary:")
        print("="*60)
        print(f"👥 Users: {len(users)}")
        print(f"👤 User Profiles: {len(profiles)}")
        print(f"📂 Job Categories: {len(categories_list)}")
        print(f"🖥️  Device Types: {len(device_types_list)}")
        print(f"📝 Backup Templates: {len(templates_list)}")
        print(f"🌐 Network Devices: {len(devices_list)}")
        print(f"⏰ Schedule Policies: {len(schedules_list)}")
        print(f"📊 Backup Jobs: {len(backup_jobs_list)}")
        print(f"💾 Storage Records: {len(storage_records)}")
        print("="*60)
        print("\n🔑 Test User Credentials:")
        print("   Username: admin      Password: admin123     (Admin)")
        print("   Username: operator1  Password: operator123  (Operator)")
        print("   Username: operator2  Password: operator123  (Operator)")
        print("   Username: viewer     Password: viewer123    (Viewer)")
        print("="*60)
        
    except Exception as e:
        db.rollback()
        print(f"\n❌ Error seeding database: {str(e)}")
        import traceback
        traceback.print_exc()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
