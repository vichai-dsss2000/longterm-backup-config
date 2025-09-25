-- Long-term Backup Configuration Database Schema
-- MySQL Database Schema for Network Device Backup Management System

CREATE DATABASE IF NOT EXISTS longterm_backup_config;
USE longterm_backup_config;

-- Users table
CREATE TABLE users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- User profiles table
CREATE TABLE user_profiles (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    department VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Login sessions table for JWT token management
CREATE TABLE login_sessions (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Device types table (vendor, model, firmware combinations)
CREATE TABLE device_types (
    id INT PRIMARY KEY AUTO_INCREMENT,
    vendor VARCHAR(50) NOT NULL,
    model VARCHAR(100) NOT NULL,
    firmware_version VARCHAR(50),
    device_category VARCHAR(50), -- router, switch, firewall, etc.
    netmiko_device_type VARCHAR(50) NOT NULL, -- for netmiko connection
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_device_type (vendor, model, firmware_version)
);

-- Network inventory devices table
CREATE TABLE network_inventory_devices (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_name VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    device_type_id INT NOT NULL,
    hostname VARCHAR(100),
    location VARCHAR(200),
    management_ip VARCHAR(45),
    snmp_community VARCHAR(100),
    ssh_username VARCHAR(50),
    ssh_password_encrypted TEXT,
    ssh_key_file VARCHAR(255),
    ssh_port INT DEFAULT 22,
    enable_password_encrypted TEXT,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_backup_date TIMESTAMP NULL,
    last_backup_status ENUM('success', 'failed', 'pending', 'running') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_type_id) REFERENCES device_types(id),
    UNIQUE KEY unique_device (device_name, ip_address)
);

-- Backup command templates table
CREATE TABLE backup_command_templates (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_type_id INT NOT NULL,
    template_name VARCHAR(100) NOT NULL,
    template_description TEXT,
    backup_command TEXT NOT NULL, -- The actual backup command with variables
    command_format ENUM('TEXT', 'JSON', 'XML', 'YAML') DEFAULT 'TEXT',
    template_variables JSON, -- Store variable definitions and defaults
    timeout_seconds INT DEFAULT 300,
    retry_count INT DEFAULT 5,
    retry_interval_seconds INT DEFAULT 60,
    is_active BOOLEAN DEFAULT TRUE,
    version VARCHAR(20) DEFAULT '1.0',
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_type_id) REFERENCES device_types(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    UNIQUE KEY unique_template (device_type_id, template_name, version)
);

-- Job categories table
CREATE TABLE job_categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    category_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    color_code VARCHAR(7), -- HEX color for UI
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Job schedule policies table
CREATE TABLE job_schedule_policies (
    id INT PRIMARY KEY AUTO_INCREMENT,
    policy_name VARCHAR(100) NOT NULL,
    device_type_id INT,
    template_id INT NOT NULL,
    job_category_id INT,
    cron_expression VARCHAR(100) NOT NULL, -- Cron format for scheduling
    backup_path VARCHAR(500) NOT NULL, -- SFTP/FTP path for backup storage
    sftp_server_ip VARCHAR(45),
    sftp_username VARCHAR(50),
    sftp_password_encrypted TEXT,
    sftp_port INT DEFAULT 22,
    retention_days INT DEFAULT 30,
    compression_enabled BOOLEAN DEFAULT TRUE,
    encryption_enabled BOOLEAN DEFAULT FALSE,
    notification_enabled BOOLEAN DEFAULT TRUE,
    notification_emails JSON, -- Array of email addresses
    is_active BOOLEAN DEFAULT TRUE,
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_type_id) REFERENCES device_types(id),
    FOREIGN KEY (template_id) REFERENCES backup_command_templates(id),
    FOREIGN KEY (job_category_id) REFERENCES job_categories(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Device backup info table (tracks individual backup jobs)
CREATE TABLE device_backup_info (
    id INT PRIMARY KEY AUTO_INCREMENT,
    device_id INT NOT NULL,
    schedule_policy_id INT NOT NULL,
    job_status ENUM('pending', 'running', 'completed', 'failed', 'retrying') DEFAULT 'pending',
    backup_start_time TIMESTAMP NULL,
    backup_end_time TIMESTAMP NULL,
    backup_file_path VARCHAR(500),
    backup_file_size_mb DECIMAL(10,2),
    error_message TEXT,
    retry_count INT DEFAULT 0,
    next_retry_time TIMESTAMP NULL,
    execution_log JSON, -- Store detailed execution logs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (device_id) REFERENCES network_inventory_devices(id),
    FOREIGN KEY (schedule_policy_id) REFERENCES job_schedule_policies(id),
    INDEX idx_job_status (job_status),
    INDEX idx_backup_date (backup_start_time),
    INDEX idx_device_schedule (device_id, schedule_policy_id)
);

-- Backup file storage table
CREATE TABLE backup_file_storage (
    id INT PRIMARY KEY AUTO_INCREMENT,
    backup_info_id INT NOT NULL,
    storage_type ENUM('local', 'sftp', 'ftp', 's3', 'azure', 'gcp') DEFAULT 'sftp',
    file_path VARCHAR(500) NOT NULL,
    file_hash VARCHAR(64), -- SHA256 hash for integrity
    file_size_bytes BIGINT,
    compression_ratio DECIMAL(5,2),
    is_encrypted BOOLEAN DEFAULT FALSE,
    storage_status ENUM('uploading', 'stored', 'failed', 'deleted') DEFAULT 'stored',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (backup_info_id) REFERENCES device_backup_info(id) ON DELETE CASCADE
);

-- System configuration table
CREATE TABLE system_config (
    id INT PRIMARY KEY AUTO_INCREMENT,
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type ENUM('string', 'integer', 'boolean', 'json') DEFAULT 'string',
    description TEXT,
    is_encrypted BOOLEAN DEFAULT FALSE,
    updated_by INT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Audit log table
CREATE TABLE audit_logs (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT,
    action VARCHAR(100) NOT NULL, -- CREATE, UPDATE, DELETE, LOGIN, BACKUP, etc.
    table_name VARCHAR(50),
    record_id INT,
    old_values JSON,
    new_values JSON,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_action_date (action, created_at),
    INDEX idx_user_action (user_id, action)
);

-- Insert default data
INSERT INTO job_categories (category_name, description, color_code) VALUES
('Daily Backup', 'Daily configuration backups', '#28a745'),
('Weekly Backup', 'Weekly full configuration backups', '#17a2b8'),
('Monthly Backup', 'Monthly archive backups', '#ffc107'),
('Emergency Backup', 'On-demand emergency backups', '#dc3545');

INSERT INTO device_types (vendor, model, firmware_version, device_category, netmiko_device_type, description) VALUES
('Cisco', 'Catalyst 2960', 'IOS 15.x', 'switch', 'cisco_ios', 'Cisco Catalyst 2960 Switch'),
('Cisco', 'ASR 1000', 'IOS-XE 16.x', 'router', 'cisco_xe', 'Cisco ASR 1000 Series Router'),
('Juniper', 'EX4200', 'Junos 18.x', 'switch', 'juniper_junos', 'Juniper EX4200 Switch'),
('Juniper', 'MX Series', 'Junos 19.x', 'router', 'juniper_junos', 'Juniper MX Series Router'),
('MikroTik', 'RouterBoard', 'RouterOS 6.x', 'router', 'mikrotik_routeros', 'MikroTik RouterBoard');

INSERT INTO system_config (config_key, config_value, config_type, description) VALUES
('smtp_server', 'localhost', 'string', 'SMTP server for notifications'),
('smtp_port', '587', 'integer', 'SMTP server port'),
('backup_retention_days', '90', 'integer', 'Default backup retention period'),
('max_concurrent_backups', '10', 'integer', 'Maximum concurrent backup jobs'),
('encryption_key_rotation_days', '365', 'integer', 'Encryption key rotation period');

-- Create indexes for performance
CREATE INDEX idx_devices_active ON network_inventory_devices(is_active);
CREATE INDEX idx_devices_last_backup ON network_inventory_devices(last_backup_date);
CREATE INDEX idx_templates_active ON backup_command_templates(is_active);
CREATE INDEX idx_schedules_active ON job_schedule_policies(is_active);
CREATE INDEX idx_sessions_active ON login_sessions(is_active, expires_at);