# AI Coding Agent Instructions

## Project Overview
This repository contains `longterm-backup-config` - a comprehensive network device backup management system with web-based administration, automated scheduling, and multi-vendor device support.

## Architecture Overview
**3-Tier Network Backup Solution:**
- **Frontend**: React.js admin dashboard with Bootstrap CSS templates
- **API Layer**: FastAPI Python service with JWT authentication  
- **Database**: MySQL with structured schema for devices, templates, and jobs
- **Automation**: Python SSH scripts using Netmiko for multi-vendor device backup

## Technology Stack

### Frontend (`/frontend` or `/web`)
- **React.js** with Bootstrap CSS admin templates
- **SweetAlert** dialogs for user interactions
- **JWT token authentication** for API communication
- CRUD operations via REST API endpoints

### Backend API (`/api` or `/backend`) 
- **FastAPI Python** framework
- **JWT Authentication** middleware
- **MySQL** database integration
- **Background job scheduling** for backup execution
- **SSH automation** with Netmiko/Paramiko

### Database Schema (`/database` or `/sql`)
Key MySQL tables:
```sql
- users, user_profiles, login_sessions
- network_inventory_devices, device_types  
- backup_command_templates, job_schedule_policies
- job_categories, device_backup_info
```

### Automation Scripts (`/scripts`)
- **Python SSH scripts** for device connections
- **Netmiko integration** for multi-vendor support
- **Template-based commands** for different device types/firmwares
- **Configuration parsing** (XML, YAML, JSON, TEXT formats)

## Directory Structure
```
├── frontend/              # React.js admin dashboard
├── api/                   # FastAPI backend service
├── database/              # MySQL schema and migrations
├── scripts/               # Python automation scripts
├── templates/             # Device command templates
│   ├── cisco/             # Vendor-specific templates
│   ├── juniper/
│   └── mikrotik/
├── configs/               # System configuration files
└── docs/                  # API documentation and runbooks
```

## Development Workflows

### Local Development Setup
1. **Database**: Set up MySQL with schema from `/database/schema.sql`
2. **Backend**: `pip install -r api/requirements.txt` → `uvicorn main:app --reload`
3. **Frontend**: `npm install` → `npm start` in `/frontend`
4. **SSH Testing**: Use `/scripts/test_connection.py` for device connectivity

### Template Management
- **Command Templates**: Store in `/templates/{vendor}/{model}/` and `backup_command_templates` table
- **Format Support**: XML, YAML, JSON, TEXT configuration parsing
- **Variable Substitution**: Use `{device_ip}`, `{username}` in templates
- **Version Control**: Tag template versions for rollback capability
- **Multi-Template Architecture**: Each device type (vendor/model/firmware) supports multiple backup templates and job schedules

#### Example Cisco Backup Template
```bash
# Cisco switch backup command pattern:
copy running-config sftp://{username}:{password}@{sftp_server_ip}/{backup_path}/{device_name}_{timestamp}.cfg
```
Template variables: `{username}`, `{password}`, `{sftp_server_ip}`, `{backup_path}`, `{device_name}`, `{timestamp}`

## Key Conventions

### API Patterns
- **JWT Authentication**: All endpoints except `/auth/login` require valid JWT
- **CRUD Operations**: Follow FastAPI/SQLAlchemy patterns
- **Job Scheduling**: Use background tasks for device backup execution
- **Error Handling**: Return structured JSON error responses

### Database Patterns  
- **Foreign Key Relationships**: Link devices → device_types → templates
- **Template Storage**: `backup_command_templates` table stores vendor-specific commands
- **Multi-Template Support**: Each vendor/model/firmware can have multiple templates and schedules
- **Device Hierarchy**: `device_types` → `backup_command_templates` (one-to-many relationship)
- **Audit Trails**: Track backup job status and timestamps
- **Soft Deletes**: Use `is_active` flags instead of hard deletes

### SSH Automation
- **Netmiko Integration**: Use device_type mapping for vendor-specific handling
- **Connection Pooling**: Reuse SSH connections for multiple commands
- **Timeout Handling**: Set appropriate timeouts per device type
- **Configuration Backup**: Store outputs with timestamp and device metadata
- **Error Handling**: 5 retry attempts per job with configurable intervals
- **Failure Management**: Log errors and send notifications after retry exhaustion

## Security Considerations
- **Credential Management**: Store device credentials encrypted in database
- **SSH Key Management**: Use SSH keys where possible, avoid plaintext passwords
- **JWT Security**: Use strong secret keys, implement token refresh
- **Network Access**: Restrict API access to authorized networks only
- **Audit Logging**: Log all device access attempts and configuration changes

## Integration Points
- **Device Discovery**: SNMP/SSH-based network inventory scanning
- **Scheduling**: Cron-like job scheduling with retry policies  
- **Notifications**: Email/Slack integration for backup status
- **File Storage**: Local/network storage for configuration backups
- **Monitoring**: Health checks for device connectivity and job status

---
*Project Status: Initial development phase - core architecture and database schema to be implemented*