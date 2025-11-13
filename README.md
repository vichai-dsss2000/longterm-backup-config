# Network Device Backup Management System

[![React](https://img.shields.io/badge/React-19.1.1-blue.svg)](https://reactjs.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.104-green.svg)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.11-blue.svg)](https://www.python.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-4.9-blue.svg)](https://www.typescriptlang.org/)
[![SQLite](https://img.shields.io/badge/SQLite-3-lightgrey.svg)](https://www.sqlite.org/)

> A comprehensive network device backup management system with web-based administration, automated scheduling, and multi-vendor device support.

## 🚀 Features

### ✨ Web Dashboard
- **Modern React UI** with responsive design
- **Real-time monitoring** of backup jobs and device status
- **Device Navigator** - hierarchical tree view by location and device type
- **Multi-page management**: Devices, Templates, Schedules, Backup Jobs
- **JWT Authentication** with secure session management

### 🔧 Device Management
- **Multi-vendor support**: Cisco, Juniper, MikroTik, HP, Fortinet, and more
- **Device inventory** with type categorization
- **SSH connection testing**
- **Hierarchical organization** by location and device type
- **Device detail pages** with full configuration history

### 📝 Backup Templates
- **Template-based commands** for different device types
- **Multiple format support**: TEXT, JSON, XML, YAML
- **Variable substitution** system
- **Version control** for templates
- **Template validation** before deployment

### ⏰ Job Scheduling
- **Cron-based scheduling** with intuitive presets
- **Per-device-type policies**
- **Retention management** (configurable retention days)
- **Compression & encryption** options
- **Email notifications** on job completion
- **Manual trigger** capability

### 📊 Backup Jobs Monitoring
- **Real-time job status** tracking
- **Success rate statistics**
- **Auto-refresh** mode (10-second intervals)
- **Filtering** by status, device, date range
- **Job details** with full execution logs
- **Retry mechanism** for failed jobs
- **Backup file download**

## 🏗️ Architecture

**3-Tier Architecture:**
```
┌─────────────────┐
│   Frontend      │  React 19 + TypeScript + React Bootstrap
│   (Port 3001)   │  
└────────┬────────┘
         │ REST API / JWT Auth
┌────────▼────────┐
│   Backend       │  FastAPI + SQLAlchemy
│   (Port 8000)   │  
└────────┬────────┘
         │ 
┌────────▼────────┐
│   Database      │  SQLite (dev) / MySQL (prod)
│   + Scripts     │  Netmiko SSH Automation
└─────────────────┘
```

## 📁 Project Structure

```
longterm-backup-config/
├── frontend/                    # React TypeScript Application
│   ├── src/
│   │   ├── components/
│   │   │   ├── Auth/           # Login & Authentication
│   │   │   ├── Dashboard/      # Main dashboard with stats
│   │   │   ├── DeviceManagement/  # Device CRUD operations
│   │   │   ├── DeviceDetail/   # Device detail page
│   │   │   ├── Templates/      # Template management
│   │   │   ├── Schedules/      # Job scheduling
│   │   │   ├── BackupJobs/     # Job monitoring
│   │   │   └── Layout/         # Main layout with Device Navigator
│   │   ├── services/           # API client services
│   │   ├── context/            # React context (Auth)
│   │   └── types/              # TypeScript interfaces
│   └── package.json
│
├── api/                        # FastAPI Backend
│   ├── main.py                # Application entry point
│   ├── database.py            # SQLAlchemy models
│   ├── schemas.py             # Pydantic schemas
│   ├── auth.py                # JWT authentication
│   ├── config.py              # Configuration
│   └── routers/               # API route handlers
│       ├── auth_router.py
│       ├── device_router.py
│       ├── template_router.py
│       ├── schedule_router.py
│       ├── backup_router.py
│       └── monitoring_router.py
│
├── scripts/                    # Automation Scripts
│   ├── ssh_connection.py      # SSH connection manager
│   ├── template_processor.py # Template engine
│   ├── backup_executor.py    # Backup job executor
│   ├── job_scheduler.py      # APScheduler integration
│   ├── device_discovery.py   # Network discovery
│   └── file_storage.py       # Backup file management
│
├── templates/                 # Device Command Templates
│   ├── cisco/
│   ├── juniper/
│   ├── mikrotik/
│   └── huawei/
│
└── database/
    └── schema.sql            # Database schema
```

## 🚦 Getting Started

### Prerequisites
- **Node.js** 18+ and npm
- **Python** 3.11+
- **SQLite** (for development) or MySQL (for production)

### Installation

#### 1. Clone the repository
```bash
git clone https://github.com/vichai-dsss2000/longterm-backup-config.git
cd longterm-backup-config
```

#### 2. Backend Setup
```bash
cd api
pip install -r requirements.txt

# Create database and seed data
python create_test_user.py
python seed_example_data.py
python create_test_schedule_data.py

# Run the API server
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at: `http://localhost:8000`
- API Documentation: `http://localhost:8000/docs`
- Alternative docs: `http://localhost:8000/redoc`

#### 3. Frontend Setup
```bash
cd frontend
npm install

# Start the development server
npm start
```

The frontend will be available at: `http://localhost:3001`

### Default Credentials
```
Username: admin
Password: admin123
```

## 📖 Usage Guide

### Device Management
1. **Add Devices**: Navigate to "Devices" → Click "Add Device"
2. **Test Connection**: Use "Test Connection" button to verify SSH access
3. **View Details**: Click on device in Device Navigator or device list
4. **Edit Device**: Click "Edit" button on device detail page

### Template Management
1. **Create Template**: Templates → "Create Template"
2. **Select Device Type**: Choose vendor/model/firmware
3. **Configure Command**: Enter backup command with variables
4. **Set Timeouts**: Configure timeout and retry settings
5. **Validate**: Use "Validate" button before saving

### Schedule Configuration
1. **Create Schedule**: Schedules → "Create Schedule"
2. **Select Template**: Choose backup template
3. **Set Cron Expression**: Use presets or custom cron
4. **Configure Options**: 
   - Backup path
   - Retention days
   - Compression/Encryption
   - Email notifications
5. **Activate**: Enable schedule to start automated backups

### Monitoring Backups
1. **View Jobs**: Navigate to "Backup Jobs"
2. **Filter Jobs**: By status, device, or date range
3. **Job Details**: Click job to view execution details
4. **Actions**:
   - **Retry**: Retry failed jobs
   - **Cancel**: Cancel running jobs
   - **Download**: Download successful backup files

### Device Navigator
- Click hamburger menu (☰) to open Device Navigator
- Tree view organized by:
  - **Location** → **Device Type** → **Devices**
- Click device to view details
- Expand/Collapse all controls
- Real-time device count display

## 🔌 API Endpoints

### Authentication
- `POST /api/auth/login` - Login and get JWT token
- `POST /api/auth/logout` - Logout current session

### Devices
- `GET /api/devices/` - List all devices
- `GET /api/devices/{id}` - Get device details
- `POST /api/devices/` - Create new device
- `PUT /api/devices/{id}` - Update device
- `DELETE /api/devices/{id}` - Delete device
- `POST /api/devices/{id}/test-connection` - Test SSH connection
- `GET /api/devices/{id}/backup-history` - Get device backup history

### Device Types
- `GET /api/devices/types` - List all device types
- `POST /api/devices/types` - Create device type
- `PUT /api/devices/types/{id}` - Update device type

### Templates
- `GET /api/templates/` - List all templates
- `GET /api/templates/{id}` - Get template details
- `POST /api/templates/` - Create template
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template
- `POST /api/templates/{id}/validate` - Validate template

### Schedules
- `GET /api/schedules/` - List all schedules
- `GET /api/schedules/{id}` - Get schedule details
- `POST /api/schedules/` - Create schedule
- `PUT /api/schedules/{id}` - Update schedule
- `DELETE /api/schedules/{id}` - Delete schedule
- `POST /api/schedules/{id}/trigger` - Manually trigger schedule

### Backup Jobs
- `GET /api/backups/` - List backup jobs
- `GET /api/backups/{id}` - Get job details
- `GET /api/backups/stats` - Get backup statistics
- `POST /api/backups/{id}/retry` - Retry failed job
- `POST /api/backups/{id}/cancel` - Cancel running job
- `GET /api/backups/{id}/download` - Download backup file

## 🛠️ Technology Stack

### Frontend
- **React 19.1.1** - UI framework
- **TypeScript 4.9** - Type safety
- **React Bootstrap 2.10** - UI components
- **React Router 6** - Navigation
- **Axios** - HTTP client
- **Lucide React** - Icons
- **SweetAlert2** - Alerts and dialogs

### Backend
- **FastAPI** - Web framework
- **SQLAlchemy** - ORM
- **Pydantic** - Data validation
- **JWT** - Authentication
- **Netmiko** - SSH automation
- **APScheduler** - Job scheduling
- **Cryptography** - Encryption

### Database
- **SQLite** (Development)
- **MySQL** (Production ready)

### DevOps
- **uvicorn** - ASGI server
- **Docker** support (optional)

## 🔐 Security Features

### Authentication & Authorization
- JWT-based authentication
- Secure password hashing (bcrypt)
- Token expiration and refresh
- Role-based access control (Admin/User)

### Data Protection
- Encrypted credential storage (Fernet)
- SSH key support
- HTTPS ready
- CORS configuration
- SQL injection protection (SQLAlchemy ORM)

### Audit & Logging
- User activity logging
- Device access tracking
- Backup job history
- Error logging with categorization

## 📊 Database Schema

### Key Tables
- `users` - User accounts and authentication
- `user_profiles` - Extended user information
- `login_sessions` - Active JWT sessions
- `network_devices` - Device inventory
- `device_types` - Device categorization
- `backup_command_templates` - Backup templates
- `job_schedule_policies` - Scheduled jobs
- `job_categories` - Job categorization
- `device_backup_info` - Backup execution records

## 🧪 Testing

### Test Data Setup
```bash
# Create test users
python create_test_user.py

# Seed example devices and templates
python seed_example_data.py

# Create test schedules
python create_test_schedule_data.py
```

### API Testing
```bash
# Test authentication
./test_auth_api.sh

# Or use the test script
python test_auth_api.py
```

### Frontend Testing
```bash
cd frontend
npm test
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License.

## 👥 Authors

- **Vichai** - Initial work - [vichai-dsss2000](https://github.com/vichai-dsss2000)

## 🙏 Acknowledgments

- FastAPI framework for excellent API development
- React team for the amazing UI library
- Netmiko for multi-vendor network device support
- Bootstrap team for responsive UI components

---

**Project Status**: ✅ Production Ready - Fully functional with all core features implemented

Last Updated: November 13, 2025