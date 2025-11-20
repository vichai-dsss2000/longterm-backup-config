# Setup Guide - longterm-backup-config

ระบบจัดการ backup อุปกรณ์เครือข่ายแบบอัตโนมัติ ด้วย FastAPI + React

---

## 📋 สารบัญ

1. [ความต้องการพื้นฐาน](#ความต้องการพื้นฐาน)
2. [โครงสร้างโปรเจค](#โครงสร้างโปรเจค)
3. [วิธีการติดตั้ง - Development](#วิธีการติดตั้ง---development)
4. [วิธีการรัน - Local](#วิธีการรัน---local)
5. [ทดสอบระบบ](#ทดสอบระบบ)
6. [Docker Deployment](#docker-deployment)
7. [Production Setup](#production-setup)
8. [Troubleshooting](#troubleshooting)

---

## ความต้องการพื้นฐาน

### Software Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| Python | 3.11+ | Backend API framework (FastAPI) |
| Node.js | 16+ | Frontend build tools (React) |
| npm | 8+ | Package manager for frontend |
| Git | - | Version control |
| SQLite3 | - | Database (included with Python) |
| Docker | 20.10+ | (Optional) For containerization |
| Docker Compose | 1.29+ | (Optional) For multi-container setup |

### System Requirements

- **OS**: Windows, macOS, or Linux
- **RAM**: 2GB minimum (4GB+ recommended)
- **Disk**: 500MB for application + database
- **Network**: Access to device SSH ports (22) for backup testing

---

## โครงสร้างโปรเจค

```
longterm-backup-config/
├── api/                          # Backend FastAPI application
│   ├── routers/                 # API endpoint routers
│   │   ├── auth_router.py       # Authentication (login, logout)
│   │   ├── device_router.py     # Device management
│   │   ├── template_router.py   # Backup templates
│   │   ├── schedule_router.py   # Job scheduling
│   │   ├── backup_router.py     # Backup operations
│   │   ├── monitoring_router.py # System monitoring
│   │   └── discovery_router.py  # Device discovery
│   ├── main.py                  # Main FastAPI application
│   ├── auth.py                  # JWT authentication logic
│   ├── database.py              # SQLAlchemy models & session
│   ├── config.py                # Settings management
│   ├── schemas.py               # Pydantic request/response models
│   ├── requirements.txt         # Python dependencies
│   ├── .env                     # Environment variables (development)
│   ├── .env.production          # Environment variables (production)
│   └── Dockerfile              # Docker image for backend
│
├── frontend/                    # React web application
│   ├── src/
│   │   ├── components/          # React components
│   │   │   ├── Auth/           # Login/Protected routes
│   │   │   ├── Dashboard/      # Main dashboard
│   │   │   ├── DeviceManagement/
│   │   │   ├── BackupJobs/
│   │   │   ├── Templates/
│   │   │   ├── Schedules/
│   │   │   └── Layout/
│   │   ├── services/            # API client & services
│   │   │   ├── apiClient.ts    # Axios instance
│   │   │   ├── deviceService.ts
│   │   │   ├── templateService.ts
│   │   │   ├── scheduleService.ts
│   │   │   └── backupService.ts
│   │   ├── context/            # React context (Auth state)
│   │   ├── App.tsx             # Main app component
│   │   └── index.tsx           # Entry point
│   ├── public/                 # Static files
│   ├── package.json            # NPM dependencies & scripts
│   ├── .env.local              # Environment (development)
│   ├── .env.production         # Environment (production)
│   ├── Dockerfile             # Docker image for frontend
│   └── nginx.conf             # Nginx configuration
│
├── scripts/                    # Automation scripts
│   ├── ssh_connection.py       # SSH device connections
│   ├── backup_executor.py      # Backup execution logic
│   ├── job_scheduler.py        # APScheduler integration
│   ├── template_processor.py   # Template processing
│   ├── device_discovery.py     # Network device discovery
│   ├── error_handling.py       # Error tracking & logging
│   └── test_validation.py      # System health checks
│
├── database/                   # Database schema
│   └── schema.sql              # SQL table definitions
│
├── docker-compose.yml          # Multi-container orchestration
├── DEPLOYMENT.md               # Production deployment guide
├── SETUP_GUIDE.md             # This file
├── README.md                   # Project overview
└── seed_example_data.py       # Database seeding script
```

---

## วิธีการติดตั้ง - Development

### ขั้นตอนที่ 1: Clone Repository

```bash
git clone https://github.com/vichai-dsss2000/longterm-backup-config.git
cd longterm-backup-config
```

### ขั้นตอนที่ 2: Backend Setup

#### Windows (PowerShell)

```powershell
# เข้าไปโฟลเดอร์ api
cd api

# สร้าง virtual environment
python -m venv .venv

# Activate venv
.\.venv\Scripts\Activate.ps1

# ติดตั้ง dependencies
pip install --upgrade pip
pip install -r requirements.txt

# ตรวจสอบว่าสำเร็จ
python verify_imports.py
```

#### macOS / Linux

```bash
cd api

python3 -m venv .venv
source .venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

python verify_imports.py
```

### ขั้นตอนที่ 3: Backend Configuration

```bash
# ในโฟลเดอร์ api ตรวจสอบไฟล์ .env
cat .env

# ตรวจสอบว่ามี DEVICE_ENCRYPTION_KEY หรือไม่
# ถ้าไม่มี ให้เพิ่มเข้าไป (ดูไฟล์ .env ที่มีอยู่)
```

### ขั้นตอนที่ 4: Database Setup

```bash
# ยังอยู่ในโฟลเดอร์ api และ venv ยังเปิดอยู่

# สร้าง database schema
python create_sqlite_schema.py

# Seed ข้อมูล example (users, devices, templates, etc.)
python ../seed_example_data.py

# ตรวจสอบ database
ls -la longterm_backup_config.db  # macOS/Linux
dir longterm_backup_config.db     # Windows
```

### ขั้นตอนที่ 5: Frontend Setup

```bash
# เปิด terminal ใหม่ (อย่าปิด terminal ของ backend)
cd frontend

# ติดตั้ง dependencies
npm install

# ตรวจสอบว่าสำเร็จ
npm list react react-router-dom axios
```

---

## วิธีการรัน - Local

### Terminal 1: Backend API

```powershell
# Windows PowerShell
cd api
.\.venv\Scripts\Activate.ps1
$env:DEV_SKIP_MANAGERS='1'
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
# macOS / Linux
cd api
source .venv/bin/activate
export DEV_SKIP_MANAGERS='1'
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

**ผลลัพธ์ที่คาดหวัง:**
```
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete
INFO:     All API routers registered successfully
```

**เข้าถึงได้ที่:**
- API Documentation: http://localhost:8000/api/docs
- ReDoc: http://localhost:8000/api/redoc
- Health Check: http://localhost:8000/api/health

---

### Terminal 2: Frontend React

```powershell
# Windows PowerShell
cd frontend
npm start
```

```bash
# macOS / Linux
cd frontend
npm start
```

**ผลลัพธ์ที่คาดหวัง:**
```
Compiled successfully!

You can now view frontend in the browser.

  Local:            http://localhost:3000
  On Your Network:  http://192.168.x.x:3000
```

**เข้าถึงได้ที่:**
- Dashboard: http://localhost:3000
- Login: http://localhost:3000/login

---

## ทดสอบระบบ

### 1. ทดสอบ Backend Login

เปิด http://localhost:8000/api/docs

1. ค้นหา endpoint: **POST /api/auth/login**
2. Click "Try it out"
3. ใส่ JSON:
```json
{
  "username": "admin",
  "password": "admin123"
}
```
4. Click "Execute" → ควรได้ token กลับมา

### 2. ทดสอบ API Endpoints

ยังคงอยู่ที่ Swagger UI:

1. Click ปุ่ม **"Authorize"** (สีเหลือง) ด้านบน
2. Paste token: `Bearer <token-from-login>`
3. Click "Authorize" (สีน้ำเงิน)
4. ลอง endpoint ต่างๆ:
   - **GET /api/devices/** - ดูรายการอุปกรณ์
   - **GET /api/templates/** - ดู backup templates
   - **GET /api/schedules/** - ดูตารางการ backup

### 3. ทดสอบ Frontend UI

เปิด http://localhost:3000

1. **Login Page**
   - Username: `admin`
   - Password: `admin123`
   - Click Login

2. **Dashboard**
   - ควรเห็นข้อมูล devices, templates, schedules
   - ตรวจสอบ Network Tab (F12) ไม่มี error

3. **Device Management**
   - ไปที่หน้า Device Management
   - ควรเห็นรายการ devices จากฐานข้อมูล

### 4. ทดสอบด้วย PowerShell

```powershell
# Login
$login = Invoke-RestMethod -Uri "http://localhost:8000/api/auth/login" `
  -Method POST -ContentType "application/json" `
  -Body '{"username":"admin","password":"admin123"}'

$token = $login.access_token
Write-Host "Token: $token"

# ใช้ token เรียก API
$headers = @{"Authorization"="Bearer $token"}
$devices = Invoke-RestMethod -Uri "http://localhost:8000/api/devices/" `
  -Headers $headers

$devices | ConvertTo-Json -Depth 3
```

---

## Docker Deployment

### ติดตั้ง Docker

- **Windows**: https://www.docker.com/products/docker-desktop
- **macOS**: https://www.docker.com/products/docker-desktop
- **Linux**: https://docs.docker.com/engine/install/

### Build & Run

```bash
# ตรวจสอบ Docker ติดตั้งแล้ว
docker --version
docker-compose --version

# Build images
docker-compose build

# เริ่มบริการ
docker-compose up -d

# ตรวจสอบ status
docker-compose ps

# ดู logs
docker-compose logs -f api
docker-compose logs -f frontend
```

**เข้าถึงได้ที่:**
- Backend: http://localhost:8000
- Frontend: http://localhost:3000

### ปิด Services

```bash
docker-compose down
```

---

## Production Setup

### เตรียมการ

1. **อัปเดต Environment Variables**

```bash
# api/.env.production
DEVICE_ENCRYPTION_KEY=<your-fernet-key>
SECRET_KEY=<your-jwt-secret-32-chars>
CORS_ORIGINS=https://yourdomain.com
DEFAULT_SFTP_SERVER=your-backup-server.com
# ... (ดูไฟล์ .env.production template)
```

2. **สร้าง SSL Certificate**

```bash
# ใช้ Let's Encrypt + Certbot
sudo apt-get install certbot
sudo certbot certonly --standalone -d yourdomain.com
```

3. **Update Nginx Configuration**

ดู `frontend/nginx.conf` แล้วอัปเดต:
- Domain name
- SSL certificate paths
- Backend API endpoint

### Deploy แบบ Manual

#### Backend:

```bash
cd api
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy production env
cp .env.production .env

# Run with gunicorn
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 main:app
```

#### Frontend:

```bash
cd frontend
npm install
npm run build

# Serve with nginx (see nginx.conf)
# หรือใช้ static server อื่น
```

### Deploy แบบ Docker

```bash
docker-compose -f docker-compose.yml build
docker-compose -f docker-compose.yml up -d
```

---

## Troubleshooting

### ❌ Backend Issues

#### Error: "ModuleNotFoundError: No module named 'fastapi'"

**วิธีแก้:**
```powershell
# ตรวจสอบว่า venv activate แล้ว
# (ควรเห็น (.venv) ข้างหน้า prompt)
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

#### Error: "DEVICE_ENCRYPTION_KEY not found"

**วิธีแก้:**
```bash
# เช็คไฟล์ .env
cat api/.env | grep DEVICE_ENCRYPTION_KEY

# ถ้าไม่มี ให้เพิ่มเข้าไป
# หรือสร้างใหม่:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

#### Error: "sqlite3.OperationalError: unable to open database file"

**วิธีแก้:**
```bash
cd api
python create_sqlite_schema.py
python ../seed_example_data.py
```

#### Error: "Port 8000 already in use"

**วิธีแก้:**
```powershell
# Windows
netstat -ano | findstr ":8000"
taskkill /PID <PID> /F

# macOS/Linux
lsof -ti:8000 | xargs kill
```

---

### ❌ Frontend Issues

#### Error: "npm: command not found"

**วิธีแก้:**
```bash
# ติดตั้ง Node.js จาก https://nodejs.org/
# ตรวจสอบการติดตั้ง
node --version
npm --version
```

#### Error: "Proxy error: Could not proxy request"

**วิธีแก้:**
```bash
# ตรวจสอบว่า backend รันอยู่ที่ port 8000
# ลองรีสตาร์ท frontend
npm start
```

#### Error: "Not authenticated"

**วิธีแก้:**
```bash
# เช็คว่า token ถูกส่งไปใน Authorization header
# DevTools → Network tab → Headers
# ควรเห็น: Authorization: Bearer <token>

# ถ้าไม่มี ให้ login ใหม่
```

---

### ❌ Database Issues

#### Error: "database is locked"

**วิธีแก้:**
```bash
# ปิดโปรแกรมที่เปิด database
# หรือลบ lock file
rm longterm_backup_config.db.lock

# Restart backend
```

#### ต้องการ Reset Database

```bash
# ลบ database เก่า
rm api/longterm_backup_config.db

# สร้างใหม่
cd api
python create_sqlite_schema.py
python ../seed_example_data.py
```

---

### ❌ Docker Issues

#### Error: "Cannot connect to Docker daemon"

**วิธีแก้:**
```bash
# ตรวจสอบ Docker รันอยู่
docker ps

# ถ้าไม่รัน ให้เปิด Docker Desktop หรือ:
sudo systemctl start docker  # Linux
```

#### Error: "Port 3000 already in use"

**วิธีแก้:**
```bash
# ใช้ port อื่น
docker-compose down
docker-compose -e PORT=3001 up
```

---

## 🔐 Security Checklist

### Pre-Production

- [ ] เปลี่ยน `SECRET_KEY` เป็น 32 characters random
- [ ] เปลี่ยน `DEVICE_ENCRYPTION_KEY` ด้วย Fernet key
- [ ] อัปเดต `CORS_ORIGINS` เป็น domain จริง
- [ ] ตั้งค่า SMTP สำหรับการแจ้งเตือน
- [ ] ตั้ง `ENVIRONMENT=production`
- [ ] ปิด `DEBUG=false`

### SSL/TLS

- [ ] ได้ SSL certificate จาก Let's Encrypt
- [ ] ตั้งค่า HTTPS redirect
- [ ] อัปเดต `REACT_APP_API_BASE_URL` เป็น `https://`

### Database

- [ ] Backup database ก่อน production
- [ ] ตั้ง read-only backups
- [ ] เปิด encryption สำหรับ sensitive data

### Monitoring

- [ ] ตั้ง log aggregation (e.g., ELK Stack)
- [ ] ตั้ง alerting สำหรับ errors
- [ ] ตั้ง health checks

---

## 📚 ลิงค์ที่เป็นประโยชน์

- **FastAPI Documentation**: https://fastapi.tiangolo.com
- **React Documentation**: https://react.dev
- **SQLAlchemy**: https://docs.sqlalchemy.org
- **Docker Documentation**: https://docs.docker.com
- **JWT Authentication**: https://jwt.io

---

## 📧 Support

สำหรับปัญหา หรือข้อเสนอแนะ ติดต่อ:
- GitHub Issues: [Project Issues]
- Email: admin@example.com
- Documentation: `DEPLOYMENT.md`

---

**Last Updated**: November 20, 2025
**Version**: 1.0.0
