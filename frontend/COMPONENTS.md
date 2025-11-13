# Frontend Components - Network Device Backup Management System

## 🎯 Overview

Frontend application สำหรับจัดการระบบ backup อุปกรณ์เครือข่ายแบบ comprehensive พร้อม features:

- ✅ **Authentication** - JWT-based login/logout
- ✅ **Dashboard** - Real-time system statistics และ recent backups
- ✅ **Device Management** - CRUD operations สำหรับ network devices
- ✅ **Backup Templates** - จัดการ backup command templates
- ✅ **Scheduler** - กำหนด backup schedules ด้วย cron expressions
- ✅ **Backup Jobs** - ดูและจัดการ backup jobs
- ✅ **Responsive Design** - Bootstrap-based UI ที่ใช้งานง่าย

## 📁 โครงสร้าง

```
frontend/src/
├── components/
│   ├── Auth/                 # Login และ authentication
│   ├── Dashboard/            # Dashboard หน้าหลัก
│   ├── DeviceManagement/     # จัดการ devices
│   ├── Templates/            # จัดการ backup templates
│   ├── Schedules/            # จัดการ schedule policies
│   ├── BackupJobs/           # จัดการ backup jobs
│   └── Layout/               # Layout components
├── services/                 # API service layers
│   ├── apiClient.ts          # Axios instance พร้อม interceptors
│   ├── dashboardService.ts   # Dashboard APIs
│   ├── deviceService.ts      # Device management APIs
│   ├── templateService.ts    # Template management APIs
│   ├── scheduleService.ts    # Schedule management APIs
│   └── backupService.ts      # Backup job APIs
├── context/
│   └── AuthContext.tsx       # Authentication context
└── types/
    └── scheduler.ts          # TypeScript type definitions

```

## 🚀 Getting Started

### 1. ติดตั้ง Dependencies

```bash
cd frontend
npm install
```

### 2. กำหนด Proxy

ใน `package.json` มีการตั้งค่า proxy ไปยัง backend:

```json
{
  "proxy": "http://localhost:8000"
}
```

### 3. เริ่มต้น Development Server

```bash
npm start
```

Application จะเปิดที่ `http://localhost:3000`

## 🔐 Authentication

### Login Credentials

Default admin account:
- **Username**: `admin`
- **Password**: `admin123`

### JWT Token Flow

1. Login ที่ `/login`
2. ได้รับ JWT token และเก็บใน localStorage
3. Token จะถูกแนบใน Authorization header ทุก API request
4. Token หมดอายุจะ redirect ไปหน้า login อัตโนมัติ

## 📊 Components Overview

### 1. Dashboard

แสดงสถิติและ overview ของระบบ:

```typescript
import { DashboardService } from '../../services/dashboardService';

// Fetch dashboard stats
const stats = await DashboardService.getStats();

// Get recent backups
const backups = await BackupService.getRecentBackups(10);
```

**Features:**
- Total devices (active/inactive)
- Total backups (success/failed)
- Scheduled jobs
- Success rate progress bar
- Recent backup jobs list
- Auto-refresh ทุก 30 วินาที

### 2. Device Management

จัดการ network devices:

```typescript
import { DeviceService } from '../../services/deviceService';

// Get all devices
const devices = await DeviceService.getDevices();

// Create new device
const newDevice = await DeviceService.createDevice({
  device_name: 'Core-Switch-01',
  ip_address: '192.168.1.1',
  device_type_id: 1,
  ssh_username: 'admin',
  ssh_password: 'secret'
});

// Test connection
const result = await DeviceService.testConnection(deviceId);
```

**Features:**
- Add/Edit/Delete devices
- Search และ filter devices
- Test SSH connection
- Device type selection
- Bulk operations support

### 3. Backup Templates

จัดการ backup command templates:

```typescript
import { TemplateService } from '../../services/templateService';

// Get templates
const templates = await TemplateService.getTemplates();

// Create template
const template = await TemplateService.createTemplate({
  device_type_id: 1,
  template_name: 'Cisco IOS Backup',
  backup_command: 'copy running-config tftp://...',
  command_format: 'TEXT'
});
```

**Features:**
- Create/Edit/Delete templates
- Template validation
- Support multiple command formats (TEXT, JSON, XML, YAML)
- Template variables
- Retry และ timeout configuration

### 4. Schedule Management

กำหนดและจัดการ backup schedules:

```typescript
import { ScheduleService } from '../../services/scheduleService';

// Get schedules
const schedules = await ScheduleService.getSchedulerJobs();

// Create schedule
const schedule = await ScheduleService.createSchedulerJob({
  policy_name: 'Daily Backup',
  cron_expression: '0 2 * * *',
  device_type_id: 1,
  template_id: 1,
  backup_path: '/backups/daily/'
});
```

**Features:**
- Cron expression builder
- Schedule validation
- Enable/Disable schedules
- Manual trigger
- View next run time

### 5. Backup Jobs

ดูและจัดการ backup jobs:

```typescript
import { BackupService } from '../../services/backupService';

// Get backup history
const backups = await BackupService.getBackups({
  device_id: 1,
  job_status: 'success',
  start_date: '2025-01-01'
});

// Trigger manual backup
const job = await BackupService.triggerManualBackup(deviceId, templateId);

// Download backup file
const blob = await BackupService.downloadBackupFile(jobId);
```

**Features:**
- View backup history
- Filter by device, status, date
- Manual backup trigger
- Retry failed backups
- Download backup files
- View execution logs

## 🔧 API Services

### apiClient.ts

Base Axios instance พร้อม:
- Auto JWT token injection
- Request/Response interceptors
- Error handling
- 401 auto-redirect

### Service Pattern

ทุก service ใช้ pattern เดียวกัน:

```typescript
export class ServiceName {
  static async getItems(): Promise<Type[]> {
    const response = await apiClient.get('/endpoint/');
    return response.data;
  }

  static async getItem(id: number): Promise<Type> {
    const response = await apiClient.get(`/endpoint/${id}`);
    return response.data;
  }

  static async createItem(data: CreateType): Promise<Type> {
    const response = await apiClient.post('/endpoint/', data);
    return response.data;
  }

  static async updateItem(id: number, data: UpdateType): Promise<Type> {
    const response = await apiClient.put(`/endpoint/${id}`, data);
    return response.data;
  }

  static async deleteItem(id: number): Promise<void> {
    await apiClient.delete(`/endpoint/${id}`);
  }
}
```

## 🎨 UI Components

### สไตล์และ Theme

- **Framework**: React Bootstrap 5
- **Icons**: React Icons (Font Awesome)
- **Alerts**: SweetAlert2
- **Color Scheme**: 
  - Primary: Blue (#0d6efd)
  - Success: Green (#198754)
  - Danger: Red (#dc3545)
  - Warning: Yellow (#ffc107)

### Common UI Patterns

**Loading State:**
```tsx
{loading ? (
  <div className="text-center py-5">
    <Spinner animation="border" variant="primary" />
    <p className="mt-2">Loading...</p>
  </div>
) : (
  // Content
)}
```

**Error Handling:**
```tsx
{error && (
  <Alert variant="danger" dismissible onClose={() => setError('')}>
    {error}
  </Alert>
)}
```

**Modal Form:**
```tsx
<Modal show={showModal} onHide={handleClose} size="lg">
  <Modal.Header closeButton>
    <Modal.Title>Form Title</Modal.Title>
  </Modal.Header>
  <Form onSubmit={handleSubmit}>
    <Modal.Body>
      {/* Form fields */}
    </Modal.Body>
    <Modal.Footer>
      <Button variant="secondary" onClick={handleClose}>Cancel</Button>
      <Button variant="primary" type="submit">Submit</Button>
    </Modal.Footer>
  </Form>
</Modal>
```

## 🔍 ตัวอย่างการใช้งาน

### 1. เพิ่ม Device ใหม่

```typescript
// 1. เปิด modal
handleShowModal();

// 2. กรอกข้อมูล
setFormData({
  device_name: 'Switch-01',
  ip_address: '192.168.1.10',
  device_type_id: 1,
  ssh_username: 'admin',
  ssh_password: 'password'
});

// 3. Submit
await DeviceService.createDevice(formData);

// 4. Refresh list
fetchDevices();
```

### 2. สร้าง Backup Schedule

```typescript
// 1. เลือก device type และ template
const deviceTypes = await DeviceService.getDeviceTypes();
const templates = await TemplateService.getTemplatesByDeviceType(deviceTypeId);

// 2. สร้าง schedule
await ScheduleService.createSchedulerJob({
  policy_name: 'Daily Backup',
  cron_expression: '0 2 * * *', // 2 AM ทุกวัน
  device_type_id: deviceTypeId,
  template_id: templateId,
  backup_path: '/backups/daily/',
  retention_days: 30
});
```

### 3. Manual Backup Trigger

```typescript
// Trigger backup
const job = await BackupService.triggerManualBackup(deviceId, templateId);

// Monitor status
const checkStatus = setInterval(async () => {
  const updatedJob = await BackupService.getBackup(job.id);
  if (updatedJob.job_status !== 'running') {
    clearInterval(checkStatus);
    // Show result
  }
}, 5000);
```

## 🐛 Debugging

### Browser Console

เปิด Developer Tools (F12) และดู Console tab สำหรับ:
- API request/response logs
- Error messages
- Component lifecycle logs

### Network Tab

ดู Network tab สำหรับ:
- API endpoints
- Request headers (JWT token)
- Response status codes
- Response data

### Common Issues

**401 Unauthorized:**
- Token หมดอายุ → Login ใหม่
- Token ไม่ถูกต้อง → Clear localStorage และ login

**422 Unprocessable Entity:**
- ข้อมูล form ไม่ครบ/ไม่ถูกต้อง
- Validation errors → ดู response.data.details

**500 Internal Server Error:**
- Backend error → ดู backend logs
- Database connection issue

## 📝 การพัฒนาต่อ

### เพิ่ม Component ใหม่

1. สร้างไฟล์ใน `src/components/NewFeature/`
2. สร้าง service ใน `src/services/newFeatureService.ts`
3. เพิ่ม route ใน App.tsx
4. เพิ่ม menu item ใน Layout

### เพิ่ม API Service

```typescript
// src/services/newService.ts
import apiClient from './apiClient';

export interface NewType {
  id: number;
  name: string;
}

export class NewService {
  static async getItems(): Promise<NewType[]> {
    const response = await apiClient.get('/new-endpoint/');
    return response.data;
  }
  
  // Add more methods...
}
```

### Style Guidelines

- ใช้ React Bootstrap components
- Responsive design (ใช้ Row, Col)
- Consistent spacing (mb-3, mb-4, py-3, py-4)
- Loading states สำหรับทุก async operation
- Error handling ด้วย Alert หรือ SweetAlert2

## 🚀 Deployment

### Build for Production

```bash
npm run build
```

### Environment Variables

สร้างไฟล์ `.env`:

```env
REACT_APP_API_URL=https://api.yourdomain.com
REACT_APP_VERSION=1.0.0
```

### Nginx Configuration

```nginx
location / {
  root /var/www/html;
  try_files $uri $uri/ /index.html;
}

location /api {
  proxy_pass http://backend:8000;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
}
```

## 📚 เอกสารเพิ่มเติม

- [React Documentation](https://react.dev/)
- [React Bootstrap](https://react-bootstrap.github.io/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [Axios Documentation](https://axios-http.com/)

---

สร้างโดย: Network Backup System Team  
Version: 1.0.0  
Last Updated: November 2025
