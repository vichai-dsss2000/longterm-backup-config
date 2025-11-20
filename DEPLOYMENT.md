# Deployment Guide - longterm-backup-config

## Development Setup (Local)

### Prerequisites
- Python 3.11+
- Node.js 16+
- SQLite3 (included with Python)

### Backend Setup

```bash
cd api

# Create virtual environment
python -m venv .venv

# Activate venv
# Windows:
.\.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables
$env:DEV_SKIP_MANAGERS='1'    # Skip heavy managers in dev

# Run backend
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

**Backend available at:** http://localhost:8000
**API Docs (Swagger UI):** http://localhost:8000/api/docs

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Start dev server (with proxy to backend)
npm start
```

**Frontend available at:** http://localhost:3000

### Database Seeding

```bash
cd api
python ../seed_example_data.py
```

Creates:
- Admin user: `admin` / `admin123`
- Sample devices, templates, schedules, backups

## Production Deployment

### Docker Setup

1. **Configure environment:**

```bash
# Update api/.env.production with your settings
DEVICE_ENCRYPTION_KEY=<your-fernet-key>
SECRET_KEY=<your-jwt-secret>
SMTP_SERVER=<your-smtp-server>
DEFAULT_SFTP_SERVER=<your-sftp-server>
# ... (see .env.production template)
```

2. **Build and run containers:**

```bash
# Build images
docker-compose build

# Run services
docker-compose up -d

# Check logs
docker-compose logs -f api
docker-compose logs -f frontend
```

**Services:**
- Backend: http://localhost:8000
- Frontend: http://localhost:3000
- Nginx (optional): http://localhost:80

### Manual Production Setup

1. **Backend:**

```bash
cd api

# Create venv
python -m venv venv
source venv/bin/activate  # or .venv\Scripts\Activate.ps1 on Windows

# Install production dependencies
pip install -r requirements.txt

# Copy .env.production to .env and update values
cp .env.production .env

# Run with gunicorn (for production)
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 main:app
```

2. **Frontend:**

```bash
cd frontend

# Install and build
npm install
npm run build

# Build output is in `build/` directory
# Serve with nginx or other static server
```

3. **Nginx Configuration:**

```nginx
upstream api {
    server api:8000;
}

server {
    listen 80;
    server_name yourdomain.com;

    # Frontend
    location / {
        root /var/www/html;
        try_files $uri /index.html;
    }

    # Backend API
    location /api {
        proxy_pass http://api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Considerations

### Required Changes for Production

1. **JWT Secret Key**
   - Generate: `openssl rand -hex 32`
   - Update `SECRET_KEY` in `.env.production`

2. **Encryption Key**
   - Generate: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
   - Update `DEVICE_ENCRYPTION_KEY` in `.env.production`

3. **Database**
   - Use PostgreSQL instead of SQLite for production
   - Update `DATABASE_URL=postgresql://user:password@host/dbname`

4. **CORS Settings**
   - Update `CORS_ORIGINS` to your domain only
   - Remove `http://localhost:*` from production

5. **SMTP Configuration**
   - Configure email server for backup notifications
   - Use app-specific passwords for email accounts

6. **SSL/TLS**
   - Use Let's Encrypt for free SSL certificates
   - Configure Nginx with HTTPS

### Environment Files

- `.env` - Development (local)
- `.env.local` - Frontend local overrides
- `.env.production` - Production settings (secrets)

**⚠️ Never commit .env files with secrets to git!**

## Database Migrations

### Create Database Schema

```bash
cd api

# Using sqlite3
sqlite3 longterm_backup_config.db < ../database/schema.sql

# Or Python
python create_sqlite_schema.py
```

### Backup Database

```bash
# SQLite backup
cp api/longterm_backup_config.db api/longterm_backup_config.db.backup

# MySQL backup (if using MySQL)
mysqldump -u root -p backup_system > backup_system.sql
```

## Monitoring

### Health Check

```bash
# Check backend health
curl http://localhost:8000/api/health

# Check Docker containers
docker-compose ps
docker-compose logs -f
```

### Common Issues

1. **Authentication Error (Not authenticated)**
   - Verify `DEVICE_ENCRYPTION_KEY` is set
   - Check JWT token is sent in Authorization header
   - Ensure token hasn't expired

2. **CORS Errors**
   - Check `CORS_ORIGINS` includes frontend URL
   - Frontend proxy enabled for development

3. **Database Connection Error**
   - Verify `DATABASE_URL` is correct
   - Check database file exists: `api/longterm_backup_config.db`

4. **Port Already in Use**
   - Change port: `uvicorn main:app --port 8001`
   - Kill existing process: `lsof -ti:8000 | xargs kill`

## Support

For issues, check:
- Backend logs: `api/logs/`
- Swagger UI: http://localhost:8000/api/docs
- Frontend console: DevTools → Console tab

See `README.md` for more information.
