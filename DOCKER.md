# Docker Deployment Guide

Complete guide for deploying the Network Device Backup Management System using Docker.

---

## 📋 Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 4GB RAM
- 20GB free disk space

---

## 🚀 Quick Start

### 1. Clone and Setup

```bash
git clone https://github.com/vichai-dsss2000/longterm-backup-config.git
cd longterm-backup-config

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment Variables

Edit `.env` file with your values:

```bash
# Generate JWT secret key
python3 -c "import secrets; print(f'JWT_SECRET_KEY={secrets.token_urlsafe(32)}')"

# Generate encryption key for credentials
python3 -c "from cryptography.fernet import Fernet; print(f'ENCRYPTION_KEY={Fernet.generate_key().decode()}')"

# Set strong database passwords
echo "DB_ROOT_PASSWORD=$(openssl rand -base64 32)"
echo "DB_PASSWORD=$(openssl rand -base64 32)"
```

### 3. Build and Run

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f
```

### 4. Initialize Database

```bash
# Run database migrations
docker-compose exec api python seed_example_data.py

# Create admin user
docker-compose exec api python create_test_user.py
```

### 5. Access Application

- **Frontend:** http://localhost:3001
- **API Documentation:** http://localhost:8000/docs
- **Database:** localhost:3306 (from host)

**Default Credentials:**
- Username: `admin`
- Password: `admin123`

⚠️ **Change these immediately in production!**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Docker Host                         │
├─────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐         ┌──────────────┐             │
│  │  Frontend   │────────▶│   Backend    │             │
│  │  (nginx)    │         │   (FastAPI)  │             │
│  │  Port 3001  │         │   Port 8000  │             │
│  └─────────────┘         └───────┬──────┘             │
│                                   │                     │
│                          ┌────────▼────────┐           │
│                          │     MySQL       │           │
│                          │   Port 3306     │           │
│                          └─────────────────┘           │
│                                                          │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Service Details

### Frontend Service

- **Base Image:** `nginx:1.25-alpine`
- **Build Context:** `./frontend`
- **Exposed Port:** `3001:80`
- **Features:**
  - React production build
  - Gzip compression
  - Security headers
  - API proxy to backend

**Health Check:**
```bash
docker-compose ps frontend
curl http://localhost:3001/
```

### Backend API Service

- **Base Image:** `python:3.11-slim`
- **Build Context:** `./api`
- **Exposed Port:** `8000:8000`
- **Workers:** 4 (configurable)
- **Features:**
  - FastAPI with uvicorn
  - Non-root user execution
  - Health check endpoint
  - Backup storage volume

**Health Check:**
```bash
docker-compose ps api
curl http://localhost:8000/api/health
```

### Database Service

- **Image:** `mysql:8.0`
- **Exposed Port:** `3306:3306`
- **Persistent Volume:** `db-data`
- **Features:**
  - UTF-8 MB4 encoding
  - Automatic schema initialization
  - Health checks
  - Backup friendly

**Health Check:**
```bash
docker-compose ps db
docker-compose exec db mysql -uroot -p${DB_ROOT_PASSWORD} -e "SELECT 1"
```

---

## 🔧 Configuration

### Environment Variables

**Required:**
```bash
# Security
JWT_SECRET_KEY=<32+ character secret>
ENCRYPTION_KEY=<fernet key>
DB_ROOT_PASSWORD=<strong password>
DB_PASSWORD=<strong password>

# Application
CORS_ORIGINS=http://localhost:3001
MAX_CONCURRENT_BACKUPS=5
```

**Optional:**
```bash
# Email notifications
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Backup storage
SFTP_SERVER_IP=10.10.100.10
SFTP_USERNAME=backup_user
SFTP_PASSWORD=secure-password

# Monitoring
ALERT_EMAIL=admin@yourdomain.com
```

### Volume Mounts

**Persistent Data:**
```yaml
volumes:
  db-data:           # MySQL database
  backup-data:       # Network device backups
  api-logs:          # Application logs
```

**Development Mode (Optional):**
```yaml
services:
  api:
    volumes:
      - ./api:/app  # Live code reload
```

### Network Configuration

**Default Network:**
- Name: `backup-network`
- Driver: `bridge`
- Subnet: Auto-assigned by Docker

**Custom Network:**
```yaml
networks:
  backup-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.25.0.0/16
```

---

## 🛠️ Management Commands

### Start/Stop Services

```bash
# Start all services
docker-compose up -d

# Start specific service
docker-compose up -d api

# Stop all services
docker-compose down

# Stop and remove volumes (⚠️ deletes data)
docker-compose down -v
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f api
docker-compose logs -f frontend
docker-compose logs -f db

# Last 100 lines
docker-compose logs --tail=100 api
```

### Execute Commands

```bash
# Open shell in container
docker-compose exec api bash
docker-compose exec frontend sh
docker-compose exec db mysql -uroot -p

# Run Python script
docker-compose exec api python seed_example_data.py

# Database backup
docker-compose exec db mysqldump -uroot -p${DB_ROOT_PASSWORD} backup_system > backup.sql

# Database restore
docker-compose exec -T db mysql -uroot -p${DB_ROOT_PASSWORD} backup_system < backup.sql
```

### Rebuild Services

```bash
# Rebuild all images
docker-compose build

# Rebuild specific service
docker-compose build api

# Rebuild without cache
docker-compose build --no-cache api

# Pull latest base images
docker-compose build --pull
```

---

## 📊 Monitoring

### Container Status

```bash
# Check running containers
docker-compose ps

# Container resource usage
docker stats

# Inspect container
docker-compose exec api env
docker inspect backup-api
```

### Health Checks

```bash
# Check all services
docker-compose ps

# Frontend health
curl http://localhost:3001/

# API health
curl http://localhost:8000/api/health | jq

# Database health
docker-compose exec db mysqladmin ping -h localhost -u root -p${DB_ROOT_PASSWORD}
```

### Application Logs

```bash
# API logs
docker-compose exec api tail -f /app/logs/api.log

# Nginx access logs
docker-compose exec frontend tail -f /var/log/nginx/access.log

# MySQL logs
docker-compose logs db
```

---

## 🔐 Security Best Practices

### 1. **Change Default Passwords**

```bash
# Generate strong passwords
openssl rand -base64 32

# Update .env file
vim .env
```

### 2. **Use Secrets (Production)**

```yaml
# docker-compose.prod.yml
secrets:
  db_password:
    file: ./secrets/db_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt

services:
  api:
    secrets:
      - db_password
      - jwt_secret
```

### 3. **Enable TLS/SSL**

```yaml
services:
  nginx:
    volumes:
      - ./ssl/cert.pem:/etc/nginx/ssl/cert.pem:ro
      - ./ssl/key.pem:/etc/nginx/ssl/key.pem:ro
```

### 4. **Scan for Vulnerabilities**

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh

# Scan images
trivy image backup-api:latest
trivy image backup-frontend:latest
trivy image mysql:8.0
```

### 5. **Limit Container Resources**

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

---

## 🚀 Production Deployment

### 1. **Production Compose File**

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  api:
    restart: always
    environment:
      - ENVIRONMENT=production
      - LOG_LEVEL=WARNING
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G

  frontend:
    restart: always
    deploy:
      replicas: 2

  db:
    restart: always
    deploy:
      resources:
        limits:
          memory: 4G
```

**Run:**
```bash
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 2. **Enable Nginx Reverse Proxy**

```bash
# Use production profile
docker-compose --profile production up -d
```

**Configure SSL:**
```nginx
# nginx/nginx.conf
server {
    listen 443 ssl http2;
    server_name backup.yourdomain.com;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass http://frontend;
    }
    
    location /api/ {
        proxy_pass http://api:8000;
    }
}
```

### 3. **Database Backups**

**Automated backup script:**
```bash
#!/bin/bash
# backup-db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/database"

mkdir -p $BACKUP_DIR

docker-compose exec -T db mysqldump \
  -uroot -p${DB_ROOT_PASSWORD} \
  --single-transaction \
  --quick \
  --lock-tables=false \
  backup_system | gzip > $BACKUP_DIR/backup_$DATE.sql.gz

# Keep last 7 days
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
```

**Cron job:**
```cron
# Daily backup at 2 AM
0 2 * * * /path/to/backup-db.sh
```

### 4. **Log Rotation**

```yaml
# docker-compose.yml
services:
  api:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### 5. **Monitoring with Prometheus**

```yaml
# docker-compose.monitoring.yml
services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
```

---

## 🔄 Backup & Recovery

### Application Backup

```bash
# Backup all volumes
docker run --rm \
  -v backup-data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar czf /backup/backup-data.tar.gz /data

# Backup database
docker-compose exec -T db mysqldump -uroot -p${DB_ROOT_PASSWORD} backup_system \
  | gzip > backup-db.sql.gz
```

### Disaster Recovery

```bash
# Restore volumes
docker run --rm \
  -v backup-data:/data \
  -v $(pwd)/backups:/backup \
  alpine tar xzf /backup/backup-data.tar.gz -C /

# Restore database
gunzip < backup-db.sql.gz | \
  docker-compose exec -T db mysql -uroot -p${DB_ROOT_PASSWORD} backup_system
```

---

## 🐛 Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs api

# Check container status
docker-compose ps

# Inspect container
docker inspect backup-api

# Remove and recreate
docker-compose down
docker-compose up -d
```

### Database Connection Issues

```bash
# Check database is running
docker-compose ps db

# Test connection from API container
docker-compose exec api python -c "
from database import engine
print(engine.connect())
"

# Check environment variables
docker-compose exec api env | grep DB
```

### Permission Issues

```bash
# Fix volume permissions
docker-compose exec api chown -R appuser:appuser /app/backups
docker-compose exec api chmod -R 755 /app/backups
```

### Out of Memory

```bash
# Check memory usage
docker stats

# Increase Docker memory limit (Docker Desktop)
# Settings → Resources → Memory → Increase limit

# Reduce API workers
# Edit docker-compose.yml:
# CMD ["uvicorn", "main:app", "--workers", "2"]
```

### Network Issues

```bash
# Inspect network
docker network inspect backup_backup-network

# Recreate network
docker-compose down
docker network prune
docker-compose up -d
```

---

## 📚 Additional Resources

- [Docker Documentation](https://docs.docker.com/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [MySQL Docker Hub](https://hub.docker.com/_/mysql)

---

## 🤝 Support

For issues and questions:
- GitHub Issues: https://github.com/vichai-dsss2000/longterm-backup-config/issues
- Email: vichai.saisood@gmail.com

---

**Last Updated:** November 13, 2025  
**Version:** 1.0.0
