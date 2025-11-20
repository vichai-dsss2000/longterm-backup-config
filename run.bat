# ลบ container/images เก่า
docker-compose down --rmi all

# Build ใหม่
docker-compose build

# รัน
docker-compose up -d

# ตรวจสอบ logs
docker-compose logs -f api