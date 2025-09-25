from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from config import settings

app = FastAPI(
    title="Network Device Backup Management System - Test",
    description="Basic test version of the backup system API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc"
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Network Device Backup Management System API", "status": "running"}

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "Network Device Backup Management System",
        "version": "1.0.0"
    }

@app.get("/api/health")
async def api_health():
    return {
        "database": "connected",
        "api": "running",
        "timestamp": "2025-09-25T00:00:00Z"
    }