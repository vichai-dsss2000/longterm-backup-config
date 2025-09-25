"""
Simplified FastAPI Application for Frontend Testing
================================================

This is a simplified version of the main FastAPI application that focuses
on core authentication functionality for frontend integration testing.
"""

import logging
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from sqlalchemy import text

from config import settings
from database import engine, Base, get_db
from auth import get_current_user

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management - startup and shutdown events."""
    logger.info("Starting up network device backup system...")
    
    # Initialize database
    try:
        # Create tables if they don't exist
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise
    
    logger.info("Network device backup system startup completed")
    
    yield
    
    # Shutdown
    logger.info("System shutdown completed")


# Create FastAPI application
app = FastAPI(
    title="Network Device Backup Management System",
    description="Comprehensive network device backup system with web-based administration.",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Custom exception handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "message": "Validation error",
            "details": exc.errors(),
            "success": False
        }
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "message": exc.detail,
            "success": False
        }
    )


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with system information."""
    return {
        "message": "Network Device Backup Management System API",
        "version": "1.0.0",
        "status": "running",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "docs": "/api/docs",
    }


# Health check endpoint
@app.get("/api/health")
async def health_check(db: Session = Depends(get_db)):
    """Health check endpoint."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": "connected"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "database": f"error: {str(e)}"
        }


# Include authentication router
from routers.auth_router import router as auth_router
app.include_router(auth_router, prefix="/api/auth", tags=["Authentication"])

# Basic dashboard data endpoints
@app.get("/api/dashboard/stats")
async def dashboard_stats(current_user = Depends(get_current_user)):
    """Get dashboard statistics."""
    return {
        "total_devices": 5,
        "active_devices": 4,
        "total_backups": 150,
        "successful_backups": 142,
        "failed_backups": 8,
        "scheduled_jobs": 12
    }

@app.get("/api/devices/")
async def get_devices(current_user = Depends(get_current_user)):
    """Get devices list."""
    return [
        {
            "id": 1,
            "device_name": "Core Switch 1",
            "ip_address": "192.168.1.10",
            "hostname": "core-switch-01",
            "location": "Data Center A",
            "device_type_id": 1,
            "device_type": {
                "vendor": "Cisco",
                "model": "Catalyst 2960",
                "firmware_version": "15.2(7)E"
            },
            "is_active": True,
            "last_backup_date": "2025-09-25T14:30:00Z",
            "last_backup_status": "success"
        },
        {
            "id": 2,
            "device_name": "Router 1",
            "ip_address": "192.168.1.1", 
            "hostname": "router-01",
            "location": "Network Closet B",
            "device_type_id": 2,
            "device_type": {
                "vendor": "Cisco",
                "model": "ISR 2921",
                "firmware_version": "15.1(4)M"
            },
            "is_active": True,
            "last_backup_date": "2025-09-25T14:25:00Z",
            "last_backup_status": "success"
        }
    ]

@app.get("/api/devices/types")
async def get_device_types(current_user = Depends(get_current_user)):
    """Get available device types."""
    return [
        {
            "id": 1,
            "vendor": "Cisco",
            "model": "Catalyst 2960",
            "firmware_version": "15.2(7)E"
        },
        {
            "id": 2,
            "vendor": "Cisco", 
            "model": "ISR 2921",
            "firmware_version": "15.1(4)M"
        },
        {
            "id": 3,
            "vendor": "Juniper",
            "model": "EX2200",
            "firmware_version": "12.3R11"
        },
        {
            "id": 4,
            "vendor": "MikroTik",
            "model": "RB750",
            "firmware_version": "6.49.8"
        }
    ]

@app.post("/api/devices/")
async def create_device(device_data: dict, current_user = Depends(get_current_user)):
    """Create a new device."""
    # In a real implementation, this would save to database
    new_device = {
        "id": 999,  # Would be auto-generated
        "device_name": device_data.get("device_name"),
        "ip_address": device_data.get("ip_address"),
        "hostname": device_data.get("hostname"),
        "location": device_data.get("location"),
        "device_type_id": device_data.get("device_type_id"),
        "is_active": device_data.get("is_active", True),
        "last_backup_date": None,
        "last_backup_status": None
    }
    return {"message": "Device created successfully", "device": new_device}

@app.put("/api/devices/{device_id}")
async def update_device(device_id: int, device_data: dict, current_user = Depends(get_current_user)):
    """Update an existing device."""
    return {"message": f"Device {device_id} updated successfully"}

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: int, current_user = Depends(get_current_user)):
    """Delete a device."""
    return {"message": f"Device {device_id} deleted successfully"}

@app.post("/api/devices/{device_id}/test-connection")
async def test_device_connection(device_id: int, current_user = Depends(get_current_user)):
    """Test connection to a device."""
    # In a real implementation, this would actually test SSH connection
    return {"success": True, "message": "Connection test successful"}

@app.get("/api/backups/recent")
async def get_recent_backups(current_user = Depends(get_current_user)):
    """Get recent backups."""
    return [
        {
            "id": 1,
            "device_name": "Core Switch 1",
            "status": "completed",
            "backup_start_time": "2025-09-25T14:30:00Z"
        },
        {
            "id": 2,
            "device_name": "Router 1", 
            "status": "completed",
            "backup_start_time": "2025-09-25T14:25:00Z"
        },
        {
            "id": 3,
            "device_name": "Access Switch 3",
            "status": "failed",
            "backup_start_time": "2025-09-25T14:20:00Z",
            "error_message": "Connection timeout"
        }
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main_simple:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )