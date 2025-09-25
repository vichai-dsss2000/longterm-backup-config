"""
Main FastAPI Application
=======================

This is the main FastAPI application entry point that integrates all the
network device backup system components including the script modules,
database models, and REST API endpoints.

Features:
- FastAPI app with middleware and CORS configuration
- Database connection and session management
- Script modules initialization and lifecycle management
- Route registration for all API endpoints
- Background task management and scheduling
- Error handling and logging configuration
- Health checks and system monitoring
"""

import logging
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session
from sqlalchemy import text

from config import settings
from database import engine, Base, get_db
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path

# Add scripts directory to Python path
scripts_path = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(scripts_path))

# Import script modules directly (not as packages)
from ssh_connection import SSHConnectionManager
from template_processor import BackupCommandTemplateManager
from backup_executor import DeviceBackupExecutor
from job_scheduler import BackupScheduler
from error_handling import error_manager
from device_discovery import DeviceDiscoveryManager
from file_storage import storage_manager
from test_validation import SystemHealthMonitor, test_runner

# Configure logging
logging.basicConfig(
	level=getattr(logging, settings.log_level.upper()),
	format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
	handlers=[
		logging.FileHandler('/tmp/backup_system.log'),
		logging.StreamHandler()
	]
)
logger = logging.getLogger(__name__)

# Global instances for script modules
ssh_manager = None
template_manager = None
backup_executor = None
job_scheduler = None
device_discovery = None
health_monitor = None


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
	
	# Initialize script modules
	global ssh_manager, template_manager, backup_executor, job_scheduler
	global device_discovery, health_monitor
	
	try:
		# Initialize SSH connection manager
		ssh_manager = SSHConnectionManager(
			max_concurrent_connections=20,
			use_connection_pool=True
		)
		logger.info("SSH connection manager initialized")
		
		# Initialize template processor
		template_manager = BackupCommandTemplateManager()
		logger.info("Template processor initialized")
		
		# Initialize backup executor
		backup_executor = DeviceBackupExecutor(
			max_concurrent_jobs=settings.max_concurrent_backups,
			storage_path="/tmp/network_backups"
		)
		logger.info("Backup executor initialized")
		
		# Initialize job scheduler
		job_scheduler = BackupScheduler(
			database_url=settings.database_url,
			max_workers=settings.max_concurrent_backups,
			storage_path="/tmp/backups"
		)
		job_scheduler.start_scheduler()
		logger.info("Job scheduler started")
		
		# Initialize device discovery manager
		device_discovery = DeviceDiscoveryManager()
		logger.info("Device discovery manager initialized")
		
		# Initialize health monitor
		health_monitor = SystemHealthMonitor()
		logger.info("System health monitor initialized")
		
		# Initialize storage manager with configuration
		# storage_manager.configure_backend(
		#     backend_name="sftp_default",
		#     backend_type="sftp",
		#     config={
		#         'host': settings.default_sftp_server,
		#         'username': settings.default_sftp_username,
		#         'password': settings.default_sftp_password,
		#         'port': settings.default_sftp_port,
		#         'base_path': settings.default_backup_path
		#     }
		# )
		logger.info("Storage manager configured")
		
		# Load existing scheduled jobs from database
		# await job_scheduler.load_jobs_from_database()
		# logger.info("Scheduled jobs loaded from database")
		
		logger.info("All script modules initialized successfully")
		
	except Exception as e:
		logger.error(f"Script modules initialization failed: {e}")
		raise
	
	# Application is ready
	logger.info("Network device backup system startup completed")
	
	yield
	
	# Shutdown
	logger.info("Shutting down network device backup system...")
	
	try:
		# Shutdown job scheduler
		if job_scheduler:
			await job_scheduler.shutdown()
			logger.info("Job scheduler shutdown completed")
		
		# Shutdown backup executor
		if backup_executor:
			backup_executor.shutdown()
			logger.info("Backup executor shutdown completed")
		
		# Close SSH connections
		if ssh_manager:
			ssh_manager.close_all_connections()
			logger.info("SSH connections closed")
		
		logger.info("System shutdown completed")
		
	except Exception as e:
		logger.error(f"Error during shutdown: {e}")


# Create FastAPI application
app = FastAPI(
	title="Network Device Backup Management System",
	description="Comprehensive network device backup system with web-based administration, "
				"automated scheduling, and multi-vendor device support.",
	version="1.0.0",
	docs_url="/api/docs",
	redoc_url="/api/redoc",
	openapi_url="/api/openapi.json",
	lifespan=lifespan
)

# Add middleware
app.add_middleware(
	CORSMiddleware,
	allow_origins=settings.cors_origins.split(","),
	allow_credentials=True,
	allow_methods=["*"],
	allow_headers=["*"],
)

app.add_middleware(
	TrustedHostMiddleware,
	allowed_hosts=["*"]  # Configure appropriately for production
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


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
	"""Handle general exceptions."""
	logger.error(f"Unhandled exception: {exc}", exc_info=True)
	return JSONResponse(
		status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
		content={
			"message": "Internal server error",
			"success": False
		}
	)


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
	"""Root endpoint with system information."""
	return {
		"message": "Network Device Backup Management System API",
		"version": "1.0.0",
		"status": "running",
		"timestamp": datetime.now(timezone.utc).isoformat(),
		"docs": "/api/docs",
		"health": "/api/health"
	}


# Health check endpoint
@app.get("/api/health", tags=["Health"])
async def health_check(db: Session = Depends(get_db)):
	"""Comprehensive health check endpoint."""
	health_status = {
		"status": "healthy",
		"timestamp": datetime.now(timezone.utc).isoformat(),
		"components": {},
		"version": "1.0.0"
	}
	
	# Check database connectivity
	try:
		db.execute(text("SELECT 1"))
		health_status["components"]["database"] = {
			"status": "healthy",
			"message": "Database connection successful"
		}
	except Exception as e:
		health_status["components"]["database"] = {
			"status": "unhealthy",
			"message": f"Database connection failed: {str(e)}"
		}
		health_status["status"] = "unhealthy"
	
	# Check script modules
	components_to_check = [
		("ssh_manager", ssh_manager),
		("template_manager", template_manager),
		("backup_executor", backup_executor),
		("job_scheduler", job_scheduler),
		("device_discovery", device_discovery),
		("health_monitor", health_monitor)
	]
	
	for component_name, component in components_to_check:
		if component is not None:
			health_status["components"][component_name] = {
				"status": "healthy",
				"message": f"{component_name} is initialized"
			}
		else:
			health_status["components"][component_name] = {
				"status": "unhealthy",
				"message": f"{component_name} is not initialized"
			}
			health_status["status"] = "unhealthy"
	
	# Check job scheduler status specifically
	if job_scheduler and hasattr(job_scheduler, 'scheduler'):
		if job_scheduler.scheduler.running:
			health_status["components"]["scheduler_status"] = {
				"status": "healthy",
				"message": "Job scheduler is running",
				"running_jobs": len(job_scheduler.scheduler.get_jobs())
			}
		else:
			health_status["components"]["scheduler_status"] = {
				"status": "warning",
				"message": "Job scheduler is not running"
			}
	
	return health_status


# Quick health check for load balancers
@app.get("/api/health/quick", tags=["Health"])
async def quick_health_check():
	"""Quick health check for load balancers."""
	return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}


# System status endpoint
@app.get("/api/system/status", tags=["System"], dependencies=[Depends(get_current_user)])
async def system_status():
	"""Get detailed system status information."""
	if not health_monitor:
		raise HTTPException(
			status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
			detail="Health monitor not available"
		)
	
	try:
		status_info = health_monitor.run_quick_health_check()
		return status_info
	except Exception as e:
		logger.error(f"System status check failed: {e}")
		raise HTTPException(
			status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
			detail="Failed to retrieve system status"
		)


# Import and include routers (will be created in subsequent files)
# Note: These imports will be added as we create the endpoint files

try:
	from routers import auth_router, device_router, template_router, backup_router
	from routers import schedule_router, monitoring_router, discovery_router
	
	# Include routers
	app.include_router(auth_router.router, prefix="/api/auth", tags=["Authentication"])
	app.include_router(device_router.router, prefix="/api/devices", tags=["Devices"])
	app.include_router(template_router.router, prefix="/api/templates", tags=["Templates"])
	app.include_router(backup_router.router, prefix="/api/backups", tags=["Backups"])
	app.include_router(schedule_router.router, prefix="/api/schedules", tags=["Schedules"])
	app.include_router(monitoring_router.router, prefix="/api/monitoring", tags=["Monitoring"])
	app.include_router(discovery_router.router, prefix="/api/discovery", tags=["Discovery"])
	
	logger.info("All API routers registered successfully")
	
except ImportError as e:
	logger.warning(f"Some API routers not available yet: {e}")
	# This is expected during initial setup - routers will be created progressively


# WebSocket endpoint for real-time updates (optional)
@app.websocket("/api/ws")
async def websocket_endpoint(websocket):
	"""WebSocket endpoint for real-time system updates."""
	await websocket.accept()
	try:
		while True:
			# Send periodic status updates
			if health_monitor:
				status = health_monitor.run_quick_health_check()
				await websocket.send_json(status)
			
			await asyncio.sleep(30)  # Send updates every 30 seconds
	except Exception as e:
		logger.error(f"WebSocket error: {e}")
	finally:
		await websocket.close()


if __name__ == "__main__":
	import uvicorn
	
	# Development server configuration
	uvicorn.run(
		"main:app",
		host="0.0.0.0",
		port=8000,
		reload=True,
		log_level=settings.log_level.lower(),
		access_log=True
	)