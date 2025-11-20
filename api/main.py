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
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from sqlalchemy.orm import Session
from sqlalchemy import text
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from config import settings
import os
from database import engine, Base, get_db
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

# Add scripts directory to Python path
scripts_path = Path(__file__).parent.parent / "scripts"
if str(scripts_path) not in sys.path:
    sys.path.insert(0, str(scripts_path))

# Import script modules directly (not as packages) with fallback
try:
    from ssh_connection import SSHConnectionManager
except ImportError:
    logger.warning("ssh_connection module not found - SSH features disabled")
    SSHConnectionManager = None

try:
    from template_processor import BackupCommandTemplateManager
except ImportError:
    logger.warning("template_processor module not found")
    BackupCommandTemplateManager = None

try:
    from backup_executor import DeviceBackupExecutor
except ImportError:
    logger.warning("backup_executor module not found")
    DeviceBackupExecutor = None

try:
    from job_scheduler import BackupScheduler
except ImportError:
    logger.warning("job_scheduler module not found")
    BackupScheduler = None

try:
    from error_handling import error_manager
except ImportError:
    logger.warning("error_handling module not found - using fallback")
    error_manager = None

try:
    from device_discovery import DeviceDiscoveryManager
except ImportError:
    logger.warning("device_discovery module not found")
    DeviceDiscoveryManager = None

try:
    from file_storage import storage_manager
except ImportError:
    logger.warning("file_storage module not found")
    storage_manager = None

try:
    from test_validation import SystemHealthMonitor, test_runner
except ImportError:
    logger.warning("test_validation module not found")
    SystemHealthMonitor = None
    test_runner = None

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

# Initialize rate limiter
limiter = Limiter(
	key_func=get_remote_address,
	default_limits=[f"{settings.rate_limit_times}/{settings.rate_limit_seconds}seconds"],
	enabled=settings.rate_limit_enabled
)

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
		# Allow skipping heavy script/module initialization in dev/test by setting
		# the environment variable DEV_SKIP_MANAGERS=1. This avoids SSH attempts
		# and scheduler work when running tests or the frontend dev server.
		if os.getenv('DEV_SKIP_MANAGERS'):
			logger.info("DEV_SKIP_MANAGERS set — skipping initialization of managers (ssh, scheduler, etc.)")
		else:
			# Initialize SSH connection manager
			if SSHConnectionManager:
				ssh_manager = SSHConnectionManager(
					max_concurrent_connections=20,
					use_connection_pool=True
				)
				logger.info("SSH connection manager initialized")

			# Initialize template processor
			if BackupCommandTemplateManager:
				template_manager = BackupCommandTemplateManager()
				logger.info("Template processor initialized")

			# Initialize backup executor
			if DeviceBackupExecutor:
				backup_executor = DeviceBackupExecutor(
					max_concurrent_jobs=settings.max_concurrent_backups,
					storage_path="/tmp/network_backups"
				)
				logger.info("Backup executor initialized")

			# Initialize job scheduler
			if BackupScheduler:
				job_scheduler = BackupScheduler(
					database_url=settings.database_url,
					max_workers=settings.max_concurrent_backups,
					storage_path="/tmp/backups"
				)
				job_scheduler.start_scheduler()
				logger.info("Job scheduler started")

			# Initialize device discovery manager
			if DeviceDiscoveryManager:
				device_discovery = DeviceDiscoveryManager()
				logger.info("Device discovery manager initialized")

			# Initialize health monitor
			if SystemHealthMonitor:
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
	description="""
	## Comprehensive REST API for Network Device Backup Automation
	
	This API provides complete functionality for managing network device backups including:
	
	* **Authentication**: JWT-based user authentication and authorization
	* **Device Management**: CRUD operations for network devices and device types
	* **Backup Templates**: Manage backup command templates for different vendors
	* **Scheduler**: Configure and manage backup job schedules with cron expressions
	* **Backup Execution**: Execute and monitor backup jobs
	* **Discovery**: Network device discovery and inventory management
	* **Monitoring**: System health checks and performance monitoring
	
	### Authentication
	Most endpoints require JWT authentication. Use the `/api/auth/login` endpoint to obtain a token.
	
	### Base URL
	All API endpoints are prefixed with `/api/`
	""",
	version="1.0.0",
	docs_url=None,  # Disable default to create custom routes
	redoc_url=None,  # Disable default to create custom routes
	openapi_url="/api/openapi.json",
	lifespan=lifespan,
	contact={
		"name": "Network Backup System Support",
		"email": "admin@example.com",
	},
	license_info={
		"name": "MIT License",
		"url": "https://opensource.org/licenses/MIT",
	},
	servers=[
		{
			"url": "http://localhost:8000",
			"description": "Development server"
		},
		{
			"url": "https://api.example.com",
			"description": "Production server"
		}
	]
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add middleware - CORS must be configured before other middleware
# Configure CORS based on environment
cors_origins = settings.cors_origins.split(",") if settings.cors_origins else []
if settings.environment == "development":
	# Allow all origins in development
	cors_origins = ["*"]

app.add_middleware(
	CORSMiddleware,
	allow_origins=cors_origins,
	allow_credentials=True,
	allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
	allow_headers=["*"],
	expose_headers=["*"],
	max_age=3600,
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
		"documentation": {
			"swagger_ui": "/api/docs",
			"redoc": "/api/redoc",
			"openapi_json": "/api/openapi.json"
		},
		"endpoints": {
			"health": "/api/health",
			"authentication": "/api/auth",
			"devices": "/api/devices",
			"templates": "/api/templates",
			"schedules": "/api/schedules",
			"backups": "/api/backups",
			"monitoring": "/api/monitoring",
			"discovery": "/api/discovery"
		}
	}


# Custom Swagger UI route
@app.get("/api/docs", include_in_schema=False)
async def custom_swagger_ui_html():
	"""Custom Swagger UI documentation page."""
	return get_swagger_ui_html(
		openapi_url="/api/openapi.json",
		title=app.title + " - Swagger UI",
		oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
		swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
		swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
		swagger_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
	)


# Custom ReDoc route
@app.get("/api/redoc", include_in_schema=False)
async def custom_redoc_html():
	"""Custom ReDoc documentation page."""
	return get_redoc_html(
		openapi_url="/api/openapi.json",
		title=app.title + " - ReDoc",
		redoc_js_url="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js",
		redoc_favicon_url="https://fastapi.tiangolo.com/img/favicon.png",
	)


# Redirect /docs to /api/docs
@app.get("/docs", include_in_schema=False)
async def redirect_docs():
	"""Redirect /docs to /api/docs."""
	return RedirectResponse(url="/api/docs")


# Redirect /redoc to /api/redoc
@app.get("/redoc", include_in_schema=False)
async def redirect_redoc():
	"""Redirect /redoc to /api/redoc."""
	return RedirectResponse(url="/api/redoc")


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


# Custom OpenAPI schema with additional information
def custom_openapi():
	"""Generate custom OpenAPI schema with enhanced documentation."""
	if app.openapi_schema:
		return app.openapi_schema
	
	openapi_schema = get_openapi(
		title=app.title,
		version=app.version,
		description=app.description,
		routes=app.routes,
		servers=app.servers,
		contact=app.contact,
		license_info=app.license_info,
	)
	
	# Add security schemes
	openapi_schema["components"]["securitySchemes"] = {
		"Bearer": {
			"type": "http",
			"scheme": "bearer",
			"bearerFormat": "JWT",
			"description": "Enter your JWT token in the format: Bearer <token>"
		}
	}
	
	# Add tags metadata with descriptions
	openapi_schema["tags"] = [
		{
			"name": "Root",
			"description": "Root endpoints and system information"
		},
		{
			"name": "Health",
			"description": "Health check and system status endpoints"
		},
		{
			"name": "Authentication",
			"description": "User authentication, login, logout, and JWT token management"
		},
		{
			"name": "Devices",
			"description": "Network device management - CRUD operations for devices and device types"
		},
		{
			"name": "Templates",
			"description": "Backup command template management for different device vendors and models"
		},
		{
			"name": "Schedules",
			"description": "Backup job scheduling with cron expressions and policy management"
		},
		{
			"name": "Backups",
			"description": "Backup execution, history, and file management"
		},
		{
			"name": "Monitoring",
			"description": "System monitoring, performance metrics, and health checks"
		},
		{
			"name": "Discovery",
			"description": "Network device discovery and automated inventory management"
		}
	]
	
	app.openapi_schema = openapi_schema
	return app.openapi_schema


app.openapi = custom_openapi


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
	
except Exception as e:
	logger.error(f"CRITICAL: Failed to import API routers: {e}", exc_info=True)
	raise


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