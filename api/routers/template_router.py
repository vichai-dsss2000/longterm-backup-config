"""
Template Management Router
========================

Handles backup command template CRUD operations and validation.
Integrates with scripts/template_processor.py for template processing and validation.
"""

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import and_

from database import get_db, BackupCommandTemplate, DeviceType
from schemas import (
    BackupCommandTemplateCreate, BackupCommandTemplateUpdate, 
    BackupCommandTemplateResponse, MessageResponse
)
from auth import get_current_user, get_admin_user

# Import script modules
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.template_processor import BackupCommandTemplateManager
from scripts.test_validation import TemplateValidator

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize template manager and validator
template_manager = BackupCommandTemplateManager()
template_validator = TemplateValidator()


@router.get("/", response_model=List[BackupCommandTemplateResponse])
async def get_templates(
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    device_type_id: Optional[int] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get list of backup command templates with filtering options."""
    query = db.query(BackupCommandTemplate).options(
        joinedload(BackupCommandTemplate.device_type)
    )
    
    # Apply filters
    if active_only:
        query = query.filter(BackupCommandTemplate.is_active == True)
    
    if device_type_id:
        query = query.filter(BackupCommandTemplate.device_type_id == device_type_id)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            BackupCommandTemplate.template_name.ilike(search_term) |
            BackupCommandTemplate.template_description.ilike(search_term) |
            BackupCommandTemplate.backup_command.ilike(search_term)
        )
    
    templates = query.offset(skip).limit(limit).all()
    
    return [
        BackupCommandTemplateResponse(
            **{key: getattr(template, key) 
               for key in BackupCommandTemplateResponse.__annotations__.keys() 
               if hasattr(template, key)}
        )
        for template in templates
    ]


@router.post("/", response_model=BackupCommandTemplateResponse)
async def create_template(
    template_data: BackupCommandTemplateCreate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Create a new backup command template."""
    # Verify device type exists
    device_type = db.query(DeviceType).filter(
        DeviceType.id == template_data.device_type_id
    ).first()
    if not device_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device type not found"
        )
    
    # Check for duplicate template name for the same device type
    existing_template = db.query(BackupCommandTemplate).filter(
        and_(
            BackupCommandTemplate.device_type_id == template_data.device_type_id,
            BackupCommandTemplate.template_name == template_data.template_name,
            BackupCommandTemplate.version == template_data.version
        )
    ).first()
    
    if existing_template:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Template with same name and version already exists for this device type"
        )
    
    # Validate template syntax
    try:
        template_dict = {
            'id': 0,  # Temporary ID for validation
            'template_name': template_data.template_name,
            'backup_command': template_data.backup_command,
            'command_format': template_data.command_format,
            'template_variables': template_data.template_variables or {}
        }
        
        validation_result = template_validator.validate_template_syntax(template_dict)
        
        if validation_result.status.value != "passed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Template validation failed: {validation_result.error_message}"
            )
    
    except Exception as e:
        logger.error(f"Template validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Template validation failed: {str(e)}"
        )
    
    # Create template
    new_template = BackupCommandTemplate(
        device_type_id=template_data.device_type_id,
        template_name=template_data.template_name,
        template_description=template_data.template_description,
        backup_command=template_data.backup_command,
        command_format=template_data.command_format,
        template_variables=template_data.template_variables,
        timeout_seconds=template_data.timeout_seconds,
        retry_count=template_data.retry_count,
        retry_interval_seconds=template_data.retry_interval_seconds,
        version=template_data.version,
        created_by=current_user.id
    )
    
    db.add(new_template)
    db.commit()
    db.refresh(new_template)
    
    logger.info(f"Created new template: {new_template.template_name} for device type {device_type.vendor} {device_type.model}")
    
    return BackupCommandTemplateResponse(
        **{key: getattr(new_template, key) 
           for key in BackupCommandTemplateResponse.__annotations__.keys() 
           if hasattr(new_template, key)}
    )


@router.get("/{template_id}", response_model=BackupCommandTemplateResponse)
async def get_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get specific template by ID."""
    template = db.query(BackupCommandTemplate).options(
        joinedload(BackupCommandTemplate.device_type)
    ).filter(BackupCommandTemplate.id == template_id).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    return BackupCommandTemplateResponse(
        **{key: getattr(template, key) 
           for key in BackupCommandTemplateResponse.__annotations__.keys() 
           if hasattr(template, key)}
    )


@router.put("/{template_id}", response_model=BackupCommandTemplateResponse)
async def update_template(
    template_id: int,
    template_data: BackupCommandTemplateUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Update existing template."""
    template = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.id == template_id
    ).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    # Check for conflicts if name or version is being changed
    update_data = template_data.dict(exclude_unset=True)
    
    if 'template_name' in update_data or 'version' in update_data:
        template_name = update_data.get('template_name', template.template_name)
        version = update_data.get('version', template.version)
        
        existing_template = db.query(BackupCommandTemplate).filter(
            and_(
                BackupCommandTemplate.id != template_id,
                BackupCommandTemplate.device_type_id == template.device_type_id,
                BackupCommandTemplate.template_name == template_name,
                BackupCommandTemplate.version == version
            )
        ).first()
        
        if existing_template:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Another template with same name and version already exists for this device type"
            )
    
    # Validate template if backup_command is being updated
    if 'backup_command' in update_data:
        try:
            template_dict = {
                'id': template_id,
                'template_name': update_data.get('template_name', template.template_name),
                'backup_command': update_data['backup_command'],
                'command_format': update_data.get('command_format', template.command_format),
                'template_variables': update_data.get('template_variables', template.template_variables) or {}
            }
            
            validation_result = template_validator.validate_template_syntax(template_dict)
            
            if validation_result.status.value != "passed":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Template validation failed: {validation_result.error_message}"
                )
        
        except Exception as e:
            logger.error(f"Template validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Template validation failed: {str(e)}"
            )
    
    # Update template fields
    for field, value in update_data.items():
        if hasattr(template, field):
            setattr(template, field, value)
    
    db.commit()
    db.refresh(template)
    
    logger.info(f"Updated template: {template.template_name} (ID: {template_id})")
    
    return BackupCommandTemplateResponse(
        **{key: getattr(template, key) 
           for key in BackupCommandTemplateResponse.__annotations__.keys() 
           if hasattr(template, key)}
    )


@router.delete("/{template_id}", response_model=MessageResponse)
async def delete_template(
    template_id: int,
    db: Session = Depends(get_db),
    current_user = Depends(get_admin_user)
):
    """Delete template (soft delete by setting is_active=False)."""
    template = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.id == template_id
    ).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    # Check if template is being used by any schedule policies
    from database import JobSchedulePolicy
    active_policies = db.query(JobSchedulePolicy).filter(
        and_(
            JobSchedulePolicy.template_id == template_id,
            JobSchedulePolicy.is_active == True
        )
    ).count()
    
    if active_policies > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot delete template. It is being used by {active_policies} active schedule policies."
        )
    
    # Soft delete
    template.is_active = False
    db.commit()
    
    logger.info(f"Soft deleted template: {template.template_name} (ID: {template_id})")
    
    return MessageResponse(message="Template deleted successfully")


@router.post("/{template_id}/validate")
async def validate_template(
    template_id: int,
    test_device_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Validate template syntax and test processing."""
    template = db.query(BackupCommandTemplate).options(
        joinedload(BackupCommandTemplate.device_type)
    ).filter(BackupCommandTemplate.id == template_id).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    try:
        # Convert to dict for validation
        template_dict = {
            'id': template.id,
            'template_name': template.template_name,
            'backup_command': template.backup_command,
            'command_format': template.command_format,
            'template_variables': template.template_variables or {}
        }
        
        # Syntax validation
        syntax_result = template_validator.validate_template_syntax(template_dict)
        
        validation_results = {
            'template_id': template_id,
            'template_name': template.template_name,
            'validation_results': {
                'syntax_validation': {
                    'status': syntax_result.status.value,
                    'message': syntax_result.error_message or "Syntax validation passed",
                    'details': syntax_result.details,
                    'warnings': syntax_result.warnings,
                    'recommendations': syntax_result.recommendations
                }
            }
        }
        
        # Test processing if test device provided
        if test_device_id:
            from database import NetworkDevice
            test_device = db.query(NetworkDevice).options(
                joinedload(NetworkDevice.device_type)
            ).filter(NetworkDevice.id == test_device_id).first()
            
            if test_device:
                test_device_info = {
                    'id': test_device.id,
                    'device_name': test_device.device_name,
                    'ip_address': test_device.ip_address,
                    'hostname': test_device.hostname or test_device.device_name
                }
                
                processing_result = template_validator.test_template_processing(
                    template_dict, test_device_info
                )
                
                validation_results['validation_results']['processing_test'] = {
                    'status': processing_result.status.value,
                    'message': processing_result.error_message or "Processing test passed",
                    'details': processing_result.details,
                    'warnings': processing_result.warnings,
                    'recommendations': processing_result.recommendations
                }
        
        return validation_results
    
    except Exception as e:
        logger.error(f"Template validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template validation failed: {str(e)}"
        )


@router.post("/{template_id}/preview")
async def preview_template_processing(
    template_id: int,
    device_id: int,
    custom_variables: Optional[dict] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Preview template processing with actual device data."""
    template = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.id == template_id
    ).first()
    
    if not template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Template not found"
        )
    
    from database import NetworkDevice
    device = db.query(NetworkDevice).options(
        joinedload(NetworkDevice.device_type)
    ).filter(NetworkDevice.id == device_id).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found"
        )
    
    # Check if device type matches template
    if device.device_type_id != template.device_type_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device type does not match template device type"
        )
    
    try:
        # Prepare device info
        device_info = {
            'id': device.id,
            'device_name': device.device_name,
            'ip_address': device.ip_address,
            'hostname': device.hostname or device.device_name,
            'management_ip': device.management_ip or device.ip_address
        }
        
        # Prepare template data
        template_data = {
            'id': template.id,
            'template_name': template.template_name,
            'backup_command': template.backup_command,
            'command_format': template.command_format,
            'template_variables': template.template_variables or {}
        }
        
        # Use custom variables or defaults
        user_variables = custom_variables or {
            'backup_path': '/tmp/preview',
            'sftp_server_ip': '192.168.1.200',
            'sftp_username': 'backup_user'
        }
        
        # Process template
        result = template_manager.process_backup_command(
            template_data, device_info, user_variables
        )
        
        return {
            'template_id': template_id,
            'device_id': device_id,
            'processing_result': {
                'success': result.success,
                'processed_content': result.processed_content if result.success else None,
                'error_message': result.error_message,
                'variables_used': dict(result.variables_used) if result.success else {},
                'warnings': result.warnings,
                'processing_time': result.processing_time
            },
            'preview_info': {
                'template_name': template.template_name,
                'device_name': device.device_name,
                'command_format': template.command_format,
                'user_variables': user_variables
            }
        }
    
    except Exception as e:
        logger.error(f"Template preview error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Template preview failed: {str(e)}"
        )


@router.get("/device-type/{device_type_id}")
async def get_templates_by_device_type(
    device_type_id: int,
    active_only: bool = True,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    """Get all templates for a specific device type."""
    # Verify device type exists
    device_type = db.query(DeviceType).filter(DeviceType.id == device_type_id).first()
    if not device_type:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device type not found"
        )
    
    query = db.query(BackupCommandTemplate).filter(
        BackupCommandTemplate.device_type_id == device_type_id
    )
    
    if active_only:
        query = query.filter(BackupCommandTemplate.is_active == True)
    
    templates = query.all()
    
    return {
        'device_type': {
            'id': device_type.id,
            'vendor': device_type.vendor,
            'model': device_type.model,
            'firmware_version': device_type.firmware_version,
            'netmiko_device_type': device_type.netmiko_device_type
        },
        'template_count': len(templates),
        'templates': [
            {
                'id': template.id,
                'template_name': template.template_name,
                'template_description': template.template_description,
                'command_format': template.command_format,
                'version': template.version,
                'is_active': template.is_active,
                'created_at': template.created_at
            }
            for template in templates
        ]
    }