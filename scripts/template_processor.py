"""
Template Processing Engine for Network Device Backup System
==========================================================

This module provides template variable substitution and command processing
for backup operations. It supports dynamic variable replacement, conditional
logic, and multiple output formats (TEXT, JSON, XML, YAML).

Features:
- Dynamic variable substitution with context-aware replacement
- Template validation and syntax checking
- Support for conditional logic and loops
- Multiple output format handling
- Built-in variables (timestamp, device info, etc.)
- Custom variable definitions and defaults
- Template inheritance and inclusion
- Secure variable handling and sanitization
"""

import logging
import json
import yaml
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, field
from pathlib import Path
import re
import hashlib
from string import Template
from jinja2 import Environment, BaseLoader, select_autoescape, TemplateError
from jinja2.sandbox import SandboxedEnvironment

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class TemplateVariable:
	"""Definition of a template variable."""
	name: str
	description: str
	default_value: Optional[str] = None
	required: bool = True
	variable_type: str = "string"  # string, integer, boolean, datetime, ip_address
	validation_pattern: Optional[str] = None
	allowed_values: Optional[List[str]] = None


@dataclass
class TemplateContext:
	"""Context data for template processing."""
	device_info: Dict[str, Any] = field(default_factory=dict)
	user_variables: Dict[str, Any] = field(default_factory=dict)
	system_variables: Dict[str, Any] = field(default_factory=dict)
	template_variables: List[TemplateVariable] = field(default_factory=list)
	
	def get_all_variables(self) -> Dict[str, Any]:
		"""Get all variables merged with proper precedence."""
		variables = {}
		
		# Start with system variables (lowest precedence)
		variables.update(self.system_variables)
		
		# Add device info
		variables.update(self.device_info)
		
		# Add user variables (highest precedence)
		variables.update(self.user_variables)
		
		return variables


@dataclass
class ProcessedTemplate:
	"""Result of template processing."""
	success: bool
	processed_content: Optional[str] = None
	original_content: str = ""
	variables_used: Dict[str, Any] = field(default_factory=dict)
	error_message: Optional[str] = None
	warnings: List[str] = field(default_factory=list)
	processing_time: float = 0.0
	output_format: str = "TEXT"


class TemplateVariableValidator:
	"""Validator for template variables."""
	
	@staticmethod
	def validate_ip_address(value: str) -> bool:
		"""Validate IP address format."""
		import ipaddress
		try:
			ipaddress.ip_address(value)
			return True
		except ValueError:
			return False
	
	@staticmethod
	def validate_pattern(value: str, pattern: str) -> bool:
		"""Validate value against regex pattern."""
		try:
			return bool(re.match(pattern, value))
		except re.error:
			return False
	
	def validate_variable(self, var_def: TemplateVariable, value: Any) -> Tuple[bool, Optional[str]]:
		"""Validate a variable value against its definition."""
		if value is None:
			if var_def.required:
				return False, f"Required variable '{var_def.name}' is missing"
			return True, None
		
		# Convert value to string for validation
		str_value = str(value)
		
		# Type validation
		if var_def.variable_type == "integer":
			try:
				int(str_value)
			except ValueError:
				return False, f"Variable '{var_def.name}' must be an integer"
		
		elif var_def.variable_type == "boolean":
			if str_value.lower() not in ["true", "false", "1", "0", "yes", "no"]:
				return False, f"Variable '{var_def.name}' must be a boolean value"
		
		elif var_def.variable_type == "ip_address":
			if not self.validate_ip_address(str_value):
				return False, f"Variable '{var_def.name}' must be a valid IP address"
		
		# Pattern validation
		if var_def.validation_pattern:
			if not self.validate_pattern(str_value, var_def.validation_pattern):
				return False, f"Variable '{var_def.name}' does not match required pattern"
		
		# Allowed values validation
		if var_def.allowed_values:
			if str_value not in var_def.allowed_values:
				return False, f"Variable '{var_def.name}' must be one of: {var_def.allowed_values}"
		
		return True, None


class TemplateProcessor:
	"""Main template processing engine."""
	
	def __init__(self, enable_jinja2: bool = True, sandbox_mode: bool = True):
		self.enable_jinja2 = enable_jinja2
		self.sandbox_mode = sandbox_mode
		self.validator = TemplateVariableValidator()
		
		# Initialize Jinja2 environment
		if self.enable_jinja2:
			if self.sandbox_mode:
				self.jinja_env = SandboxedEnvironment(
					autoescape=select_autoescape(['html', 'xml']),
					trim_blocks=True,
					lstrip_blocks=True
				)
			else:
				self.jinja_env = Environment(
					autoescape=select_autoescape(['html', 'xml']),
					trim_blocks=True,
					lstrip_blocks=True
				)
	
	def _generate_system_variables(self) -> Dict[str, Any]:
		"""Generate built-in system variables."""
		now = datetime.now(timezone.utc)
		
		return {
			'timestamp': now.strftime('%Y%m%d_%H%M%S'),
			'timestamp_iso': now.isoformat(),
			'date': now.strftime('%Y-%m-%d'),
			'time': now.strftime('%H:%M:%S'),
			'year': now.year,
			'month': now.month,
			'day': now.day,
			'hour': now.hour,
			'minute': now.minute,
			'second': now.second,
			'weekday': now.strftime('%A'),
			'uuid': self._generate_uuid(),
		}
	
	def _generate_uuid(self) -> str:
		"""Generate unique identifier for this processing session."""
		import uuid
		return str(uuid.uuid4())
	
	def _sanitize_variable_value(self, value: Any) -> str:
		"""Sanitize variable value for security."""
		if value is None:
			return ""
		
		str_value = str(value)
		
		# Remove potentially dangerous characters
		dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '[', ']']
		for char in dangerous_chars:
			str_value = str_value.replace(char, '')
		
		# Limit length to prevent buffer overflow attacks
		if len(str_value) > 1000:
			str_value = str_value[:1000]
			logger.warning(f"Variable value truncated to 1000 characters for security")
		
		return str_value
	
	def _extract_template_variables(self, template_content: str) -> List[str]:
		"""Extract variable names from template content."""
		variables = set()
		
		# Find Python-style variables {variable_name}
		python_vars = re.findall(r'\{([^}]+)\}', template_content)
		variables.update(python_vars)
		
		# Find Jinja2-style variables {{ variable_name }}
		if self.enable_jinja2:
			jinja_vars = re.findall(r'\{\{\s*([^}|\s]+)(?:\s*\|[^}]*)?\s*\}\}', template_content)
			variables.update(jinja_vars)
		
		return list(variables)
	
	def _validate_template_context(self, context: TemplateContext, 
								 required_variables: List[str]) -> Tuple[bool, List[str]]:
		"""Validate that all required variables are available in context."""
		errors = []
		all_variables = context.get_all_variables()
		
		# Validate template-defined variables
		for var_def in context.template_variables:
			value = all_variables.get(var_def.name)
			is_valid, error_msg = self.validator.validate_variable(var_def, value)
			if not is_valid:
				errors.append(error_msg)
		
		# Check for missing required variables found in template
		for var_name in required_variables:
			if var_name not in all_variables:
				errors.append(f"Required variable '{var_name}' not found in context")
		
		return len(errors) == 0, errors
	
	def _process_simple_substitution(self, template_content: str, 
								   context: TemplateContext) -> ProcessedTemplate:
		"""Process template using simple string substitution."""
		start_time = datetime.now()
		
		try:
			all_variables = context.get_all_variables()
			system_variables = self._generate_system_variables()
			all_variables.update(system_variables)
			
			# Sanitize variable values
			sanitized_vars = {
				key: self._sanitize_variable_value(value)
				for key, value in all_variables.items()
			}
			
			# Use Python string Template for safe substitution
			template = Template(template_content)
			processed_content = template.safe_substitute(sanitized_vars)
			
			# Check for remaining unreplaced variables
			remaining_vars = re.findall(r'\$\{([^}]+)\}', processed_content)
			warnings = []
			if remaining_vars:
				warnings.append(f"Unreplaced variables found: {remaining_vars}")
			
			processing_time = (datetime.now() - start_time).total_seconds()
			
			return ProcessedTemplate(
				success=True,
				processed_content=processed_content,
				original_content=template_content,
				variables_used=sanitized_vars,
				warnings=warnings,
				processing_time=processing_time
			)
			
		except Exception as e:
			processing_time = (datetime.now() - start_time).total_seconds()
			logger.error(f"Error in simple template processing: {e}")
			
			return ProcessedTemplate(
				success=False,
				original_content=template_content,
				error_message=str(e),
				processing_time=processing_time
			)
	
	def _process_jinja2_template(self, template_content: str, 
							   context: TemplateContext) -> ProcessedTemplate:
		"""Process template using Jinja2 engine."""
		start_time = datetime.now()
		
		try:
			all_variables = context.get_all_variables()
			system_variables = self._generate_system_variables()
			all_variables.update(system_variables)
			
			# Create Jinja2 template
			template = self.jinja_env.from_string(template_content)
			
			# Render template
			processed_content = template.render(all_variables)
			
			processing_time = (datetime.now() - start_time).total_seconds()
			
			return ProcessedTemplate(
				success=True,
				processed_content=processed_content,
				original_content=template_content,
				variables_used=all_variables,
				processing_time=processing_time
			)
			
		except TemplateError as e:
			processing_time = (datetime.now() - start_time).total_seconds()
			logger.error(f"Jinja2 template error: {e}")
			
			return ProcessedTemplate(
				success=False,
				original_content=template_content,
				error_message=f"Template error: {str(e)}",
				processing_time=processing_time
			)
			
		except Exception as e:
			processing_time = (datetime.now() - start_time).total_seconds()
			logger.error(f"Error in Jinja2 template processing: {e}")
			
			return ProcessedTemplate(
				success=False,
				original_content=template_content,
				error_message=str(e),
				processing_time=processing_time
			)
	
	def process_template(self, template_content: str, context: TemplateContext,
						output_format: str = "TEXT") -> ProcessedTemplate:
		"""
		Process template with given context and return processed result.
		
		Args:
			template_content: The template string to process
			context: Template context with variables and settings
			output_format: Output format (TEXT, JSON, XML, YAML)
		"""
		# Extract variables from template
		required_variables = self._extract_template_variables(template_content)
		
		# Validate context
		is_valid, validation_errors = self._validate_template_context(context, required_variables)
		if not is_valid:
			return ProcessedTemplate(
				success=False,
				original_content=template_content,
				error_message=f"Template validation failed: {'; '.join(validation_errors)}",
				output_format=output_format
			)
		
		# Choose processing method based on template content
		if self.enable_jinja2 and ('{{' in template_content or '{%' in template_content):
			result = self._process_jinja2_template(template_content, context)
		else:
			result = self._process_simple_substitution(template_content, context)
		
		result.output_format = output_format
		
		# Format output if needed
		if result.success and output_format != "TEXT":
			result = self._format_output(result, output_format)
		
		return result
	
	def _format_output(self, result: ProcessedTemplate, output_format: str) -> ProcessedTemplate:
		"""Format the processed content according to output format."""
		try:
			if output_format == "JSON":
				# Try to parse as JSON to validate
				try:
					parsed = json.loads(result.processed_content)
					result.processed_content = json.dumps(parsed, indent=2)
				except json.JSONDecodeError:
					# If not valid JSON, wrap in a JSON object
					result.processed_content = json.dumps({
						"command_output": result.processed_content
					}, indent=2)
			
			elif output_format == "YAML":
				# Try to parse as YAML to validate
				try:
					parsed = yaml.safe_load(result.processed_content)
					result.processed_content = yaml.dump(parsed, default_flow_style=False)
				except yaml.YAMLError:
					# If not valid YAML, create a YAML document
					result.processed_content = yaml.dump({
						"command_output": result.processed_content
					}, default_flow_style=False)
			
			elif output_format == "XML":
				# Try to parse as XML to validate
				try:
					ET.fromstring(result.processed_content)
				except ET.ParseError:
					# If not valid XML, wrap in XML tags
					result.processed_content = f"<command_output>{result.processed_content}</command_output>"
		
		except Exception as e:
			result.warnings.append(f"Output formatting warning: {str(e)}")
		
		return result
	
	def validate_template_syntax(self, template_content: str) -> Tuple[bool, List[str]]:
		"""Validate template syntax without processing."""
		errors = []
		
		try:
			# Check for balanced braces
			if template_content.count('{') != template_content.count('}'):
				errors.append("Unbalanced braces in template")
			
			# If Jinja2 is enabled, validate Jinja2 syntax
			if self.enable_jinja2 and ('{{' in template_content or '{%' in template_content):
				try:
					self.jinja_env.from_string(template_content)
				except TemplateError as e:
					errors.append(f"Jinja2 syntax error: {str(e)}")
			
			# Validate variable names
			variables = self._extract_template_variables(template_content)
			for var in variables:
				if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', var):
					errors.append(f"Invalid variable name: '{var}'")
		
		except Exception as e:
			errors.append(f"Template validation error: {str(e)}")
		
		return len(errors) == 0, errors


class BackupCommandTemplateManager:
	"""Manager for backup command templates."""
	
	def __init__(self):
		self.processor = TemplateProcessor()
		self.templates_cache: Dict[str, str] = {}
	
	def load_template_from_db(self, template_data: Dict[str, Any]) -> Tuple[str, List[TemplateVariable]]:
		"""Load template content and variables from database record."""
		template_content = template_data.get('backup_command', '')
		
		# Parse template variables from JSON
		variables = []
		if template_data.get('template_variables'):
			try:
				var_definitions = json.loads(template_data['template_variables'])
				for var_name, var_config in var_definitions.items():
					variables.append(TemplateVariable(
						name=var_name,
						description=var_config.get('description', ''),
						default_value=var_config.get('default'),
						required=var_config.get('required', True),
						variable_type=var_config.get('type', 'string'),
						validation_pattern=var_config.get('pattern'),
						allowed_values=var_config.get('allowed_values')
					))
			except (json.JSONDecodeError, KeyError) as e:
				logger.warning(f"Error parsing template variables: {e}")
		
		return template_content, variables
	
	def create_device_context(self, device_info: Dict[str, Any], 
							user_variables: Optional[Dict[str, Any]] = None) -> TemplateContext:
		"""Create template context from device information."""
		context = TemplateContext()
		
		# Device information
		context.device_info = {
			'device_name': device_info.get('device_name', ''),
			'device_ip': device_info.get('ip_address', ''),
			'hostname': device_info.get('hostname', ''),
			'device_type': device_info.get('device_type', ''),
			'location': device_info.get('location', ''),
			'management_ip': device_info.get('management_ip', device_info.get('ip_address', '')),
		}
		
		# SSH connection info
		context.device_info.update({
			'username': device_info.get('ssh_username', ''),
			'ssh_port': device_info.get('ssh_port', 22),
		})
		
		# User-provided variables
		if user_variables:
			context.user_variables = user_variables
		
		return context
	
	def process_backup_command(self, template_data: Dict[str, Any], 
							 device_info: Dict[str, Any],
							 user_variables: Optional[Dict[str, Any]] = None) -> ProcessedTemplate:
		"""Process backup command template for specific device."""
		
		# Load template
		template_content, template_variables = self.load_template_from_db(template_data)
		
		# Create context
		context = self.create_device_context(device_info, user_variables)
		context.template_variables = template_variables
		
		# Add SFTP/backup specific variables
		context.user_variables.update({
			'sftp_server_ip': user_variables.get('sftp_server_ip', ''),
			'sftp_username': user_variables.get('sftp_username', ''),
			'sftp_password': user_variables.get('sftp_password', ''),
			'backup_path': user_variables.get('backup_path', '/backups'),
			'backup_filename': f"{device_info.get('device_name', 'device')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.cfg"
		})
		
		# Process template
		output_format = template_data.get('command_format', 'TEXT')
		result = self.processor.process_template(template_content, context, output_format)
		
		return result


# Example template variable definitions for different device types
CISCO_TEMPLATE_VARIABLES = {
	"sftp_server_ip": {
		"description": "SFTP server IP address",
		"type": "ip_address",
		"required": True
	},
	"sftp_username": {
		"description": "SFTP username",
		"type": "string",
		"required": True
	},
	"sftp_password": {
		"description": "SFTP password",
		"type": "string",
		"required": True
	},
	"backup_path": {
		"description": "Backup directory path on SFTP server",
		"type": "string",
		"default": "/backups",
		"required": False
	}
}

# Example templates for different vendors
TEMPLATE_EXAMPLES = {
	"cisco_ios_backup": {
		"template_name": "Cisco IOS Configuration Backup",
		"backup_command": "copy running-config sftp://{sftp_username}:{sftp_password}@{sftp_server_ip}{backup_path}/{backup_filename}",
		"command_format": "TEXT",
		"template_variables": json.dumps(CISCO_TEMPLATE_VARIABLES)
	},
	
	"juniper_backup": {
		"template_name": "Juniper Configuration Backup",
		"backup_command": "file copy /config/juniper.conf.gz sftp://{sftp_username}@{sftp_server_ip}{backup_path}/{backup_filename}",
		"command_format": "TEXT",
		"template_variables": json.dumps(CISCO_TEMPLATE_VARIABLES)
	},
	
	"mikrotik_backup": {
		"template_name": "MikroTik Configuration Backup", 
		"backup_command": "/export file={backup_filename}\n/tool fetch address={sftp_server_ip} src-path={backup_filename} user={sftp_username} password={sftp_password} dst-path={backup_path}/{backup_filename} upload=yes",
		"command_format": "TEXT",
		"template_variables": json.dumps(CISCO_TEMPLATE_VARIABLES)
	}
}


if __name__ == "__main__":
	# Example usage and testing
	logging.basicConfig(level=logging.DEBUG)
	
	# Test template processing
	manager = BackupCommandTemplateManager()
	
	# Test device info
	device_info = {
		'device_name': 'test-switch-01',
		'ip_address': '192.168.1.100',
		'hostname': 'sw01',
		'device_type': 'cisco_ios',
		'ssh_username': 'admin'
	}
	
	# Test user variables
	user_vars = {
		'sftp_server_ip': '192.168.1.200',
		'sftp_username': 'backup_user',
		'sftp_password': 'backup_pass',
		'backup_path': '/network-backups'
	}
	
	# Test Cisco template
	cisco_template = TEMPLATE_EXAMPLES['cisco_ios_backup']
	result = manager.process_backup_command(cisco_template, device_info, user_vars)
	
	print(f"Template processing result:")
	print(f"Success: {result.success}")
	print(f"Processed command: {result.processed_content}")
	print(f"Variables used: {list(result.variables_used.keys())}")
	
	if result.warnings:
		print(f"Warnings: {result.warnings}")
	if result.error_message:
		print(f"Error: {result.error_message}")