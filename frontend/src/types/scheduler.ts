// TypeScript interfaces for Scheduler Jobs (Job Schedule Policies)

export interface JobCategory {
  id: number;
  category_name: string;
  description?: string;
  color_code?: string;
  is_active: boolean;
  created_at: string;
}

export interface DeviceType {
  id: number;
  vendor: string;
  model: string;
  firmware_version?: string;
  device_category: string;
  netmiko_device_type: string;
  description?: string;
  is_active: boolean;
}

export interface BackupTemplate {
  id: number;
  device_type_id: number;
  template_name: string;
  template_description?: string;
  backup_command: string;
  command_format: 'TEXT' | 'JSON' | 'XML' | 'YAML';
  template_variables?: Record<string, any>;
  timeout_seconds: number;
  retry_count: number;
  retry_interval_seconds: number;
  is_active: boolean;
  version: string;
  created_at: string;
  updated_at: string;
  device_type?: DeviceType;
}

export interface SchedulerJob {
  id: number;
  policy_name: string;
  device_type_id?: number;
  template_id: number;
  job_category_id?: number;
  cron_expression: string;
  backup_path: string;
  sftp_server_ip?: string;
  sftp_username?: string;
  sftp_port: number;
  retention_days: number;
  compression_enabled: boolean;
  encryption_enabled: boolean;
  notification_enabled: boolean;
  notification_emails?: string[];
  is_active: boolean;
  created_at: string;
  template?: BackupTemplate;
  job_category?: JobCategory;
}

export interface SchedulerJobCreate {
  policy_name: string;
  device_type_id?: number;
  template_id: number;
  job_category_id?: number;
  cron_expression: string;
  backup_path: string;
  sftp_server_ip?: string;
  sftp_username?: string;
  sftp_password?: string;
  sftp_port?: number;
  retention_days?: number;
  compression_enabled?: boolean;
  encryption_enabled?: boolean;
  notification_enabled?: boolean;
  notification_emails?: string[];
}

export interface SchedulerJobUpdate {
  policy_name?: string;
  device_type_id?: number;
  template_id?: number;
  job_category_id?: number;
  cron_expression?: string;
  backup_path?: string;
  sftp_server_ip?: string;
  sftp_username?: string;
  sftp_password?: string;
  sftp_port?: number;
  retention_days?: number;
  compression_enabled?: boolean;
  encryption_enabled?: boolean;
  notification_enabled?: boolean;
  notification_emails?: string[];
  is_active?: boolean;
}

export interface JobCategoryCreate {
  category_name: string;
  description?: string;
  color_code?: string;
}

export interface JobCategoryUpdate {
  category_name?: string;
  description?: string;
  color_code?: string;
  is_active?: boolean;
}

export interface ApiResponse<T> {
  data?: T;
  message?: string;
  error?: string;
}

export interface PaginationParams {
  skip?: number;
  limit?: number;
  active_only?: boolean;
  device_type_id?: number;
  category_id?: number;
}