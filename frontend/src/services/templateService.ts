import apiClient from './apiClient';

// Backup Template
export interface BackupTemplate {
  id: number;
  device_type_id: number;
  template_name: string;
  template_description?: string;
  backup_command: string;
  command_format: 'TEXT' | 'JSON' | 'XML' | 'YAML';
  template_variables?: any;
  timeout_seconds: number;
  retry_count: number;
  retry_interval_seconds: number;
  is_active: boolean;
  version: string;
  created_at: string;
  updated_at: string;
}

export interface BackupTemplateCreate {
  device_type_id: number;
  template_name: string;
  template_description?: string;
  backup_command: string;
  command_format?: 'TEXT' | 'JSON' | 'XML' | 'YAML';
  template_variables?: any;
  timeout_seconds?: number;
  retry_count?: number;
  retry_interval_seconds?: number;
}

export interface BackupTemplateUpdate {
  template_name?: string;
  template_description?: string;
  backup_command?: string;
  command_format?: 'TEXT' | 'JSON' | 'XML' | 'YAML';
  template_variables?: any;
  timeout_seconds?: number;
  retry_count?: number;
  retry_interval_seconds?: number;
  is_active?: boolean;
}

export class TemplateService {
  static async getTemplates(params?: {
    skip?: number;
    limit?: number;
    device_type_id?: number;
    is_active?: boolean;
  }): Promise<BackupTemplate[]> {
    const response = await apiClient.get('/templates/', { params });
    return response.data;
  }

  static async getTemplate(id: number): Promise<BackupTemplate> {
    const response = await apiClient.get(`/templates/${id}`);
    return response.data;
  }

  static async createTemplate(data: BackupTemplateCreate): Promise<BackupTemplate> {
    const response = await apiClient.post('/templates/', data);
    return response.data;
  }

  static async updateTemplate(id: number, data: BackupTemplateUpdate): Promise<BackupTemplate> {
    const response = await apiClient.put(`/templates/${id}`, data);
    return response.data;
  }

  static async deleteTemplate(id: number): Promise<void> {
    await apiClient.delete(`/templates/${id}`);
  }

  static async validateTemplate(id: number): Promise<{
    valid: boolean;
    message: string;
    errors?: string[];
  }> {
    const response = await apiClient.post(`/templates/${id}/validate`);
    return response.data;
  }

  static async getTemplatesByDeviceType(deviceTypeId: number): Promise<BackupTemplate[]> {
    const response = await apiClient.get(`/templates/by-device-type/${deviceTypeId}`);
    return response.data;
  }
}
