import apiClient from './apiClient';

// Backup Job
export interface BackupJob {
  id: number;
  device?: {
    id: number;
    device_name: string;
    ip_address: string;
  };
  device_id?: number;
  template?: {
    id: number;
    template_name: string;
  };
  template_id?: number;
  schedule_policy_id?: number;
  job_status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'success';
  backup_start_time?: string;
  backup_end_time?: string;
  backup_file_path?: string;
  backup_file_size?: number;
  backup_file_size_mb?: number;
  error_message?: string;
  retry_count: number;
  execution_time_seconds?: number;
  duration_seconds?: number;
  next_retry_time?: string;
  created_at: string;
  updated_at?: string;
}

export interface BackupJobCreate {
  device_id: number;
  template_id: number;
  schedule_policy_id?: number;
}

export interface BackupHistory {
  id: number;
  device_name: string;
  device_ip: string;
  template_name: string;
  job_status: string;
  backup_start_time: string;
  backup_end_time?: string;
  backup_file_path?: string;
  backup_file_size?: number;
  execution_time_seconds?: number;
  error_message?: string;
}

export class BackupService {
  static async getBackups(params?: {
    skip?: number;
    limit?: number;
    device_id?: number;
    job_status?: string;
    start_date?: string;
    end_date?: string;
  }): Promise<BackupJob[]> {
    try {
      const response = await apiClient.get('/backups/', { params });
      return response.data;
    } catch (err: any) {
      // Treat 404 as empty list (no backups available)
      if (err.response?.status === 404) return [];
      throw err;
    }
  }

  static async getBackup(id: number): Promise<BackupJob> {
    const response = await apiClient.get(`/backups/${id}`);
    return response.data;
  }

  static async createBackup(data: BackupJobCreate): Promise<BackupJob> {
    const response = await apiClient.post('/backups/', data);
    return response.data;
  }

  static async getRecentBackups(limit: number = 10): Promise<BackupHistory[]> {
    const response = await apiClient.get('/backups/recent', { params: { limit } });
    return response.data;
  }

  static async triggerManualBackup(deviceId: number, templateId: number): Promise<BackupJob> {
    const response = await apiClient.post('/backups/manual', {
      device_id: deviceId,
      template_id: templateId
    });
    return response.data;
  }

  static async cancelBackup(id: number): Promise<void> {
    await apiClient.post(`/backups/${id}/cancel`);
  }

  static async retryBackup(id: number): Promise<BackupJob> {
    const response = await apiClient.post(`/backups/${id}/retry`);
    return response.data;
  }

  static async downloadBackupFile(id: number): Promise<Blob> {
    const response = await apiClient.get(`/backups/${id}/download`, {
      responseType: 'blob'
    });
    return response.data;
  }

  static async getBackupStats(): Promise<{
    total_backups?: number;
    total_jobs?: number;
    successful_backups?: number;
    failed_backups?: number;
    running_backups?: number;
    total_backup_size?: number;
    total_backup_size_mb?: number;
    status_breakdown?: {
      completed?: number;
      failed?: number;
      pending?: number;
      running?: number;
    };
    success_rate?: number;
    average_duration_seconds?: number;
  }> {
    try {
      const response = await apiClient.get('/backups/stats');
      return response.data;
    } catch (err: any) {
      // If stats endpoint not available, return sensible defaults
      if (err.response?.status === 404) {
        return {
          total_backups: 0,
          total_jobs: 0,
          successful_backups: 0,
          failed_backups: 0,
          running_backups: 0,
          total_backup_size: 0,
          total_backup_size_mb: 0,
          status_breakdown: {},
          success_rate: 0,
          average_duration_seconds: 0
        };
      }
      throw err;
    }
  }
}
