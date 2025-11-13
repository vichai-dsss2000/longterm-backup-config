import apiClient from './apiClient';

export interface DashboardStats {
  total_devices: number;
  active_devices: number;
  inactive_devices: number;
  total_templates: number;
  active_templates: number;
  total_schedules: number;
  active_schedules: number;
  total_backups: number;
  successful_backups: number;
  failed_backups: number;
  running_backups: number;
  pending_backups: number;
  total_backup_size: number;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  components: {
    [key: string]: {
      status: 'healthy' | 'unhealthy';
      message: string;
    };
  };
  version: string;
}

export class DashboardService {
  static async getStats(): Promise<DashboardStats> {
    try {
      // Get data from multiple endpoints
      const [
        devicesResponse,
        templatesResponse,
        schedulesResponse,
        backupsResponse
      ] = await Promise.all([
        apiClient.get('/devices/'),
        apiClient.get('/templates/'),
        apiClient.get('/schedules/'),
        apiClient.get('/backups/stats')
      ]);

      const devices = devicesResponse.data;
      const templates = templatesResponse.data;
      const schedules = schedulesResponse.data;
      const backupStats = backupsResponse.data;

      // Map API response fields to frontend interface
      const statusBreakdown = backupStats.status_breakdown || {};

      return {
        total_devices: devices.length,
        active_devices: devices.filter((d: any) => d.is_active).length,
        inactive_devices: devices.filter((d: any) => !d.is_active).length,
        total_templates: templates.length,
        active_templates: templates.filter((t: any) => t.is_active).length,
        total_schedules: schedules.length,
        active_schedules: schedules.filter((s: any) => s.is_active).length,
        total_backups: backupStats.total_jobs || 0,
        successful_backups: statusBreakdown.completed || 0,
        failed_backups: statusBreakdown.failed || 0,
        running_backups: statusBreakdown.running || 0,
        pending_backups: statusBreakdown.pending || 0,
        total_backup_size: backupStats.total_backup_size_mb || 0
      };
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      throw error;
    }
  }

  static async getSystemHealth(): Promise<SystemHealth> {
    const response = await apiClient.get('/health');
    return response.data;
  }
}
