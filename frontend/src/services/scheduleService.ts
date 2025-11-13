import axios from 'axios';
import {
  SchedulerJob,
  SchedulerJobCreate,
  SchedulerJobUpdate,
  JobCategory,
  JobCategoryCreate,
  JobCategoryUpdate,
  BackupTemplate,
  DeviceType,
  PaginationParams,
  ApiResponse
} from '../types/scheduler';

const BASE_URL = '/api';

// Axios instance with interceptors for error handling
const apiClient = axios.create({
  baseURL: BASE_URL,
});

// Add token to requests automatically
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Scheduler Jobs (Job Schedule Policies) API
export class ScheduleService {
  
  // Get all scheduler jobs with filtering
  static async getSchedulerJobs(params: PaginationParams = {}): Promise<SchedulerJob[]> {
    const response = await apiClient.get('/schedules/', { params });
    return response.data;
  }

  // Get a specific scheduler job by ID
  static async getSchedulerJob(id: number): Promise<SchedulerJob> {
    const response = await apiClient.get(`/schedules/${id}`);
    return response.data;
  }

  // Create a new scheduler job
  static async createSchedulerJob(data: SchedulerJobCreate): Promise<SchedulerJob> {
    const response = await apiClient.post('/schedules/', data);
    return response.data;
  }

  // Update an existing scheduler job
  static async updateSchedulerJob(id: number, data: SchedulerJobUpdate): Promise<SchedulerJob> {
    const response = await apiClient.put(`/schedules/${id}`, data);
    return response.data;
  }

  // Delete a scheduler job (soft delete)
  static async deleteSchedulerJob(id: number): Promise<ApiResponse<any>> {
    const response = await apiClient.delete(`/schedules/${id}`);
    return response.data;
  }

  // Manually trigger a scheduler job
  static async triggerSchedulerJob(id: number, deviceIds?: number[]): Promise<ApiResponse<any>> {
    const response = await apiClient.post(`/schedules/${id}/trigger`, {
      device_ids: deviceIds
    });
    return response.data;
  }

  // Get all job categories
  static async getJobCategories(activeOnly: boolean = true): Promise<JobCategory[]> {
    const response = await apiClient.get('/schedules/categories', {
      params: { active_only: activeOnly }
    });
    return response.data;
  }

  // Create a new job category
  static async createJobCategory(data: JobCategoryCreate): Promise<JobCategory> {
    const response = await apiClient.post('/schedules/categories', data);
    return response.data;
  }

  // Update a job category
  static async updateJobCategory(id: number, data: JobCategoryUpdate): Promise<JobCategory> {
    const response = await apiClient.put(`/schedules/categories/${id}`, data);
    return response.data;
  }

  // Delete a job category
  static async deleteJobCategory(id: number): Promise<ApiResponse<any>> {
    const response = await apiClient.delete(`/schedules/categories/${id}`);
    return response.data;
  }

  // Get all backup templates (needed for creating scheduler jobs)
  static async getBackupTemplates(activeOnly: boolean = true): Promise<BackupTemplate[]> {
    const response = await apiClient.get('/templates/', {
      params: { active_only: activeOnly }
    });
    return response.data;
  }

  // Get all device types (needed for creating scheduler jobs)
  static async getDeviceTypes(activeOnly: boolean = true): Promise<DeviceType[]> {
    const response = await apiClient.get('/devices/types', {
      params: { active_only: activeOnly }
    });
    return response.data;
  }

  // Validate cron expression
  static validateCronExpression(cronExpression: string): boolean {
    // Basic cron validation - should have 5 or 6 parts
    const parts = cronExpression.trim().split(/\s+/);
    if (parts.length < 5 || parts.length > 6) {
      return false;
    }

    // Check for valid characters in each part
    const validCronChars = /^[0-9\-*/,?LW#]+$/;
    return parts.every(part => validCronChars.test(part));
  }

  // Get common cron expression presets
  static getCronPresets(): Array<{ label: string; value: string; description: string }> {
    return [
      { label: 'Every minute', value: '* * * * *', description: 'Runs every minute' },
      { label: 'Every 5 minutes', value: '*/5 * * * *', description: 'Runs every 5 minutes' },
      { label: 'Every hour', value: '0 * * * *', description: 'Runs at the start of every hour' },
      { label: 'Every day at midnight', value: '0 0 * * *', description: 'Runs daily at 00:00' },
      { label: 'Every day at 6 AM', value: '0 6 * * *', description: 'Runs daily at 06:00' },
      { label: 'Every Monday at 9 AM', value: '0 9 * * 1', description: 'Runs every Monday at 09:00' },
      { label: 'Every weekday at 8 AM', value: '0 8 * * 1-5', description: 'Runs Monday-Friday at 08:00' },
      { label: 'Every month on 1st', value: '0 0 1 * *', description: 'Runs on the 1st of every month' },
      { label: 'Every week on Sunday', value: '0 0 * * 0', description: 'Runs every Sunday at midnight' }
    ];
  }
}

export default ScheduleService;