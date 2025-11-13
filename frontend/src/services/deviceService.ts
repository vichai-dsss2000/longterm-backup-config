import apiClient from './apiClient';

// Device Types
export interface DeviceType {
  id: number;
  vendor: string;
  model: string;
  firmware_version?: string;
  device_category?: string;
  netmiko_device_type: string;
  description?: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeviceTypeCreate {
  vendor: string;
  model: string;
  firmware_version?: string;
  device_category?: string;
  netmiko_device_type: string;
  description?: string;
}

// Network Devices
export interface NetworkDevice {
  id: number;
  device_name: string;
  ip_address: string;
  device_type_id: number;
  hostname?: string;
  location?: string;
  management_ip?: string;
  ssh_username?: string;
  ssh_port: number;
  description?: string;
  is_active: boolean;
  last_backup_date?: string;
  last_backup_status?: 'success' | 'failed' | 'pending' | 'running';
  created_at: string;
  updated_at: string;
  device_type?: DeviceType;
}

export interface NetworkDeviceCreate {
  device_name: string;
  ip_address: string;
  device_type_id: number;
  hostname?: string;
  location?: string;
  management_ip?: string;
  ssh_username?: string;
  ssh_password?: string;
  ssh_port?: number;
  enable_password?: string;
  description?: string;
}

export interface NetworkDeviceUpdate {
  device_name?: string;
  ip_address?: string;
  device_type_id?: number;
  hostname?: string;
  location?: string;
  management_ip?: string;
  ssh_username?: string;
  ssh_password?: string;
  ssh_port?: number;
  enable_password?: string;
  description?: string;
  is_active?: boolean;
}

export class DeviceService {
  // Device Types
  static async getDeviceTypes(): Promise<DeviceType[]> {
    const response = await apiClient.get('/devices/types');
    return response.data;
  }

  static async getDeviceType(id: number): Promise<DeviceType> {
    const response = await apiClient.get(`/devices/types/${id}`);
    return response.data;
  }

  static async createDeviceType(data: DeviceTypeCreate): Promise<DeviceType> {
    const response = await apiClient.post('/devices/types', data);
    return response.data;
  }

  static async updateDeviceType(id: number, data: Partial<DeviceTypeCreate>): Promise<DeviceType> {
    const response = await apiClient.put(`/devices/types/${id}`, data);
    return response.data;
  }

  static async deleteDeviceType(id: number): Promise<void> {
    await apiClient.delete(`/devices/types/${id}`);
  }

  // Network Devices
  static async getDevices(params?: {
    skip?: number;
    limit?: number;
    device_type_id?: number;
    is_active?: boolean;
  }): Promise<NetworkDevice[]> {
    const response = await apiClient.get('/devices/', { params });
    return response.data;
  }

  static async getDevice(id: number): Promise<NetworkDevice> {
    const response = await apiClient.get(`/devices/${id}`);
    return response.data;
  }

  static async createDevice(data: NetworkDeviceCreate): Promise<NetworkDevice> {
    const response = await apiClient.post('/devices/', data);
    return response.data;
  }

  static async updateDevice(id: number, data: NetworkDeviceUpdate): Promise<NetworkDevice> {
    const response = await apiClient.put(`/devices/${id}`, data);
    return response.data;
  }

  static async deleteDevice(id: number): Promise<void> {
    await apiClient.delete(`/devices/${id}`);
  }

  // Test device connectivity
  static async testConnection(id: number): Promise<{
    success: boolean;
    message: string;
    connection_time?: number;
    device_info?: {
      device_type?: string;
      hostname?: string;
      version?: string;
      [key: string]: any;
    };
    details?: any;
  }> {
    const response = await apiClient.post(`/devices/${id}/test-connection`);
    return response.data;
  }

  // Get device backup history
  static async getDeviceBackupHistory(deviceId: number): Promise<any[]> {
    const response = await apiClient.get(`/devices/${deviceId}/backup-history`);
    return response.data;
  }
}
