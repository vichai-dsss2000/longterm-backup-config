import axios from 'axios';

const BASE_URL = '/api';

// Axios instance with interceptors for error handling
const apiClient = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add token to requests automatically
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
      console.log('Adding token to request:', config.url, 'Token:', token.substring(0, 20) + '...');
    } else {
      console.log('No token found for request:', config.url);
    }
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Handle response errors
apiClient.interceptors.response.use(
  (response) => {
    console.log('Response received:', response.config.url, 'Status:', response.status);
    return response;
  },
  (error) => {
    console.error('Response error:', error.config?.url, 'Status:', error.response?.status, 'Data:', error.response?.data);
    
    if (error.response?.status === 401) {
      // Token expired or invalid
      console.log('401 Unauthorized - removing token and redirecting to login');
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default apiClient;
