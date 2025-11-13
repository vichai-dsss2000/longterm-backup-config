import React, { createContext, useContext, useState, useEffect, ReactNode, useCallback } from 'react';
import apiClient from '../services/apiClient';

interface User {
  id: number;
  username: string;
  email: string;
  is_admin: boolean;
}

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  isAuthenticated: boolean;
  loading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem('token'));
  const [loading, setLoading] = useState(true);

  const logout = useCallback(() => {
    console.log('Logging out user');
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
  }, []);

  useEffect(() => {
    const verifyToken = async () => {
      const storedToken = localStorage.getItem('token');
      console.log('Verifying token on mount:', storedToken ? storedToken.substring(0, 20) + '...' : 'No token');
      
      if (storedToken) {
        // Verify token and get user info
        try {
          console.log('Fetching user info from /api/auth/me');
          const response = await apiClient.get('/auth/me');
          console.log('User info received:', response.data);
          setUser(response.data);
          setToken(storedToken);
        } catch (error) {
          console.error('Failed to fetch user info:', error);
          logout();
        } finally {
          setLoading(false);
        }
      } else {
        console.log('No token found, user not authenticated');
        setLoading(false);
      }
    };
    
    verifyToken();
  }, [logout]);

  const login = async (username: string, password: string): Promise<boolean> => {
    try {
      console.log('Attempting login with:', { username, password: '***' });
      
      // Use apiClient for consistent axios instance
      const response = await apiClient.post('/auth/login', {
        username,
        password
      });

      console.log('Login response:', response.data);
      
      const { access_token, user: userData } = response.data;
      
      // Store token first
      localStorage.setItem('token', access_token);
      console.log('Token stored in localStorage:', access_token.substring(0, 20) + '...');
      
      // Then set state
      setToken(access_token);
      setUser(userData);
      
      console.log('Login successful, user set:', userData.username);
      return true;
    } catch (error: any) {
      console.error('Login failed:', error);
      if (error.response) {
        console.error('Error response:', error.response.data);
        console.error('Error status:', error.response.status);
      }
      return false;
    }
  };

  const value: AuthContextType = {
    user,
    token,
    login,
    logout,
    isAuthenticated: !!token && !!user,
    loading
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};