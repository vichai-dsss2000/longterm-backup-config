import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

// Components
import Layout from './components/Layout/Layout';
import Dashboard from './components/Dashboard/Dashboard';
import DeviceManagement from './components/DeviceManagement/DeviceManagement';
import BackupJobs from './components/BackupJobs/BackupJobs';
import Templates from './components/Templates/Templates';
import Schedules from './components/Schedules/Schedules';
import Login from './components/Auth/Login';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/Auth/ProtectedRoute';

const App: React.FC = () => {
  return (
    <AuthProvider>
      <Router>
        <div className="App">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route
              path="/*"
              element={
                <ProtectedRoute>
                  <Layout>
                    <Routes>
                      <Route path="/" element={<Dashboard />} />
                      <Route path="/devices" element={<DeviceManagement />} />
                      <Route path="/backups" element={<BackupJobs />} />
                      <Route path="/templates" element={<Templates />} />
                      <Route path="/schedules" element={<Schedules />} />
                    </Routes>
                  </Layout>
                </ProtectedRoute>
              }
            />
          </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
};

export default App;
