import React, { useState, useEffect } from 'react';
import { Row, Col, Card, ProgressBar, Badge, ListGroup, Alert } from 'react-bootstrap';
import { FaServer, FaDatabase, FaClock, FaCheckCircle, FaExclamationTriangle } from 'react-icons/fa';
import axios from 'axios';

interface DashboardStats {
  total_devices: number;
  active_devices: number;
  total_backups: number;
  successful_backups: number;
  failed_backups: number;
  scheduled_jobs: number;
}

interface RecentBackup {
  id: number;
  device_name: string;
  status: string;
  backup_start_time: string;
  error_message?: string;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentBackups, setRecentBackups] = useState<RecentBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      console.log('Fetching dashboard data...');
      
      const [statsResponse, backupsResponse] = await Promise.all([
        axios.get('/api/dashboard/stats'),
        axios.get('/api/backups/recent?limit=10')
      ]);

      console.log('Stats response:', statsResponse.data);
      console.log('Backups response:', backupsResponse.data);
      
      setStats(statsResponse.data);
      setRecentBackups(backupsResponse.data);
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
      setError('Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge bg="success">Success</Badge>;
      case 'failed':
        return <Badge bg="danger">Failed</Badge>;
      case 'running':
        return <Badge bg="primary">Running</Badge>;
      case 'pending':
        return <Badge bg="warning">Pending</Badge>;
      default:
        return <Badge bg="secondary">{status}</Badge>;
    }
  };

  if (loading) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-primary" />
        <p className="mt-2">Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return <Alert variant="danger">{error}</Alert>;
  }

  const successRate = stats && stats.total_backups > 0 
    ? (stats.successful_backups / stats.total_backups) * 100 
    : 0;

  return (
    <div>
      <h2 className="mb-4">System Dashboard</h2>
      
      {/* Stats Cards */}
      <Row className="mb-4">
        <Col md={3}>
          <Card className="text-center">
            <Card.Body>
              <FaServer size={40} className="text-primary mb-2" />
              <h3>{stats?.total_devices || 0}</h3>
              <p className="text-muted mb-0">Total Devices</p>
              <small className="text-success">
                {stats?.active_devices || 0} active
              </small>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3}>
          <Card className="text-center">
            <Card.Body>
              <FaDatabase size={40} className="text-success mb-2" />
              <h3>{stats?.total_backups || 0}</h3>
              <p className="text-muted mb-0">Total Backups</p>
              <small className="text-muted">
                {stats?.successful_backups || 0} successful
              </small>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3}>
          <Card className="text-center">
            <Card.Body>
              <FaClock size={40} className="text-warning mb-2" />
              <h3>{stats?.scheduled_jobs || 0}</h3>
              <p className="text-muted mb-0">Scheduled Jobs</p>
              <small className="text-primary">Active</small>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3}>
          <Card className="text-center">
            <Card.Body>
              <div className="mb-2">
                {successRate >= 90 ? (
                  <FaCheckCircle size={40} className="text-success" />
                ) : (
                  <FaExclamationTriangle size={40} className="text-warning" />
                )}
              </div>
              <h3>{successRate.toFixed(1)}%</h3>
              <p className="text-muted mb-0">Success Rate</p>
              <ProgressBar 
                now={successRate} 
                variant={successRate >= 90 ? 'success' : 'warning'}
                // size="sm"
              />
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Recent Backups */}
      <Row>
        <Col md={12}>
          <Card>
            <Card.Header>
              <h5 className="mb-0">Recent Backup Jobs</h5>
            </Card.Header>
            <Card.Body>
              {recentBackups.length > 0 ? (
                <ListGroup variant="flush">
                  {recentBackups.map((backup) => (
                    <ListGroup.Item 
                      key={backup.id}
                      className="d-flex justify-content-between align-items-center"
                    >
                      <div>
                        <strong>{backup.device_name}</strong>
                        <br />
                        <small className="text-muted">
                          {new Date(backup.backup_start_time).toLocaleString()}
                        </small>
                        {backup.error_message && (
                          <div className="text-danger mt-1">
                            <small>{backup.error_message}</small>
                          </div>
                        )}
                      </div>
                      <div>
                        {getStatusBadge(backup.status)}
                      </div>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              ) : (
                <p className="text-muted text-center py-3">
                  No recent backup jobs found
                </p>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;