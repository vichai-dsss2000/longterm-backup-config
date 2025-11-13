import React, { useState, useEffect } from 'react';
import { Row, Col, Card, ProgressBar, Badge, ListGroup, Alert, Button, Spinner } from 'react-bootstrap';
import { FaServer, FaDatabase, FaClock, FaCheckCircle, FaExclamationTriangle, FaSync, FaChartLine } from 'react-icons/fa';
import { DashboardService, DashboardStats } from '../../services/dashboardService';
import { BackupService } from '../../services/backupService';

interface RecentBackup {
  id: number;
  device?: {
    id: number;
    device_name: string;
    ip_address: string;
  };
  device_name?: string; // Legacy support
  template?: {
    id: number;
    template_name: string;
  };
  job_status: string;
  backup_start_time: string;
  backup_end_time?: string;
  error_message?: string;
  backup_file_path?: string;
  duration_seconds?: number;
}

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [recentBackups, setRecentBackups] = useState<RecentBackup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchDashboardData();
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDashboardData, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const [statsData, backupsData] = await Promise.all([
        DashboardService.getStats(),
        BackupService.getRecentBackups(10)
      ]);
      
      setStats(statsData);
      setRecentBackups(backupsData as any);
      setError('');
    } catch (err: any) {
      console.error('Failed to fetch dashboard data:', err);
      setError(err.response?.data?.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await fetchDashboardData();
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
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2 className="mb-0">System Dashboard</h2>
        <Button 
          variant="outline-primary" 
          onClick={handleRefresh}
          disabled={refreshing}
        >
          {refreshing ? (
            <><Spinner animation="border" size="sm" className="me-2" />Refreshing...</>
          ) : (
            <><FaSync className="me-2" />Refresh</>
          )}
        </Button>
      </div>
      
      {/* Stats Cards */}
      <Row className="mb-4">
        <Col md={3} className="mb-3">
          <Card className="text-center h-100 shadow-sm">
            <Card.Body>
              <FaServer size={40} className="text-primary mb-3" />
              <h3 className="mb-1">{stats?.total_devices || 0}</h3>
              <p className="text-muted mb-2">Total Devices</p>
              <div className="d-flex justify-content-center gap-2">
                <Badge bg="success">{stats?.active_devices || 0} active</Badge>
                <Badge bg="secondary">{stats?.inactive_devices || 0} inactive</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3} className="mb-3">
          <Card className="text-center h-100 shadow-sm">
            <Card.Body>
              <FaDatabase size={40} className="text-success mb-3" />
              <h3 className="mb-1">{stats?.total_backups || 0}</h3>
              <p className="text-muted mb-2">Total Backups</p>
              <div className="d-flex justify-content-center gap-2">
                <Badge bg="success">{stats?.successful_backups || 0} success</Badge>
                <Badge bg="danger">{stats?.failed_backups || 0} failed</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3} className="mb-3">
          <Card className="text-center h-100 shadow-sm">
            <Card.Body>
              <FaClock size={40} className="text-warning mb-3" />
              <h3 className="mb-1">{stats?.total_schedules || 0}</h3>
              <p className="text-muted mb-2">Scheduled Jobs</p>
              <div className="d-flex justify-content-center gap-2">
                <Badge bg="primary">{stats?.active_schedules || 0} active</Badge>
                <Badge bg="warning">{stats?.running_backups || 0} running</Badge>
              </div>
            </Card.Body>
          </Card>
        </Col>
        
        <Col md={3} className="mb-3">
          <Card className="text-center h-100 shadow-sm">
            <Card.Body>
              <div className="mb-3">
                {successRate >= 90 ? (
                  <FaCheckCircle size={40} className="text-success" />
                ) : successRate >= 70 ? (
                  <FaChartLine size={40} className="text-warning" />
                ) : (
                  <FaExclamationTriangle size={40} className="text-danger" />
                )}
              </div>
              <h3 className="mb-1">{successRate.toFixed(1)}%</h3>
              <p className="text-muted mb-2">Success Rate</p>
              <ProgressBar 
                now={successRate} 
                variant={successRate >= 90 ? 'success' : successRate >= 70 ? 'warning' : 'danger'}
                // size="sm"
              />
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Recent Backups */}
      <Row>
        <Col md={12}>
          <Card className="shadow-sm">
            <Card.Header className="bg-white">
              <h5 className="mb-0">
                <FaDatabase className="me-2" />
                Recent Backup Jobs
              </h5>
            </Card.Header>
            <Card.Body>
              {recentBackups.length > 0 ? (
                <ListGroup variant="flush">
                  {recentBackups.map((backup) => (
                    <ListGroup.Item 
                      key={backup.id}
                      className="d-flex justify-content-between align-items-center py-3"
                    >
                      <div className="flex-grow-1">
                        <div className="d-flex align-items-center mb-1">
                          <strong className="me-2">
                            {backup.device?.device_name || backup.device_name || 'Unknown Device'}
                          </strong>
                          {getStatusBadge(backup.job_status)}
                        </div>
                        <small className="text-muted d-block">
                          <FaClock className="me-1" />
                          {backup.backup_start_time 
                            ? new Date(backup.backup_start_time).toLocaleString()
                            : 'Not started'}
                        </small>
                        {backup.template && (
                          <small className="text-muted d-block">
                            Template: {backup.template.template_name}
                          </small>
                        )}
                        {backup.error_message && (
                          <div className="text-danger mt-2">
                            <small>
                              <FaExclamationTriangle className="me-1" />
                              {backup.error_message}
                            </small>
                          </div>
                        )}
                      </div>
                    </ListGroup.Item>
                  ))}
                </ListGroup>
              ) : (
                <div className="text-center py-5">
                  <FaDatabase size={50} className="text-muted mb-3" />
                  <p className="text-muted mb-0">No recent backup jobs found</p>
                </div>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;