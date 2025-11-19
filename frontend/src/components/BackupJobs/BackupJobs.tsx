import React, { useState, useEffect, useCallback } from 'react';
import {
  Container,
  Row,
  Col,
  Card,
  Table,
  Button,
  Form,
  Alert,
  Badge,
  Spinner,
  InputGroup,
  FormControl,
  Modal,
  OverlayTrigger,
  Tooltip
} from 'react-bootstrap';
import {
  
  RefreshCw,
  Download,
  X,
  CheckCircle,
  XCircle,
  Clock,
  AlertCircle,
  Filter,
  Search,
  
  FileText,
  Zap
} from 'lucide-react';
import { BackupService, BackupJob, BackupHistory } from '../../services/backupService';
import { DeviceService } from '../../services/deviceService';
import Swal from 'sweetalert2';

const BackupJobs: React.FC = () => {
  // State management
  const [jobs, setJobs] = useState<BackupJob[]>([]);
  
  const [devices, setDevices] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [filterDevice, setFilterDevice] = useState<number | null>(null);
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');

  // Stats
  const [stats, setStats] = useState<any>({
    total_backups: 0,
    total_jobs: 0,
    successful_backups: 0,
    failed_backups: 0,
    running_backups: 0,
    total_backup_size: 0,
    total_backup_size_mb: 0,
    status_breakdown: {
      completed: 0,
      failed: 0,
      pending: 0,
      running: 0
    },
    success_rate: 0
  });

  // Modal states
  const [showDetailsModal, setShowDetailsModal] = useState(false);
  const [selectedJob, setSelectedJob] = useState<BackupJob | null>(null);

  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Load data
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = {};
      if (filterDevice) params.device_id = filterDevice;
      if (filterStatus !== 'all') params.job_status = filterStatus;
      if (startDate) params.start_date = startDate;
      if (endDate) params.end_date = endDate;

      const [jobsData, statsData, devicesData] = await Promise.all([
        BackupService.getBackups(params),
        BackupService.getBackupStats(),
        DeviceService.getDevices()
      ]);

      setJobs(jobsData);
      setStats(statsData);
      setDevices(devicesData);
      setError(null);
    } catch (err: any) {
      setError('Failed to load backup jobs');
      console.error('Error loading data:', err);
    } finally {
      setLoading(false);
    }
  }, [filterDevice, filterStatus, startDate, endDate]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Auto-refresh effect
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (autoRefresh) {
      interval = setInterval(() => {
        loadData();
      }, 10000); // Refresh every 10 seconds
      return () => {
        if (interval) clearInterval(interval);
      };
    }
    return () => {};
  }, [autoRefresh, loadData]);

  // Handlers
  const handleRetryJob = async (job: BackupJob) => {
    try {
      await BackupService.retryBackup(job.id);
      setSuccess(`Backup job #${job.id} has been queued for retry`);
      loadData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to retry backup job');
    }
  };

  const handleCancelJob = async (job: BackupJob) => {
    const result = await Swal.fire({
      title: 'Cancel Backup Job?',
      text: `Are you sure you want to cancel backup job #${job.id}?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#6c757d',
      confirmButtonText: 'Yes, cancel it!'
    });

    if (result.isConfirmed) {
      try {
        await BackupService.cancelBackup(job.id);
        setSuccess(`Backup job #${job.id} has been cancelled`);
        loadData();
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to cancel backup job');
      }
    }
  };

  const handleDownloadBackup = async (job: BackupJob) => {
    try {
      const blob = await BackupService.downloadBackupFile(job.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = job.backup_file_path?.split('/').pop() || `backup-${job.id}.txt`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to download backup file');
    }
  };

  const handleViewDetails = (job: BackupJob) => {
    setSelectedJob(job);
    setShowDetailsModal(true);
  };

  // Filter jobs
  const filteredJobs = jobs.filter(job => {
    const matchesSearch = searchTerm === '' || 
      job.backup_file_path?.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSearch;
  });

  // Utility functions
  const getStatusBadge = (status: string) => {
    const statusConfig: any = {
      pending: { bg: 'secondary', icon: Clock, text: 'Pending' },
      running: { bg: 'primary', icon: RefreshCw, text: 'Running' },
      success: { bg: 'success', icon: CheckCircle, text: 'Success' },
      completed: { bg: 'success', icon: CheckCircle, text: 'Success' },
      failed: { bg: 'danger', icon: XCircle, text: 'Failed' },
      cancelled: { bg: 'warning', icon: X, text: 'Cancelled' }
    };

    const config = statusConfig[status] || statusConfig.pending;
    const Icon = config.icon;

    return (
      <Badge bg={config.bg}>
        <Icon size={12} className="me-1" />
        {config.text}
      </Badge>
    );
  };

  const formatFileSize = (bytes?: number, mb?: number) => {
    if (mb !== undefined && mb !== null) {
      return `${mb.toFixed(2)} MB`;
    }
    if (!bytes) return 'N/A';
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  };

  const formatDuration = (seconds?: number) => {
    if (!seconds) return 'N/A';
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
  };

  const getSuccessRate = () => {
    if (stats.success_rate !== undefined) {
      return stats.success_rate.toFixed(1);
    }
    const total = stats.total_backups || stats.total_jobs || 0;
    if (total === 0) return 0;
    const successful = stats.successful_backups || stats.status_breakdown?.completed || 0;
    return ((successful / total) * 100).toFixed(1);
  };

  return (
    <Container fluid>
      {/* Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h2>Backup Jobs</h2>
            <div className="d-flex gap-2">
              <Form.Check
                type="switch"
                label="Auto-refresh"
                checked={autoRefresh}
                onChange={(e) => setAutoRefresh(e.target.checked)}
              />
              <Button variant="outline-primary" onClick={loadData} disabled={loading}>
                <RefreshCw size={16} className={loading ? 'spinner-icon' : ''} />
              </Button>
            </div>
          </div>
        </Col>
      </Row>

      {/* Alerts */}
      {error && (
        <Alert variant="danger" dismissible onClose={() => setError(null)}>
          {error}
        </Alert>
      )}
      {success && (
        <Alert variant="success" dismissible onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Stats Cards */}
      <Row className="mb-4">
        <Col md={3}>
          <Card className="border-primary">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-1">Total Backups</h6>
                  <h3 className="mb-0">{stats.total_backups || stats.total_jobs || 0}</h3>
                </div>
                <FileText size={40} className="text-primary opacity-50" />
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="border-success">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-1">Successful</h6>
                  <h3 className="mb-0 text-success">{stats.successful_backups || stats.status_breakdown?.completed || 0}</h3>
                  <small className="text-muted">{getSuccessRate()}% success rate</small>
                </div>
                <CheckCircle size={40} className="text-success opacity-50" />
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="border-danger">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-1">Failed</h6>
                  <h3 className="mb-0 text-danger">{stats.failed_backups || stats.status_breakdown?.failed || 0}</h3>
                </div>
                <XCircle size={40} className="text-danger opacity-50" />
              </div>
            </Card.Body>
          </Card>
        </Col>
        <Col md={3}>
          <Card className="border-info">
            <Card.Body>
              <div className="d-flex justify-content-between align-items-center">
                <div>
                  <h6 className="text-muted mb-1">Running</h6>
                  <h3 className="mb-0 text-info">{stats.running_backups || stats.status_breakdown?.running || 0}</h3>
                  <small className="text-muted">Total: {formatFileSize(undefined, stats.total_backup_size_mb || stats.total_backup_size)}</small>
                </div>
                <Zap size={40} className="text-info opacity-50" />
              </div>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Filters */}
      <Card className="mb-4">
        <Card.Body>
          <Row className="align-items-end">
            <Col md={3}>
              <Form.Group>
                <Form.Label>Search</Form.Label>
                <InputGroup>
                  <InputGroup.Text>
                    <Search size={16} />
                  </InputGroup.Text>
                  <FormControl
                    placeholder="Search backup files..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </InputGroup>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>Status</Form.Label>
                <Form.Select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                >
                  <option value="all">All Status</option>
                  <option value="pending">Pending</option>
                  <option value="running">Running</option>
                  <option value="completed">Completed</option>
                  <option value="success">Success</option>
                  <option value="failed">Failed</option>
                  <option value="cancelled">Cancelled</option>
                </Form.Select>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>Device</Form.Label>
                <Form.Select
                  value={filterDevice || ''}
                  onChange={(e) => setFilterDevice(e.target.value ? Number(e.target.value) : null)}
                >
                  <option value="">All Devices</option>
                  {devices.map(device => (
                    <option key={device.id} value={device.id}>
                      {device.device_name}
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>Start Date</Form.Label>
                <Form.Control
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                />
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>End Date</Form.Label>
                <Form.Control
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                />
              </Form.Group>
            </Col>
            <Col md={1}>
              <Button variant="outline-secondary" onClick={loadData}>
                <Filter size={16} />
              </Button>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      {/* Jobs Table */}
      <Card>
        <Card.Body>
          {loading ? (
            <div className="text-center p-4">
              <Spinner animation="border" role="status">
                <span className="visually-hidden">Loading...</span>
              </Spinner>
            </div>
          ) : (
            <Table responsive hover>
              <thead>
                <tr>
                  <th>Job ID</th>
                  <th>Device</th>
                  <th>Status</th>
                  <th>Start Time</th>
                  <th>Duration</th>
                  <th>File Size</th>
                  <th>Retries</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredJobs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-4 text-muted">
                      No backup jobs found
                    </td>
                  </tr>
                ) : (
                  filteredJobs.map(job => (
                    <tr key={job.id}>
                      <td>
                        <strong>#{job.id}</strong>
                      </td>
                      <td>
                        {job.device ? (
                          <>
                            <strong>{job.device.device_name}</strong>
                            <br />
                            <small className="text-muted">{job.device.ip_address}</small>
                          </>
                        ) : (
                          <small className="text-muted">Device ID: {job.device_id || 'N/A'}</small>
                        )}
                      </td>
                      <td>{getStatusBadge(job.job_status)}</td>
                      <td>
                        {job.backup_start_time ? (
                          <small>{new Date(job.backup_start_time).toLocaleString()}</small>
                        ) : (
                          <small className="text-muted">Not started</small>
                        )}
                      </td>
                      <td>
                        <small>{formatDuration(job.execution_time_seconds || job.duration_seconds)}</small>
                      </td>
                      <td>
                        <small>{formatFileSize(job.backup_file_size, job.backup_file_size_mb)}</small>
                      </td>
                      <td>
                        <Badge bg={job.retry_count > 0 ? 'warning' : 'secondary'}>
                          {job.retry_count}
                        </Badge>
                      </td>
                      <td>
                        <div className="d-flex gap-1">
                          <OverlayTrigger overlay={<Tooltip>View Details</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-info"
                              onClick={() => handleViewDetails(job)}
                            >
                              <AlertCircle size={14} />
                            </Button>
                          </OverlayTrigger>

                          {job.job_status === 'failed' && (
                            <OverlayTrigger overlay={<Tooltip>Retry</Tooltip>}>
                              <Button
                                size="sm"
                                variant="outline-warning"
                                onClick={() => handleRetryJob(job)}
                              >
                                <RefreshCw size={14} />
                              </Button>
                            </OverlayTrigger>
                          )}

                          {job.job_status === 'running' && (
                            <OverlayTrigger overlay={<Tooltip>Cancel</Tooltip>}>
                              <Button
                                size="sm"
                                variant="outline-danger"
                                onClick={() => handleCancelJob(job)}
                              >
                                <X size={14} />
                              </Button>
                            </OverlayTrigger>
                          )}

                          {(job.job_status === 'success' || job.job_status === 'completed') && job.backup_file_path && (
                            <OverlayTrigger overlay={<Tooltip>Download</Tooltip>}>
                              <Button
                                size="sm"
                                variant="outline-success"
                                onClick={() => handleDownloadBackup(job)}
                              >
                                <Download size={14} />
                              </Button>
                            </OverlayTrigger>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </Table>
          )}
        </Card.Body>
      </Card>

      {/* Job Details Modal */}
      <Modal show={showDetailsModal} onHide={() => setShowDetailsModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Backup Job Details - #{selectedJob?.id}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {selectedJob && (
            <div>
              <Row className="mb-3">
                <Col md={6}>
                  <strong>Device:</strong><br />
                  {selectedJob.device ? (
                    <>
                      {selectedJob.device.device_name}<br />
                      <small className="text-muted">{selectedJob.device.ip_address}</small>
                    </>
                  ) : (
                    <small className="text-muted">Device ID: {selectedJob.device_id || 'N/A'}</small>
                  )}
                </Col>
                <Col md={6}>
                  <strong>Template:</strong><br />
                  {selectedJob.template ? (
                    selectedJob.template.template_name
                  ) : (
                    <small className="text-muted">Template ID: {selectedJob.template_id || 'N/A'}</small>
                  )}
                </Col>
              </Row>
              <Row className="mb-3">
                <Col md={6}>
                  <strong>Status:</strong> {getStatusBadge(selectedJob.job_status)}
                </Col>
                <Col md={6}>
                  <strong>Retry Count:</strong> {selectedJob.retry_count}
                </Col>
              </Row>
              <Row className="mb-3">
                <Col md={6}>
                  <strong>Start Time:</strong><br />
                  <small>{selectedJob.backup_start_time ? new Date(selectedJob.backup_start_time).toLocaleString() : 'N/A'}</small>
                </Col>
                <Col md={6}>
                  <strong>End Time:</strong><br />
                  <small>{selectedJob.backup_end_time ? new Date(selectedJob.backup_end_time).toLocaleString() : 'N/A'}</small>
                </Col>
              </Row>
              <Row className="mb-3">
                <Col md={6}>
                  <strong>Duration:</strong> {formatDuration(selectedJob.execution_time_seconds || selectedJob.duration_seconds)}
                </Col>
                <Col md={6}>
                  <strong>File Size:</strong> {formatFileSize(selectedJob.backup_file_size, selectedJob.backup_file_size_mb)}
                </Col>
              </Row>
              {selectedJob.backup_file_path && (
                <Row className="mb-3">
                  <Col>
                    <strong>File Path:</strong><br />
                    <code>{selectedJob.backup_file_path}</code>
                  </Col>
                </Row>
              )}
              {selectedJob.error_message && (
                <Row className="mb-3">
                  <Col>
                    <Alert variant="danger">
                      <strong>Error Message:</strong><br />
                      {selectedJob.error_message}
                    </Alert>
                  </Col>
                </Row>
              )}
              <Row>
                <Col md={6}>
                  <strong>Created:</strong><br />
                  <small>{new Date(selectedJob.created_at).toLocaleString()}</small>
                </Col>
                <Col md={6}>
                  <strong>Updated:</strong><br />
                  <small>{selectedJob.updated_at ? new Date(selectedJob.updated_at).toLocaleString() : 'N/A'}</small>
                </Col>
              </Row>
              {selectedJob.next_retry_time && (
                <Row className="mt-3">
                  <Col>
                    <Alert variant="info">
                      <strong>Next Retry:</strong> {new Date(selectedJob.next_retry_time).toLocaleString()}
                    </Alert>
                  </Col>
                </Row>
              )}
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowDetailsModal(false)}>
            Close
          </Button>
        </Modal.Footer>
      </Modal>

      <style>
        {`
          @keyframes spin {
            from { transform: rotate(0deg); }
            to { transform: rotate(360deg); }
          }
          .spinner-icon {
            animation: spin 1s linear infinite;
          }
        `}
      </style>
    </Container>
  );
};

export default BackupJobs;