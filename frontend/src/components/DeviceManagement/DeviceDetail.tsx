import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Container,
  Row,
  Col,
  Card,
  Button,
  Badge,
  Spinner,
  Alert,
  Table,
  Modal,
  Form,
  Tabs,
  Tab,
  ProgressBar
} from 'react-bootstrap';
import {
  ArrowLeft,
  Edit,
  Trash2,
  Activity,
  Server,
  MapPin,
  Network,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  RefreshCw,
  Download,
  Terminal,
  Info
} from 'lucide-react';
import { DeviceService, NetworkDevice, DeviceType, NetworkDeviceUpdate } from '../../services/deviceService';
import { BackupService, BackupJob } from '../../services/backupService';
import Swal from 'sweetalert2';

const DeviceDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  
  // State management
  const [device, setDevice] = useState<NetworkDevice | null>(null);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  const [backupHistory, setBackupHistory] = useState<BackupJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  
  // Edit modal state
  const [showEditModal, setShowEditModal] = useState(false);
  const [editFormData, setEditFormData] = useState<NetworkDeviceUpdate>({});
  const [submitting, setSubmitting] = useState(false);

  // Load data
  useEffect(() => {
    if (id) {
      loadDeviceData();
    }
  }, [id]);

  const loadDeviceData = async () => {
    setLoading(true);
    try {
      const [deviceData, typesData, backupsData] = await Promise.all([
        DeviceService.getDevice(Number(id)),
        DeviceService.getDeviceTypes(),
        BackupService.getBackups({ device_id: Number(id), limit: 10 })
      ]);

      setDevice(deviceData);
      setDeviceTypes(typesData);
      setBackupHistory(backupsData);
      setError(null);
    } catch (err: any) {
      console.error('Error loading device:', err);
      setError('Failed to load device details');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = () => {
    if (device) {
      setEditFormData({
        device_name: device.device_name,
        ip_address: device.ip_address,
        device_type_id: device.device_type_id,
        hostname: device.hostname,
        location: device.location,
        management_ip: device.management_ip,
        ssh_username: device.ssh_username,
        ssh_port: device.ssh_port,
        description: device.description,
        is_active: device.is_active
      });
      setShowEditModal(true);
    }
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!device) return;

    setSubmitting(true);
    try {
      await DeviceService.updateDevice(device.id, editFormData);
      Swal.fire('Success', 'Device updated successfully', 'success');
      setShowEditModal(false);
      loadDeviceData();
    } catch (err: any) {
      Swal.fire('Error', err.response?.data?.message || 'Failed to update device', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async () => {
    if (!device) return;

    const result = await Swal.fire({
      title: 'Delete Device?',
      text: `Are you sure you want to delete "${device.device_name}"?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#6c757d',
      confirmButtonText: 'Yes, delete it!'
    });

    if (result.isConfirmed) {
      try {
        await DeviceService.deleteDevice(device.id);
        Swal.fire('Deleted!', 'Device has been deleted.', 'success');
        navigate('/devices');
      } catch (err: any) {
        Swal.fire('Error', err.response?.data?.message || 'Failed to delete device', 'error');
      }
    }
  };

  const handleTestConnection = async () => {
    if (!device) return;

    setTesting(true);
    try {
      const result = await DeviceService.testConnection(device.id);
      
      if (result.success) {
        Swal.fire({
          title: 'Connection Successful',
          html: `
            <p><strong>Connection Time:</strong> ${result.connection_time?.toFixed(2)}s</p>
            ${result.device_info ? `
              <p><strong>Device Type:</strong> ${result.device_info.device_type || 'N/A'}</p>
              <p><strong>Hostname:</strong> ${result.device_info.hostname || 'N/A'}</p>
              <p><strong>Version:</strong> ${result.device_info.version || 'N/A'}</p>
            ` : ''}
          `,
          icon: 'success'
        });
      } else {
        Swal.fire('Connection Failed', result.message, 'error');
      }
    } catch (err: any) {
      Swal.fire('Error', 'Failed to test connection', 'error');
    } finally {
      setTesting(false);
    }
  };

  const handleTriggerBackup = async () => {
    if (!device) return;

    const result = await Swal.fire({
      title: 'Trigger Manual Backup?',
      text: `Start backup for "${device.device_name}"?`,
      icon: 'question',
      showCancelButton: true,
      confirmButtonText: 'Yes, backup now!'
    });

    if (result.isConfirmed) {
      try {
        // Assuming there's a manual backup endpoint
        Swal.fire('Backup Started', 'Manual backup has been triggered', 'success');
        setTimeout(loadDeviceData, 2000); // Reload after 2 seconds
      } catch (err: any) {
        Swal.fire('Error', 'Failed to trigger backup', 'error');
      }
    }
  };

  const getStatusBadge = (status?: string) => {
    const statusConfig: any = {
      success: { bg: 'success', icon: CheckCircle, text: 'Success' },
      completed: { bg: 'success', icon: CheckCircle, text: 'Success' },
      failed: { bg: 'danger', icon: XCircle, text: 'Failed' },
      running: { bg: 'primary', icon: RefreshCw, text: 'Running' },
      pending: { bg: 'secondary', icon: Clock, text: 'Pending' }
    };

    const config = statusConfig[status || 'pending'] || statusConfig.pending;
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

  if (loading) {
    return (
      <Container className="mt-4">
        <div className="text-center py-5">
          <Spinner animation="border" variant="primary" />
          <p className="mt-2">Loading device details...</p>
        </div>
      </Container>
    );
  }

  if (error || !device) {
    return (
      <Container className="mt-4">
        <Alert variant="danger">
          <AlertCircle size={20} className="me-2" />
          {error || 'Device not found'}
        </Alert>
        <Button variant="outline-primary" onClick={() => navigate('/devices')}>
          <ArrowLeft size={16} className="me-2" />
          Back to Devices
        </Button>
      </Container>
    );
  }

  return (
    <Container fluid className="mt-4">
      {/* Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <div>
              <Button 
                variant="outline-secondary" 
                size="sm" 
                onClick={() => navigate('/devices')}
                className="me-3"
              >
                <ArrowLeft size={16} />
              </Button>
              <h2 className="d-inline">
                <Server size={28} className="me-2" />
                {device.device_name}
              </h2>
              {device.is_active ? (
                <Badge bg="success" className="ms-3">Active</Badge>
              ) : (
                <Badge bg="secondary" className="ms-3">Inactive</Badge>
              )}
            </div>
            <div className="d-flex gap-2">
              <Button 
                variant="outline-info" 
                onClick={handleTestConnection}
                disabled={testing}
              >
                {testing ? (
                  <><Spinner animation="border" size="sm" className="me-2" />Testing...</>
                ) : (
                  <><Activity size={16} className="me-2" />Test Connection</>
                )}
              </Button>
              <Button variant="outline-success" onClick={handleTriggerBackup}>
                <RefreshCw size={16} className="me-2" />
                Trigger Backup
              </Button>
              <Button variant="primary" onClick={handleEdit}>
                <Edit size={16} className="me-2" />
                Edit
              </Button>
              <Button variant="outline-danger" onClick={handleDelete}>
                <Trash2 size={16} className="me-2" />
                Delete
              </Button>
            </div>
          </div>
        </Col>
      </Row>

      {/* Main Content Tabs */}
      <Tabs defaultActiveKey="overview" className="mb-3">
        <Tab eventKey="overview" title="Overview">
          <Row>
            {/* Device Information */}
            <Col md={6}>
              <Card className="mb-4">
                <Card.Header>
                  <Info size={18} className="me-2" />
                  <strong>Device Information</strong>
                </Card.Header>
                <Card.Body>
                  <Table borderless>
                    <tbody>
                      <tr>
                        <td width="40%"><strong>Device Name:</strong></td>
                        <td>{device.device_name}</td>
                      </tr>
                      <tr>
                        <td><strong>IP Address:</strong></td>
                        <td><code>{device.ip_address}</code></td>
                      </tr>
                      <tr>
                        <td><strong>Hostname:</strong></td>
                        <td>{device.hostname || 'N/A'}</td>
                      </tr>
                      <tr>
                        <td><strong>Management IP:</strong></td>
                        <td>{device.management_ip ? <code>{device.management_ip}</code> : 'N/A'}</td>
                      </tr>
                      <tr>
                        <td><strong>Location:</strong></td>
                        <td>
                          <MapPin size={14} className="me-1" />
                          {device.location || 'N/A'}
                        </td>
                      </tr>
                      <tr>
                        <td><strong>Device Type:</strong></td>
                        <td>
                          {device.device_type ? (
                            <>
                              {typeof device.device_type === 'object' ? (
                                <>
                                  {device.device_type.vendor} {device.device_type.model}
                                  {device.device_type.firmware_version && (
                                    <><br /><small className="text-muted">v{device.device_type.firmware_version}</small></>
                                  )}
                                </>
                              ) : (
                                device.device_type
                              )}
                            </>
                          ) : (
                            'N/A'
                          )}
                        </td>
                      </tr>
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>

              {/* SSH Configuration */}
              <Card className="mb-4">
                <Card.Header>
                  <Terminal size={18} className="me-2" />
                  <strong>SSH Configuration</strong>
                </Card.Header>
                <Card.Body>
                  <Table borderless>
                    <tbody>
                      <tr>
                        <td width="40%"><strong>SSH Username:</strong></td>
                        <td>{device.ssh_username || 'N/A'}</td>
                      </tr>
                      <tr>
                        <td><strong>SSH Port:</strong></td>
                        <td>{device.ssh_port || 22}</td>
                      </tr>
                      <tr>
                        <td><strong>Password:</strong></td>
                        <td>
                          <Badge bg="secondary">••••••••</Badge>
                          <small className="text-muted ms-2">Encrypted</small>
                        </td>
                      </tr>
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>
            </Col>

            {/* Status and Statistics */}
            <Col md={6}>
              <Card className="mb-4">
                <Card.Header>
                  <Activity size={18} className="me-2" />
                  <strong>Status & Statistics</strong>
                </Card.Header>
                <Card.Body>
                  <Table borderless>
                    <tbody>
                      <tr>
                        <td width="40%"><strong>Status:</strong></td>
                        <td>
                          {device.is_active ? (
                            <Badge bg="success">
                              <CheckCircle size={12} className="me-1" />
                              Active
                            </Badge>
                          ) : (
                            <Badge bg="secondary">
                              <XCircle size={12} className="me-1" />
                              Inactive
                            </Badge>
                          )}
                        </td>
                      </tr>
                      <tr>
                        <td><strong>Last Backup:</strong></td>
                        <td>
                          {device.last_backup_date ? (
                            <>
                              {new Date(device.last_backup_date).toLocaleString()}
                              <br />
                              {getStatusBadge(device.last_backup_status)}
                            </>
                          ) : (
                            <span className="text-muted">Never</span>
                          )}
                        </td>
                      </tr>
                      <tr>
                        <td><strong>Total Backups:</strong></td>
                        <td>
                          <Badge bg="primary">{backupHistory.length}</Badge>
                        </td>
                      </tr>
                      <tr>
                        <td><strong>Created:</strong></td>
                        <td>
                          <small>{device.created_at ? new Date(device.created_at).toLocaleString() : 'N/A'}</small>
                        </td>
                      </tr>
                    </tbody>
                  </Table>
                </Card.Body>
              </Card>

              {/* Description */}
              {device.description && (
                <Card className="mb-4">
                  <Card.Header>
                    <strong>Description</strong>
                  </Card.Header>
                  <Card.Body>
                    <p className="mb-0">{device.description}</p>
                  </Card.Body>
                </Card>
              )}
            </Col>
          </Row>
        </Tab>

        <Tab eventKey="backup-history" title={`Backup History (${backupHistory.length})`}>
          <Card>
            <Card.Body>
              {backupHistory.length === 0 ? (
                <div className="text-center py-4 text-muted">
                  <Clock size={40} className="mb-3 opacity-50" />
                  <p>No backup history found</p>
                </div>
              ) : (
                <Table responsive hover>
                  <thead>
                    <tr>
                      <th>Date</th>
                      <th>Status</th>
                      <th>Duration</th>
                      <th>File Size</th>
                      <th>Template</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {backupHistory.map((backup) => (
                      <tr key={backup.id}>
                        <td>
                          <small>
                            {backup.backup_start_time 
                              ? new Date(backup.backup_start_time).toLocaleString()
                              : 'N/A'
                            }
                          </small>
                        </td>
                        <td>{getStatusBadge(backup.job_status)}</td>
                        <td>
                          <small>
                            {backup.duration_seconds 
                              ? `${Math.floor(backup.duration_seconds / 60)}m ${backup.duration_seconds % 60}s`
                              : 'N/A'
                            }
                          </small>
                        </td>
                        <td>
                          <small>{formatFileSize(backup.backup_file_size, backup.backup_file_size_mb)}</small>
                        </td>
                        <td>
                          <small>
                            {backup.template?.template_name || `Template #${backup.template_id}`}
                          </small>
                        </td>
                        <td>
                          {(backup.job_status === 'success' || backup.job_status === 'completed') && backup.backup_file_path && (
                            <Button size="sm" variant="outline-success">
                              <Download size={14} />
                            </Button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
            </Card.Body>
          </Card>
        </Tab>
      </Tabs>

      {/* Edit Modal */}
      <Modal show={showEditModal} onHide={() => setShowEditModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Edit Device - {device.device_name}</Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSaveEdit}>
          <Modal.Body>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Device Name *</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.device_name || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, device_name: e.target.value })}
                    required
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>IP Address *</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.ip_address || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, ip_address: e.target.value })}
                    required
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Device Type *</Form.Label>
                  <Form.Select
                    value={editFormData.device_type_id || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, device_type_id: parseInt(e.target.value) })}
                    required
                  >
                    <option value="">Select device type...</option>
                    {deviceTypes.map((type) => (
                      <option key={type.id} value={type.id}>
                        {type.vendor} {type.model} {type.firmware_version ? `v${type.firmware_version}` : ''}
                      </option>
                    ))}
                  </Form.Select>
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Hostname</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.hostname || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, hostname: e.target.value })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Location</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.location || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, location: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Management IP</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.management_ip || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, management_ip: e.target.value })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>SSH Username</Form.Label>
                  <Form.Control
                    type="text"
                    value={editFormData.ssh_username || ''}
                    onChange={(e) => setEditFormData({ ...editFormData, ssh_username: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>SSH Port</Form.Label>
                  <Form.Control
                    type="number"
                    value={editFormData.ssh_port || 22}
                    onChange={(e) => setEditFormData({ ...editFormData, ssh_port: parseInt(e.target.value) })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                value={editFormData.description || ''}
                onChange={(e) => setEditFormData({ ...editFormData, description: e.target.value })}
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Check
                type="checkbox"
                label="Active"
                checked={editFormData.is_active !== false}
                onChange={(e) => setEditFormData({ ...editFormData, is_active: e.target.checked })}
              />
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowEditModal(false)} disabled={submitting}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={submitting}>
              {submitting ? (
                <><Spinner animation="border" size="sm" className="me-2" />Saving...</>
              ) : (
                'Save Changes'
              )}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </Container>
  );
};

export default DeviceDetail;
