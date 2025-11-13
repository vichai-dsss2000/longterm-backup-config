import React, { useState, useEffect } from 'react';
import { 
  Table, 
  Button, 
  Modal, 
  Form, 
  Alert, 
  Badge,
  Card,
  Spinner,
  InputGroup,
  Row,
  Col
} from 'react-bootstrap';
import { FaPlus, FaEdit, FaTrash, FaSync, FaServer, FaCheckCircle, FaSearch, FaPlay } from 'react-icons/fa';
import { DeviceService, NetworkDevice, DeviceType, NetworkDeviceCreate } from '../../services/deviceService';
import Swal from 'sweetalert2';

const DeviceManagement: React.FC = () => {
  const [devices, setDevices] = useState<NetworkDevice[]>([]);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  const [filteredDevices, setFilteredDevices] = useState<NetworkDevice[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [editingDevice, setEditingDevice] = useState<NetworkDevice | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<'all' | 'active' | 'inactive'>('all');
  const [submitting, setSubmitting] = useState(false);

  // Form state
  const [formData, setFormData] = useState<NetworkDeviceCreate>({
    device_name: '',
    ip_address: '',
    device_type_id: 0,
    hostname: '',
    location: '',
    management_ip: '',
    ssh_username: '',
    ssh_password: '',
    ssh_port: 22,
    enable_password: '',
    description: ''
  });

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    filterDevices();
  }, [devices, searchTerm, filterStatus]);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [devicesData, typesData] = await Promise.all([
        DeviceService.getDevices(),
        DeviceService.getDeviceTypes()
      ]);
      setDevices(devicesData);
      setDeviceTypes(typesData);
      setError('');
    } catch (err: any) {
      console.error('Failed to fetch data:', err);
      setError(err.response?.data?.message || 'Failed to load devices');
    } finally {
      setLoading(false);
    }
  };

  const filterDevices = () => {
    let filtered = devices;

    // Filter by status
    if (filterStatus === 'active') {
      filtered = filtered.filter(d => d.is_active);
    } else if (filterStatus === 'inactive') {
      filtered = filtered.filter(d => !d.is_active);
    }

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(d =>
        d.device_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        d.ip_address.includes(searchTerm) ||
        d.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        d.location?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    setFilteredDevices(filtered);
  };

  const handleShowModal = (device?: NetworkDevice) => {
    if (device) {
      setEditingDevice(device);
      setFormData({
        device_name: device.device_name,
        ip_address: device.ip_address,
        device_type_id: device.device_type_id,
        hostname: device.hostname || '',
        location: device.location || '',
        management_ip: device.management_ip || '',
        ssh_username: device.ssh_username || '',
        ssh_password: '',
        ssh_port: device.ssh_port,
        enable_password: '',
        description: device.description || ''
      });
    } else {
      setEditingDevice(null);
      setFormData({
        device_name: '',
        ip_address: '',
        device_type_id: deviceTypes.length > 0 ? deviceTypes[0].id : 0,
        hostname: '',
        location: '',
        management_ip: '',
        ssh_username: '',
        ssh_password: '',
        ssh_port: 22,
        enable_password: '',
        description: ''
      });
    }
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingDevice(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);

    try {
      if (editingDevice) {
        await DeviceService.updateDevice(editingDevice.id, formData);
        Swal.fire('Success', 'Device updated successfully', 'success');
      } else {
        await DeviceService.createDevice(formData);
        Swal.fire('Success', 'Device created successfully', 'success');
      }
      handleCloseModal();
      fetchData();
    } catch (err: any) {
      Swal.fire('Error', err.response?.data?.message || 'Operation failed', 'error');
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (device: NetworkDevice) => {
    const result = await Swal.fire({
      title: 'Are you sure?',
      text: `Delete device "${device.device_name}"?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#3085d6',
      confirmButtonText: 'Yes, delete it!'
    });

    if (result.isConfirmed) {
      try {
        await DeviceService.deleteDevice(device.id);
        Swal.fire('Deleted!', 'Device has been deleted.', 'success');
        fetchData();
      } catch (err: any) {
        Swal.fire('Error', err.response?.data?.message || 'Failed to delete device', 'error');
      }
    }
  };

  const handleTestConnection = async (device: NetworkDevice) => {
    Swal.fire({
      title: 'Testing Connection...',
      text: `Connecting to ${device.device_name}...`,
      allowOutsideClick: false,
      showConfirmButton: false,
      willOpen: () => {
        Swal.showLoading(null);
      }
    });

    try {
      const result = await DeviceService.testConnection(device.id);
      Swal.fire({
        title: result.success ? 'Success' : 'Failed',
        text: result.message,
        icon: result.success ? 'success' : 'error'
      });
    } catch (err: any) {
      Swal.fire('Error', err.response?.data?.message || 'Connection test failed', 'error');
    }
  };

  const getStatusBadge = (device: NetworkDevice) => {
    if (!device.is_active) {
      return <Badge bg="secondary">Inactive</Badge>;
    }
    
    switch (device.last_backup_status) {
      case 'success':
        return <Badge bg="success">Active</Badge>;
      case 'failed':
        return <Badge bg="danger">Failed</Badge>;
      case 'running':
        return <Badge bg="primary">Running</Badge>;
      default:
        return <Badge bg="warning">Pending</Badge>;
    }
  };

  if (loading) {
    return (
      <div className="text-center py-5">
        <Spinner animation="border" variant="primary" />
        <p className="mt-2">Loading devices...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2><FaServer className="me-2" />Device Management</h2>
        <div className="d-flex gap-2">
          <Button variant="outline-primary" onClick={fetchData}>
            <FaSync className="me-2" />Refresh
          </Button>
          <Button variant="primary" onClick={() => handleShowModal()}>
            <FaPlus className="me-2" />Add Device
          </Button>
        </div>
      </div>

      {error && <Alert variant="danger" dismissible onClose={() => setError('')}>{error}</Alert>}

      <Card className="mb-4">
        <Card.Body>
          <Row>
            <Col md={6}>
              <InputGroup>
                <InputGroup.Text><FaSearch /></InputGroup.Text>
                <Form.Control
                  placeholder="Search devices..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                />
              </InputGroup>
            </Col>
            <Col md={6}>
              <Form.Select
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value as any)}
              >
                <option value="all">All Devices</option>
                <option value="active">Active Only</option>
                <option value="inactive">Inactive Only</option>
              </Form.Select>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      <Card>
        <Card.Body>
          <Table responsive hover>
            <thead>
              <tr>
                <th>Device Name</th>
                <th>IP Address</th>
                <th>Type</th>
                <th>Location</th>
                <th>Status</th>
                <th>Last Backup</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredDevices.length > 0 ? (
                filteredDevices.map((device) => (
                  <tr key={device.id}>
                    <td>
                      <strong>{device.device_name}</strong>
                      {device.hostname && (
                        <><br /><small className="text-muted">{device.hostname}</small></>
                      )}
                    </td>
                    <td>{device.ip_address}</td>
                    <td>
                      {device.device_type ? (
                        <>
                          {device.device_type.vendor} {device.device_type.model}
                          {device.device_type.firmware_version && (
                            <><br /><small className="text-muted">v{device.device_type.firmware_version}</small></>
                          )}
                        </>
                      ) : (
                        'N/A'
                      )}
                    </td>
                    <td>{device.location || '-'}</td>
                    <td>{getStatusBadge(device)}</td>
                    <td>
                      {device.last_backup_date ? (
                        <small>{new Date(device.last_backup_date).toLocaleString()}</small>
                      ) : (
                        <small className="text-muted">Never</small>
                      )}
                    </td>
                    <td>
                      <div className="d-flex gap-1">
                        <Button
                          size="sm"
                          variant="outline-success"
                          onClick={() => handleTestConnection(device)}
                          title="Test Connection"
                        >
                          <FaCheckCircle />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-primary"
                          onClick={() => handleShowModal(device)}
                          title="Edit"
                        >
                          <FaEdit />
                        </Button>
                        <Button
                          size="sm"
                          variant="outline-danger"
                          onClick={() => handleDelete(device)}
                          title="Delete"
                        >
                          <FaTrash />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center text-muted py-4">
                    <FaServer size={50} className="mb-3 opacity-50" />
                    <p>No devices found</p>
                  </td>
                </tr>
              )}
            </tbody>
          </Table>
        </Card.Body>
      </Card>

      {/* Add/Edit Modal */}
      <Modal show={showModal} onHide={handleCloseModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>{editingDevice ? 'Edit Device' : 'Add New Device'}</Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSubmit}>
          <Modal.Body>
            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Device Name *</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.device_name}
                    onChange={(e) => setFormData({ ...formData, device_name: e.target.value })}
                    required
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>IP Address *</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.ip_address}
                    onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
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
                    value={formData.device_type_id}
                    onChange={(e) => setFormData({ ...formData, device_type_id: parseInt(e.target.value) })}
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
                    value={formData.hostname}
                    onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
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
                    value={formData.location}
                    onChange={(e) => setFormData({ ...formData, location: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Management IP</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.management_ip}
                    onChange={(e) => setFormData({ ...formData, management_ip: e.target.value })}
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
                    value={formData.ssh_username}
                    onChange={(e) => setFormData({ ...formData, ssh_username: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>SSH Port</Form.Label>
                  <Form.Control
                    type="number"
                    value={formData.ssh_port}
                    onChange={(e) => setFormData({ ...formData, ssh_port: parseInt(e.target.value) })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>SSH Password</Form.Label>
                  <Form.Control
                    type="password"
                    value={formData.ssh_password}
                    onChange={(e) => setFormData({ ...formData, ssh_password: e.target.value })}
                    placeholder={editingDevice ? '(leave blank to keep current)' : ''}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group className="mb-3">
                  <Form.Label>Enable Password</Form.Label>
                  <Form.Control
                    type="password"
                    value={formData.enable_password}
                    onChange={(e) => setFormData({ ...formData, enable_password: e.target.value })}
                    placeholder={editingDevice ? '(leave blank to keep current)' : ''}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Form.Group className="mb-3">
              <Form.Label>Description</Form.Label>
              <Form.Control
                as="textarea"
                rows={3}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
              />
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={handleCloseModal} disabled={submitting}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={submitting}>
              {submitting ? (
                <><Spinner animation="border" size="sm" className="me-2" />Saving...</>
              ) : (
                editingDevice ? 'Update Device' : 'Create Device'
              )}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </div>
  );
};

export default DeviceManagement;
