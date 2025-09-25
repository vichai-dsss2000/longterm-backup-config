import React, { useState, useEffect } from 'react';
import { 
  Table, 
  Button, 
  Modal, 
  Form, 
  Alert, 
  Badge,
  ButtonGroup,
  Card 
} from 'react-bootstrap';
import { FaPlus, FaEdit, FaTrash, FaPlay, FaServer } from 'react-icons/fa';
import axios from 'axios';
import Swal from 'sweetalert2';

interface Device {
  id: number;
  device_name: string;
  ip_address: string;
  hostname?: string;
  location?: string;
  device_type_id: number;
  device_type?: {
    vendor: string;
    model: string;
    firmware_version?: string;
  };
  is_active: boolean;
  last_backup_date?: string;
  last_backup_status?: string;
}

interface DeviceType {
  id: number;
  vendor: string;
  model: string;
  firmware_version?: string;
}

const DeviceManagement: React.FC = () => {
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  const [showModal, setShowModal] = useState(false);
  const [editingDevice, setEditingDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Form state
  const [formData, setFormData] = useState({
    device_name: '',
    ip_address: '',
    hostname: '',
    location: '',
    device_type_id: '',
    ssh_username: '',
    ssh_password: '',
    ssh_port: 22,
    is_active: true
  });

  useEffect(() => {
    fetchDevices();
    fetchDeviceTypes();
  }, []);

  const fetchDevices = async () => {
    try {
      console.log('Fetching devices...');
      const response = await axios.get('/api/devices/');
      console.log('Devices response:', response.data);
      setDevices(response.data);
    } catch (err) {
      console.error('Failed to fetch devices:', err);
      setError('Failed to load devices');
    } finally {
      setLoading(false);
    }
  };

  const fetchDeviceTypes = async () => {
    try {
      console.log('Fetching device types...');
      const response = await axios.get('/api/devices/types');
      console.log('Device types response:', response.data);
      setDeviceTypes(response.data);
    } catch (error) {
      console.error('Failed to fetch device types:', error);
    
    }
  };

  const handleShowModal = (device?: Device) => {
    if (device) {
      setEditingDevice(device);
      setFormData({
        device_name: device.device_name,
        ip_address: device.ip_address,
        hostname: device.hostname || '',
        location: device.location || '',
        device_type_id: device.device_type_id.toString(),
        ssh_username: '',
        ssh_password: '',
        ssh_port: 22,
        is_active: device.is_active
      });
    } else {
      setEditingDevice(null);
      setFormData({
        device_name: '',
        ip_address: '',
        hostname: '',
        location: '',
        device_type_id: '',
        ssh_username: '',
        ssh_password: '',
        ssh_port: 22,
        is_active: true
      });
    }
    setShowModal(true);
  };

  const handleCloseModal = () => {
    setShowModal(false);
    setEditingDevice(null);
    setError('');
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const deviceData = {
        ...formData,
        device_type_id: parseInt(formData.device_type_id)
      };

      console.log('Submitting device data:', deviceData);

      if (editingDevice) {
        const response = await axios.put(`/api/devices/${editingDevice.id}`, deviceData);
        console.log('Update response:', response.data);
        Swal.fire('Success!', 'Device updated successfully', 'success');
      } else {
        const response = await axios.post('/api/devices/', deviceData);
        console.log('Create response:', response.data);
        Swal.fire('Success!', 'Device created successfully', 'success');
      }

      handleCloseModal();
      fetchDevices();
    } catch (err) {
      console.error('Failed to save device:', err);
      setError('Failed to save device. Please check console for details.');
    }
  };

  const handleDelete = async (device: Device) => {
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
        await axios.delete(`/api/devices/${device.id}`);
        Swal.fire('Deleted!', 'Device has been deleted.', 'success');
        fetchDevices();
      } catch (err) {
        console.error('Failed to delete device:', err);
        Swal.fire('Error!', 'Failed to delete device.', 'error');
      }
    }
  };

  const handleTestConnection = async (device: Device) => {
    try {
      setLoading(true);
      const response = await axios.post(`/api/devices/${device.id}/test-connection`);
      
      if (response.data.success) {
        Swal.fire('Success!', 'Connection test successful', 'success');
      } else {
        Swal.fire('Failed!', response.data.error || 'Connection test failed', 'error');
      }
    } catch (err) {
      console.error('Connection test failed:', err);
      Swal.fire('Error!', 'Connection test failed', 'error');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status?: string) => {
    switch (status) {
      case 'success':
        return <Badge bg="success">Success</Badge>;
      case 'failed':
        return <Badge bg="danger">Failed</Badge>;
      case 'pending':
        return <Badge bg="warning">Pending</Badge>;
      default:
        return <Badge bg="secondary">Unknown</Badge>;
    }
  };

  if (loading) {
    return (
      <div className="text-center py-5">
        <div className="spinner-border text-primary" />
        <p className="mt-2">Loading devices...</p>
      </div>
    );
  }

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-4">
        <h2>Device Management</h2>
        <Button variant="primary" onClick={() => handleShowModal()}>
          <FaPlus className="me-1" />
          Add Device
        </Button>
      </div>

      {error && <Alert variant="danger">{error}</Alert>}

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
              {devices.map((device) => (
                <tr key={device.id}>
                  <td>
                    <FaServer className="me-2 text-primary" />
                    {device.device_name}
                  </td>
                  <td>{device.ip_address}</td>
                  <td>
                    {device.device_type ? (
                      <span>
                        {device.device_type.vendor} {device.device_type.model}
                        {device.device_type.firmware_version && (
                          <small className="text-muted d-block">
                            {device.device_type.firmware_version}
                          </small>
                        )}
                      </span>
                    ) : (
                      'Unknown'
                    )}
                  </td>
                  <td>{device.location || '-'}</td>
                  <td>
                    <Badge bg={device.is_active ? 'success' : 'secondary'}>
                      {device.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                  <td>
                    {device.last_backup_date ? (
                      <div>
                        {getStatusBadge(device.last_backup_status)}
                        <small className="text-muted d-block">
                          {new Date(device.last_backup_date).toLocaleString()}
                        </small>
                      </div>
                    ) : (
                      'Never'
                    )}
                  </td>
                  <td>
                    <ButtonGroup size="sm">
                      <Button
                        variant="outline-primary"
                        onClick={() => handleTestConnection(device)}
                        title="Test Connection"
                      >
                        <FaPlay />
                      </Button>
                      <Button
                        variant="outline-secondary"
                        onClick={() => handleShowModal(device)}
                        title="Edit"
                      >
                        <FaEdit />
                      </Button>
                      <Button
                        variant="outline-danger"
                        onClick={() => handleDelete(device)}
                        title="Delete"
                      >
                        <FaTrash />
                      </Button>
                    </ButtonGroup>
                  </td>
                </tr>
              ))}
            </tbody>
          </Table>

          {devices.length === 0 && (
            <div className="text-center py-4 text-muted">
              No devices found. Add your first device to get started.
            </div>
          )}
        </Card.Body>
      </Card>

      {/* Add/Edit Device Modal */}
      <Modal show={showModal} onHide={handleCloseModal} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            {editingDevice ? 'Edit Device' : 'Add New Device'}
          </Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSubmit}>
          <Modal.Body>
            {error && <Alert variant="danger">{error}</Alert>}
            
            <Form.Group className="mb-3">
              <Form.Label>Device Name *</Form.Label>
              <Form.Control
                type="text"
                value={formData.device_name}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, device_name: e.target.value})}
                required
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>IP Address *</Form.Label>
              <Form.Control
                type="text"
                value={formData.ip_address}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, ip_address: e.target.value})}
                required
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Device Type *</Form.Label>
              <Form.Select
                value={formData.device_type_id}
                onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setFormData({...formData, device_type_id: e.target.value})}
                required
              >
                <option value="">Select Device Type</option>
                {deviceTypes.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.vendor} {type.model} {type.firmware_version}
                  </option>
                ))}
              </Form.Select>
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Hostname</Form.Label>
              <Form.Control
                type="text"
                value={formData.hostname}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, hostname: e.target.value})}
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>Location</Form.Label>
              <Form.Control
                type="text"
                value={formData.location}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, location: e.target.value})}
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>SSH Username *</Form.Label>
              <Form.Control
                type="text"
                value={formData.ssh_username}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, ssh_username: e.target.value})}
                required
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>SSH Password *</Form.Label>
              <Form.Control
                type="password"
                value={formData.ssh_password}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, ssh_password: e.target.value})}
                required={!editingDevice}
                placeholder={editingDevice ? "Leave empty to keep current password" : ""}
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Label>SSH Port</Form.Label>
              <Form.Control
                type="number"
                value={formData.ssh_port}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, ssh_port: parseInt(e.target.value)})}
              />
            </Form.Group>

            <Form.Group className="mb-3">
              <Form.Check
                type="checkbox"
                label="Active"
                checked={formData.is_active}
                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setFormData({...formData, is_active: e.target.checked})}
              />
            </Form.Group>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={handleCloseModal}>
              Cancel
            </Button>
            <Button variant="primary" type="submit">
              {editingDevice ? 'Update' : 'Create'}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>
    </div>
  );
};

export default DeviceManagement;