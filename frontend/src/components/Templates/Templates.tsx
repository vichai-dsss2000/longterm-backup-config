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
  Tooltip,
  Nav,
  Tab
} from 'react-bootstrap';
import {
  Plus,
  Edit,
  Trash2,
  Copy,
  CheckCircle,
  Search,
  Filter,
  FileText,
  Code,
  Settings,
  Eye,
  RefreshCw
} from 'lucide-react';
import { TemplateService, BackupTemplate, BackupTemplateCreate } from '../../services/templateService';
import { DeviceService, DeviceType } from '../../services/deviceService';
import Swal from 'sweetalert2';

const Templates: React.FC = () => {
  // State management
  const [templates, setTemplates] = useState<BackupTemplate[]>([]);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Modal states
  const [showModal, setShowModal] = useState(false);
  const [showViewModal, setShowViewModal] = useState(false);
  const [editingTemplate, setEditingTemplate] = useState<BackupTemplate | null>(null);
  const [viewingTemplate, setViewingTemplate] = useState<BackupTemplate | null>(null);

  // Form state
  const [formData, setFormData] = useState<BackupTemplateCreate>({
    device_type_id: 0,
    template_name: '',
    template_description: '',
    backup_command: '',
    command_format: 'TEXT',
    template_variables: {},
    timeout_seconds: 300,
    retry_count: 3,
    retry_interval_seconds: 60
  });

  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [filterDeviceType, setFilterDeviceType] = useState<number | null>(null);
  const [filterFormat, setFilterFormat] = useState<string>('all');
  const [showInactive, setShowInactive] = useState(false);

  // Load data
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params: any = {};
      if (filterDeviceType) params.device_type_id = filterDeviceType;
      if (!showInactive) params.is_active = true;

      const [templatesData, deviceTypesData] = await Promise.all([
        TemplateService.getTemplates(params),
        DeviceService.getDeviceTypes()
      ]);

      setTemplates(templatesData);
      setDeviceTypes(deviceTypesData);
      setError(null);
    } catch (err: any) {
      setError('Failed to load templates');
      console.error('Error loading data:', err);
    } finally {
      setLoading(false);
    }
  }, [filterDeviceType, showInactive]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handlers
  const openCreateModal = () => {
    setEditingTemplate(null);
    setFormData({
      device_type_id: 0,
      template_name: '',
      template_description: '',
      backup_command: '',
      command_format: 'TEXT',
      template_variables: {},
      timeout_seconds: 300,
      retry_count: 3,
      retry_interval_seconds: 60
    });
    setShowModal(true);
  };

  const openEditModal = (template: BackupTemplate) => {
    setEditingTemplate(template);
    setFormData({
      device_type_id: template.device_type_id,
      template_name: template.template_name,
      template_description: template.template_description,
      backup_command: template.backup_command,
      command_format: template.command_format,
      template_variables: template.template_variables,
      timeout_seconds: template.timeout_seconds,
      retry_count: template.retry_count,
      retry_interval_seconds: template.retry_interval_seconds
    });
    setShowModal(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (editingTemplate) {
        await TemplateService.updateTemplate(editingTemplate.id, formData);
        setSuccess('Template updated successfully');
      } else {
        await TemplateService.createTemplate(formData);
        setSuccess('Template created successfully');
      }
      setShowModal(false);
      loadData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save template');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (template: BackupTemplate) => {
    const result = await Swal.fire({
      title: 'Delete Template?',
      text: `Are you sure you want to delete "${template.template_name}"?`,
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#d33',
      cancelButtonColor: '#6c757d',
      confirmButtonText: 'Yes, delete it!'
    });

    if (result.isConfirmed) {
      try {
        await TemplateService.deleteTemplate(template.id);
        setSuccess('Template deleted successfully');
        loadData();
      } catch (err: any) {
        setError(err.response?.data?.detail || 'Failed to delete template');
      }
    }
  };

  const handleDuplicate = async (template: BackupTemplate) => {
    setEditingTemplate(null);
    setFormData({
      device_type_id: template.device_type_id,
      template_name: `${template.template_name} (Copy)`,
      template_description: template.template_description,
      backup_command: template.backup_command,
      command_format: template.command_format,
      template_variables: template.template_variables,
      timeout_seconds: template.timeout_seconds,
      retry_count: template.retry_count,
      retry_interval_seconds: template.retry_interval_seconds
    });
    setShowModal(true);
  };

  const handleValidate = async (template: BackupTemplate) => {
    try {
      const result = await TemplateService.validateTemplate(template.id);
      if (result.valid) {
        Swal.fire('Valid Template', result.message, 'success');
      } else {
        Swal.fire('Invalid Template', result.message, 'error');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to validate template');
    }
  };

  const handleViewTemplate = (template: BackupTemplate) => {
    setViewingTemplate(template);
    setShowViewModal(true);
  };

  // Filter templates
  const filteredTemplates = templates.filter(template => {
    const matchesSearch = searchTerm === '' ||
      template.template_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      template.template_description?.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesFormat = filterFormat === 'all' || template.command_format === filterFormat;
    return matchesSearch && matchesFormat;
  });

  // Utility functions
  const getDeviceTypeName = (deviceTypeId: number) => {
    const deviceType = deviceTypes.find(dt => dt.id === deviceTypeId);
    return deviceType ? `${deviceType.vendor} ${deviceType.model}` : 'Unknown';
  };

  const getFormatBadge = (format: string) => {
    const formatConfig: any = {
      TEXT: { bg: 'secondary', icon: FileText },
      JSON: { bg: 'info', icon: Code },
      XML: { bg: 'warning', icon: Code },
      YAML: { bg: 'primary', icon: Code }
    };

    const config = formatConfig[format] || formatConfig.TEXT;
    const Icon = config.icon;

    return (
      <Badge bg={config.bg}>
        <Icon size={12} className="me-1" />
        {format}
      </Badge>
    );
  };

  return (
    <Container fluid>
      {/* Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h2>Backup Templates</h2>
            <div className="d-flex gap-2">
              <Button variant="outline-primary" onClick={loadData} disabled={loading}>
                <RefreshCw size={16} className={loading ? 'spinner-icon' : ''} />
              </Button>
              <Button variant="primary" onClick={openCreateModal}>
                <Plus size={16} className="me-2" />
                Create Template
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

      {/* Filters */}
      <Card className="mb-4">
        <Card.Body>
          <Row className="align-items-end">
            <Col md={4}>
              <Form.Group>
                <Form.Label>Search</Form.Label>
                <InputGroup>
                  <InputGroup.Text>
                    <Search size={16} />
                  </InputGroup.Text>
                  <FormControl
                    placeholder="Search templates..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </InputGroup>
              </Form.Group>
            </Col>
            <Col md={3}>
              <Form.Group>
                <Form.Label>Device Type</Form.Label>
                <Form.Select
                  value={filterDeviceType || ''}
                  onChange={(e) => setFilterDeviceType(e.target.value ? Number(e.target.value) : null)}
                >
                  <option value="">All Device Types</option>
                  {deviceTypes.map(type => (
                    <option key={type.id} value={type.id}>
                      {type.vendor} {type.model}
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>Format</Form.Label>
                <Form.Select
                  value={filterFormat}
                  onChange={(e) => setFilterFormat(e.target.value)}
                >
                  <option value="all">All Formats</option>
                  <option value="TEXT">TEXT</option>
                  <option value="JSON">JSON</option>
                  <option value="XML">XML</option>
                  <option value="YAML">YAML</option>
                </Form.Select>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Check
                type="checkbox"
                label="Show Inactive"
                checked={showInactive}
                onChange={(e) => setShowInactive(e.target.checked)}
              />
            </Col>
            <Col md={1}>
              <Button variant="outline-secondary" onClick={loadData}>
                <Filter size={16} />
              </Button>
            </Col>
          </Row>
        </Card.Body>
      </Card>

      {/* Templates Table */}
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
                  <th>Template Name</th>
                  <th>Device Type</th>
                  <th>Format</th>
                  <th>Timeout</th>
                  <th>Retry</th>
                  <th>Version</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredTemplates.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-4 text-muted">
                      No templates found
                    </td>
                  </tr>
                ) : (
                  filteredTemplates.map(template => (
                    <tr key={template.id}>
                      <td>
                        <strong>{template.template_name}</strong>
                        {template.template_description && (
                          <>
                            <br />
                            <small className="text-muted">{template.template_description}</small>
                          </>
                        )}
                      </td>
                      <td>
                        <small>{getDeviceTypeName(template.device_type_id)}</small>
                      </td>
                      <td>{getFormatBadge(template.command_format)}</td>
                      <td>
                        <small>{template.timeout_seconds}s</small>
                      </td>
                      <td>
                        <Badge bg="info">
                          {template.retry_count} × {template.retry_interval_seconds}s
                        </Badge>
                      </td>
                      <td>
                        <Badge bg="secondary">{template.version}</Badge>
                      </td>
                      <td>
                        <Badge bg={template.is_active ? 'success' : 'danger'}>
                          {template.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td>
                        <div className="d-flex gap-1">
                          <OverlayTrigger overlay={<Tooltip>View</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-info"
                              onClick={() => handleViewTemplate(template)}
                            >
                              <Eye size={14} />
                            </Button>
                          </OverlayTrigger>

                          <OverlayTrigger overlay={<Tooltip>Edit</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-primary"
                              onClick={() => openEditModal(template)}
                            >
                              <Edit size={14} />
                            </Button>
                          </OverlayTrigger>

                          <OverlayTrigger overlay={<Tooltip>Duplicate</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-secondary"
                              onClick={() => handleDuplicate(template)}
                            >
                              <Copy size={14} />
                            </Button>
                          </OverlayTrigger>

                          <OverlayTrigger overlay={<Tooltip>Validate</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-success"
                              onClick={() => handleValidate(template)}
                            >
                              <CheckCircle size={14} />
                            </Button>
                          </OverlayTrigger>

                          <OverlayTrigger overlay={<Tooltip>Delete</Tooltip>}>
                            <Button
                              size="sm"
                              variant="outline-danger"
                              onClick={() => handleDelete(template)}
                            >
                              <Trash2 size={14} />
                            </Button>
                          </OverlayTrigger>
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

      {/* Create/Edit Modal */}
      <Modal show={showModal} onHide={() => setShowModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>
            {editingTemplate ? 'Edit Template' : 'Create New Template'}
          </Modal.Title>
        </Modal.Header>
        <Form onSubmit={handleSubmit}>
          <Modal.Body>
            <Tab.Container defaultActiveKey="basic">
              <Nav variant="tabs" className="mb-3">
                <Nav.Item>
                  <Nav.Link eventKey="basic">Basic Info</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                  <Nav.Link eventKey="command">Backup Command</Nav.Link>
                </Nav.Item>
                <Nav.Item>
                  <Nav.Link eventKey="settings">Settings</Nav.Link>
                </Nav.Item>
              </Nav>

              <Tab.Content>
                <Tab.Pane eventKey="basic">
                  <Form.Group className="mb-3">
                    <Form.Label>Template Name *</Form.Label>
                    <Form.Control
                      type="text"
                      value={formData.template_name}
                      onChange={(e) => setFormData({ ...formData, template_name: e.target.value })}
                      required
                      placeholder="e.g., Cisco IOS Full Backup"
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Device Type *</Form.Label>
                    <Form.Select
                      value={formData.device_type_id}
                      onChange={(e) => setFormData({ ...formData, device_type_id: Number(e.target.value) })}
                      required
                    >
                      <option value="">Select device type...</option>
                      {deviceTypes.map(type => (
                        <option key={type.id} value={type.id}>
                          {type.vendor} {type.model} {type.firmware_version ? `v${type.firmware_version}` : ''}
                        </option>
                      ))}
                    </Form.Select>
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Description</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={3}
                      value={formData.template_description}
                      onChange={(e) => setFormData({ ...formData, template_description: e.target.value })}
                      placeholder="Describe what this template does..."
                    />
                  </Form.Group>

                  <Form.Group className="mb-3">
                    <Form.Label>Command Format</Form.Label>
                    <Form.Select
                      value={formData.command_format}
                      onChange={(e) => setFormData({ ...formData, command_format: e.target.value as any })}
                    >
                      <option value="TEXT">TEXT</option>
                      <option value="JSON">JSON</option>
                      <option value="XML">XML</option>
                      <option value="YAML">YAML</option>
                    </Form.Select>
                  </Form.Group>
                </Tab.Pane>

                <Tab.Pane eventKey="command">
                  <Form.Group className="mb-3">
                    <Form.Label>Backup Command *</Form.Label>
                    <Form.Control
                      as="textarea"
                      rows={10}
                      value={formData.backup_command}
                      onChange={(e) => setFormData({ ...formData, backup_command: e.target.value })}
                      required
                      placeholder="Enter backup command template..."
                      style={{ fontFamily: 'monospace' }}
                    />
                    <Form.Text className="text-muted">
                      Use variables like {'{device_ip}'}, {'{username}'}, {'{password}'}, etc.
                    </Form.Text>
                  </Form.Group>

                  <Alert variant="info">
                    <strong>Example Variables:</strong>
                    <ul className="mb-0 mt-2">
                      <li><code>{'{device_ip}'}</code> - Device IP address</li>
                      <li><code>{'{device_name}'}</code> - Device name</li>
                      <li><code>{'{username}'}</code> - SSH username</li>
                      <li><code>{'{password}'}</code> - SSH password</li>
                      <li><code>{'{timestamp}'}</code> - Current timestamp</li>
                      <li><code>{'{backup_path}'}</code> - Backup destination path</li>
                    </ul>
                  </Alert>
                </Tab.Pane>

                <Tab.Pane eventKey="settings">
                  <Row>
                    <Col md={4}>
                      <Form.Group className="mb-3">
                        <Form.Label>Timeout (seconds)</Form.Label>
                        <Form.Control
                          type="number"
                          value={formData.timeout_seconds}
                          onChange={(e) => setFormData({ ...formData, timeout_seconds: Number(e.target.value) })}
                          min={30}
                          max={3600}
                        />
                      </Form.Group>
                    </Col>
                    <Col md={4}>
                      <Form.Group className="mb-3">
                        <Form.Label>Retry Count</Form.Label>
                        <Form.Control
                          type="number"
                          value={formData.retry_count}
                          onChange={(e) => setFormData({ ...formData, retry_count: Number(e.target.value) })}
                          min={0}
                          max={10}
                        />
                      </Form.Group>
                    </Col>
                    <Col md={4}>
                      <Form.Group className="mb-3">
                        <Form.Label>Retry Interval (seconds)</Form.Label>
                        <Form.Control
                          type="number"
                          value={formData.retry_interval_seconds}
                          onChange={(e) => setFormData({ ...formData, retry_interval_seconds: Number(e.target.value) })}
                          min={10}
                          max={600}
                        />
                      </Form.Group>
                    </Col>
                  </Row>

                  <Alert variant="warning">
                    <Settings size={16} className="me-2" />
                    <strong>Settings Guide:</strong>
                    <ul className="mb-0 mt-2">
                      <li>Set appropriate timeout based on device complexity</li>
                      <li>Configure retry attempts for network instability</li>
                      <li>Adjust retry interval to avoid overwhelming devices</li>
                    </ul>
                  </Alert>
                </Tab.Pane>
              </Tab.Content>
            </Tab.Container>
          </Modal.Body>
          <Modal.Footer>
            <Button variant="secondary" onClick={() => setShowModal(false)} disabled={loading}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={loading}>
              {loading ? (
                <>
                  <Spinner animation="border" size="sm" className="me-2" />
                  Saving...
                </>
              ) : (
                editingTemplate ? 'Update Template' : 'Create Template'
              )}
            </Button>
          </Modal.Footer>
        </Form>
      </Modal>

      {/* View Template Modal */}
      <Modal show={showViewModal} onHide={() => setShowViewModal(false)} size="lg">
        <Modal.Header closeButton>
          <Modal.Title>Template Details</Modal.Title>
        </Modal.Header>
        <Modal.Body>
          {viewingTemplate && (
            <div>
              <Row className="mb-3">
                <Col md={6}>
                  <strong>Template Name:</strong><br />
                  {viewingTemplate.template_name}
                </Col>
                <Col md={6}>
                  <strong>Device Type:</strong><br />
                  {getDeviceTypeName(viewingTemplate.device_type_id)}
                </Col>
              </Row>
              <Row className="mb-3">
                <Col md={4}>
                  <strong>Format:</strong> {getFormatBadge(viewingTemplate.command_format)}
                </Col>
                <Col md={4}>
                  <strong>Version:</strong> <Badge bg="secondary">{viewingTemplate.version}</Badge>
                </Col>
                <Col md={4}>
                  <strong>Status:</strong>{' '}
                  <Badge bg={viewingTemplate.is_active ? 'success' : 'danger'}>
                    {viewingTemplate.is_active ? 'Active' : 'Inactive'}
                  </Badge>
                </Col>
              </Row>
              {viewingTemplate.template_description && (
                <Row className="mb-3">
                  <Col>
                    <strong>Description:</strong><br />
                    <p className="text-muted">{viewingTemplate.template_description}</p>
                  </Col>
                </Row>
              )}
              <Row className="mb-3">
                <Col>
                  <strong>Backup Command:</strong>
                  <pre className="bg-light p-3 rounded mt-2" style={{ maxHeight: '300px', overflow: 'auto' }}>
                    <code>{viewingTemplate.backup_command}</code>
                  </pre>
                </Col>
              </Row>
              <Row className="mb-3">
                <Col md={4}>
                  <strong>Timeout:</strong> {viewingTemplate.timeout_seconds}s
                </Col>
                <Col md={4}>
                  <strong>Retry Count:</strong> {viewingTemplate.retry_count}
                </Col>
                <Col md={4}>
                  <strong>Retry Interval:</strong> {viewingTemplate.retry_interval_seconds}s
                </Col>
              </Row>
              <Row>
                <Col md={6}>
                  <strong>Created:</strong><br />
                  <small>{new Date(viewingTemplate.created_at).toLocaleString()}</small>
                </Col>
                <Col md={6}>
                  <strong>Updated:</strong><br />
                  <small>{new Date(viewingTemplate.updated_at).toLocaleString()}</small>
                </Col>
              </Row>
            </div>
          )}
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={() => setShowViewModal(false)}>
            Close
          </Button>
          {viewingTemplate && (
            <Button variant="primary" onClick={() => {
              setShowViewModal(false);
              openEditModal(viewingTemplate);
            }}>
              <Edit size={16} className="me-2" />
              Edit Template
            </Button>
          )}
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

export default Templates;