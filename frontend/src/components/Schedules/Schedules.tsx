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
  OverlayTrigger,
  Tooltip
} from 'react-bootstrap';
import { 
  Plus, 
  Edit, 
  Trash2, 
  Play, 
  Eye, 
  Search,
  Filter,
  Clock,
  Mail,
  Shield,
  Archive
} from 'lucide-react';
import ScheduleService from '../../services/scheduleService';
import {
  SchedulerJob,
  SchedulerJobCreate,
  JobCategory,
  BackupTemplate,
  DeviceType
} from '../../types/scheduler';
import SchedulerJobModal from './SchedulerJobModal';
import JobDetailsModal from './JobDetailsModal';
import DeleteConfirmationModal from './DeleteConfirmationModal';

const Schedules: React.FC = () => {
  // State management
  const [jobs, setJobs] = useState<SchedulerJob[]>([]);
  const [categories, setCategories] = useState<JobCategory[]>([]);
  const [templates, setTemplates] = useState<BackupTemplate[]>([]);
  const [deviceTypes, setDeviceTypes] = useState<DeviceType[]>([]);
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  
  // Modal states
  const [showModal, setShowModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [editingJob, setEditingJob] = useState<SchedulerJob | null>(null);
  const [jobToDelete, setJobToDelete] = useState<SchedulerJob | null>(null);
  const [viewingJob, setViewingJob] = useState<SchedulerJob | null>(null);
  
  // Form state
  const [formData, setFormData] = useState<SchedulerJobCreate>({
    policy_name: '',
    template_id: 0,
    cron_expression: '',
    backup_path: '',
    sftp_port: 22,
    retention_days: 30,
    compression_enabled: true,
    encryption_enabled: false,
    notification_enabled: true,
    notification_emails: []
  });
  
  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [filterCategory, setFilterCategory] = useState<number | null>(null);
  const [filterDeviceType, setFilterDeviceType] = useState<number | null>(null);
  const [showInactive, setShowInactive] = useState(false);

  // Load data
  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [jobsData, categoriesData, templatesData, deviceTypesData] = await Promise.all([
        ScheduleService.getSchedulerJobs({ active_only: !showInactive }),
        ScheduleService.getJobCategories(),
        ScheduleService.getBackupTemplates(),
        ScheduleService.getDeviceTypes()
      ]);
      
      setJobs(jobsData);
      setCategories(categoriesData);
      setTemplates(templatesData);
      setDeviceTypes(deviceTypesData);
      setError(null);
    } catch (err) {
      setError('Failed to load scheduler jobs');
      console.error('Error loading data:', err);
    } finally {
      setLoading(false);
    }
  }, [showInactive]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle form submission
  const handleSubmit = async (data: SchedulerJobCreate) => {
    setLoading(true);
    
    try {
      if (editingJob) {
        await ScheduleService.updateSchedulerJob(editingJob.id, data);
        setSuccess('Scheduler job updated successfully');
      } else {
        await ScheduleService.createSchedulerJob(data);
        setSuccess('Scheduler job created successfully');
      }
      
      setShowModal(false);
      resetForm();
      loadData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save scheduler job');
    } finally {
      setLoading(false);
    }
  };

  // Handle delete
  const handleDelete = async () => {
    if (!jobToDelete) {
      return;
    }
    
    setLoading(true);
    try {
      await ScheduleService.deleteSchedulerJob(jobToDelete.id);
      setSuccess('Scheduler job deleted successfully');
      setShowDeleteModal(false);
      setJobToDelete(null);
      loadData();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to delete scheduler job');
    } finally {
      setLoading(false);
    }
  };

  // Handle trigger job
  const handleTriggerJob = async (job: SchedulerJob) => {
    setLoading(true);
    try {
      await ScheduleService.triggerSchedulerJob(job.id);
      setSuccess(`Triggered backup job: ${job.policy_name}`);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to trigger job');
    } finally {
      setLoading(false);
    }
  };

  // Form helpers
  const resetForm = () => {
    setFormData({
      policy_name: '',
      template_id: 0,
      cron_expression: '',
      backup_path: '',
      sftp_port: 22,
      retention_days: 30,
      compression_enabled: true,
      encryption_enabled: false,
      notification_enabled: true,
      notification_emails: []
    });
    setEditingJob(null);
  };

  const openCreateModal = () => {
    resetForm();
    setShowModal(true);
  };

  const openEditModal = (job: SchedulerJob) => {
    setEditingJob(job);
    setFormData({
      policy_name: job.policy_name,
      device_type_id: job.device_type_id,
      template_id: job.template_id,
      job_category_id: job.job_category_id,
      cron_expression: job.cron_expression,
      backup_path: job.backup_path,
      sftp_server_ip: job.sftp_server_ip,
      sftp_username: job.sftp_username,
      sftp_port: job.sftp_port,
      retention_days: job.retention_days,
      compression_enabled: job.compression_enabled,
      encryption_enabled: job.encryption_enabled,
      notification_enabled: job.notification_enabled,
      notification_emails: job.notification_emails || []
    });
    setShowModal(true);
  };

  const openDeleteModal = (job: SchedulerJob) => {
    setJobToDelete(job);
    setShowDeleteModal(true);
  };

  // Filter jobs based on search and filters
  const filteredJobs = jobs.filter(job => {
    const matchesSearch = job.policy_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         job.backup_path.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesCategory = !filterCategory || job.job_category_id === filterCategory;
    const matchesDeviceType = !filterDeviceType || job.device_type_id === filterDeviceType;
    
    return matchesSearch && matchesCategory && matchesDeviceType;
  });

  // Utility functions
  const getCategoryBadge = (categoryId?: number) => {
    const category = categories.find(c => c.id === categoryId);
    if (!category) {
      return null;
    }
    
    return (
      <Badge 
        bg="info" 
        style={{ backgroundColor: category.color_code || '#17a2b8' }}
      >
        {category.category_name}
      </Badge>
    );
  };

  const getTemplateName = (templateId: number) => {
    const template = templates.find(t => t.id === templateId);
    return template?.template_name || 'Unknown Template';
  };

  const formatCronExpression = (cron: string) => {
    // Simple cron to human readable conversion
    const presets = ScheduleService.getCronPresets();
    const preset = presets.find(p => p.value === cron);
    return preset ? preset.label : cron;
  };

  return (
    <Container fluid>
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h2>Backup Schedules</h2>
            <Button variant="primary" onClick={openCreateModal}>
              <Plus size={16} className="me-2" />
              Create Schedule
            </Button>
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
                    placeholder="Search schedules..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />
                </InputGroup>
              </Form.Group>
            </Col>
            <Col md={2}>
              <Form.Group>
                <Form.Label>Category</Form.Label>
                <Form.Select
                  value={filterCategory || ''}
                  onChange={(e) => setFilterCategory(e.target.value ? Number(e.target.value) : null)}
                >
                  <option value="">All Categories</option>
                  {categories.map(category => (
                    <option key={category.id} value={category.id}>
                      {category.category_name}
                    </option>
                  ))}
                </Form.Select>
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
              <Form.Check
                type="checkbox"
                label="Show Inactive"
                checked={showInactive}
                onChange={(e) => {
                  setShowInactive(e.target.checked);
                  // Reload data when filter changes
                  if (e.target.checked !== showInactive) {
                    setTimeout(loadData, 100);
                  }
                }}
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
                  <th>Policy Name</th>
                  <th>Category</th>
                  <th>Template</th>
                  <th>Schedule</th>
                  <th>Backup Path</th>
                  <th>Features</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredJobs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="text-center py-4 text-muted">
                      No scheduler jobs found
                    </td>
                  </tr>
                ) : (
                  filteredJobs.map(job => (
                    <tr key={job.id}>
                      <td>
                        <strong>{job.policy_name}</strong>
                      </td>
                      <td>
                        {getCategoryBadge(job.job_category_id)}
                      </td>
                      <td>
                        <small className="text-muted">
                          {getTemplateName(job.template_id)}
                        </small>
                      </td>
                      <td>
                        <OverlayTrigger
                          overlay={<Tooltip>{job.cron_expression}</Tooltip>}
                        >
                          <Badge bg="secondary">
                            <Clock size={12} className="me-1" />
                            {formatCronExpression(job.cron_expression)}
                          </Badge>
                        </OverlayTrigger>
                      </td>
                      <td>
                        <small className="text-muted">{job.backup_path}</small>
                      </td>
                      <td>
                        <div className="d-flex gap-1">
                          {job.compression_enabled && (
                            <OverlayTrigger overlay={<Tooltip>Compression Enabled</Tooltip>}>
                              <Badge bg="info" className="p-1">
                                <Archive size={12} />
                              </Badge>
                            </OverlayTrigger>
                          )}
                          {job.encryption_enabled && (
                            <OverlayTrigger overlay={<Tooltip>Encryption Enabled</Tooltip>}>
                              <Badge bg="warning" className="p-1">
                                <Shield size={12} />
                              </Badge>
                            </OverlayTrigger>
                          )}
                          {job.notification_enabled && (
                            <OverlayTrigger overlay={<Tooltip>Notifications Enabled</Tooltip>}>
                              <Badge bg="success" className="p-1">
                                <Mail size={12} />
                              </Badge>
                            </OverlayTrigger>
                          )}
                        </div>
                      </td>
                      <td>
                        <Badge bg={job.is_active ? 'success' : 'danger'}>
                          {job.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </td>
                      <td>
                        <div className="d-flex gap-1">
                          <OverlayTrigger overlay={<Tooltip>View Details</Tooltip>}>
                            <Button 
                              size="sm" 
                              variant="outline-info"
                              onClick={() => setViewingJob(job)}
                            >
                              <Eye size={14} />
                            </Button>
                          </OverlayTrigger>
                          
                          <OverlayTrigger overlay={<Tooltip>Edit Schedule</Tooltip>}>
                            <Button 
                              size="sm" 
                              variant="outline-primary"
                              onClick={() => openEditModal(job)}
                            >
                              <Edit size={14} />
                            </Button>
                          </OverlayTrigger>
                          
                          {job.is_active && (
                            <OverlayTrigger overlay={<Tooltip>Trigger Now</Tooltip>}>
                              <Button 
                                size="sm" 
                                variant="outline-success"
                                onClick={() => handleTriggerJob(job)}
                              >
                                <Play size={14} />
                              </Button>
                            </OverlayTrigger>
                          )}
                          
                          <OverlayTrigger overlay={<Tooltip>Delete Schedule</Tooltip>}>
                            <Button 
                              size="sm" 
                              variant="outline-danger"
                              onClick={() => openDeleteModal(job)}
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

      {/* Modals */}
      <SchedulerJobModal
        show={showModal}
        onHide={() => setShowModal(false)}
        onSave={handleSubmit}
        formData={formData}
        setFormData={setFormData}
        categories={categories}
        templates={templates}
        deviceTypes={deviceTypes}
        isEditing={!!editingJob}
        loading={loading}
      />

      <JobDetailsModal
        show={!!viewingJob}
        onHide={() => setViewingJob(null)}
        job={viewingJob}
        onEdit={(job) => {
          setViewingJob(null);
          openEditModal(job);
        }}
        onTrigger={(job) => {
          setViewingJob(null);
          handleTriggerJob(job);
        }}
      />

      <DeleteConfirmationModal
        show={showDeleteModal}
        onHide={() => setShowDeleteModal(false)}
        onConfirm={handleDelete}
        job={jobToDelete}
        loading={loading}
      />
    </Container>
  );
};

export default Schedules;