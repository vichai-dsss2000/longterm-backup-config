import React from 'react';
import { Modal, Form, Button, Row, Col } from 'react-bootstrap';
import { SchedulerJobCreate, JobCategory, BackupTemplate, DeviceType } from '../../types/scheduler';
import ScheduleService from '../../services/scheduleService';

interface SchedulerJobModalProps {
  show: boolean;
  onHide: () => void;
  onSave: (data: SchedulerJobCreate) => void;
  formData: SchedulerJobCreate;
  setFormData: React.Dispatch<React.SetStateAction<SchedulerJobCreate>>;
  categories: JobCategory[];
  templates: BackupTemplate[];
  deviceTypes: DeviceType[];
  isEditing: boolean;
  loading: boolean;
}

const SchedulerJobModal: React.FC<SchedulerJobModalProps> = ({
  show,
  onHide,
  onSave,
  formData,
  setFormData,
  categories,
  templates,
  deviceTypes,
  isEditing,
  loading
}) => {
  const cronPresets = ScheduleService.getCronPresets();

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handleEmailsChange = (emailsString: string) => {
    const emails = emailsString.split(',').map(email => email.trim()).filter(email => email);
    setFormData(prev => ({
      ...prev,
      notification_emails: emails
    }));
  };

  // Validation functions
  const validateEmail = (email: string): boolean => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
  };

  const validateEmails = (emails: string[]): boolean => {
    if (!emails || emails.length === 0) {
      return true; // Optional field
    }
    return emails.every(email => validateEmail(email));
  };

  const validateIP = (ip: string): boolean => {
    if (!ip) {
      return true; // Optional field
    }
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      return false;
    }
    return ip.split('.').every(octet => {
      const num = parseInt(octet);
      return num >= 0 && num <= 255;
    });
  };

  const validatePath = (path: string): boolean => {
    if (!path) {
      return false;
    }
    // Check for path injection or dangerous characters
    const dangerousChars = /[<>:"|?*]/;
    return !dangerousChars.test(path);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (isFormValid) {
      onSave(formData);
    }
  };

  // Computed validation states
  const isValidCron = ScheduleService.validateCronExpression(formData.cron_expression);
  const isValidEmails = validateEmails(formData.notification_emails || []);
  const isValidSftpIP = validateIP(formData.sftp_server_ip || '');
  const isValidBackupPath = validatePath(formData.backup_path);
  const isFormValid = formData.policy_name && 
                     formData.template_id && 
                     isValidBackupPath && 
                     isValidCron && 
                     isValidEmails && 
                     isValidSftpIP;

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>
          {isEditing ? 'Edit Scheduler Job' : 'Create New Scheduler Job'}
        </Modal.Title>
      </Modal.Header>
      <Form onSubmit={handleSubmit}>
        <Modal.Body>
          <Row>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Policy Name *</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="Enter policy name"
                  value={formData.policy_name}
                  onChange={(e) => handleInputChange('policy_name', e.target.value)}
                  required
                />
              </Form.Group>
            </Col>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Job Category</Form.Label>
                <Form.Select
                  value={formData.job_category_id || ''}
                  onChange={(e) => handleInputChange('job_category_id', e.target.value ? Number(e.target.value) : undefined)}
                >
                  <option value="">Select category</option>
                  {categories.map(category => (
                    <option key={category.id} value={category.id}>
                      {category.category_name}
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
          </Row>

          <Row>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Backup Template *</Form.Label>
                <Form.Select
                  value={formData.template_id || ''}
                  onChange={(e) => handleInputChange('template_id', Number(e.target.value))}
                  required
                >
                  <option value="">Select template</option>
                  {templates.map(template => (
                    <option key={template.id} value={template.id}>
                      {template.template_name} ({template.device_type?.vendor} {template.device_type?.model})
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Device Type</Form.Label>
                <Form.Select
                  value={formData.device_type_id || ''}
                  onChange={(e) => handleInputChange('device_type_id', e.target.value ? Number(e.target.value) : undefined)}
                >
                  <option value="">All device types</option>
                  {deviceTypes.map(type => (
                    <option key={type.id} value={type.id}>
                      {type.vendor} {type.model} ({type.firmware_version})
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
          </Row>

          <Row>
            <Col md={8}>
              <Form.Group className="mb-3">
                <Form.Label>Schedule (Cron Expression) *</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="* * * * *"
                  value={formData.cron_expression}
                  onChange={(e) => handleInputChange('cron_expression', e.target.value)}
                  isInvalid={!!formData.cron_expression && !isValidCron}
                  required
                />
                <Form.Control.Feedback type="invalid">
                  Invalid cron expression format
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
            <Col md={4}>
              <Form.Group className="mb-3">
                <Form.Label>Quick Presets</Form.Label>
                <Form.Select
                  value=""
                  onChange={(e) => e.target.value && handleInputChange('cron_expression', e.target.value)}
                >
                  <option value="">Select preset</option>
                  {cronPresets.map((preset, index) => (
                    <option key={index} value={preset.value}>
                      {preset.label}
                    </option>
                  ))}
                </Form.Select>
              </Form.Group>
            </Col>
          </Row>

          <Form.Group className="mb-3">
            <Form.Label>Backup Path *</Form.Label>
            <Form.Control
              type="text"
              placeholder="/backups/{device_name}_{timestamp}.cfg"
              value={formData.backup_path}
              onChange={(e) => handleInputChange('backup_path', e.target.value)}
              isInvalid={!!formData.backup_path && !isValidBackupPath}
              required
            />
            <Form.Control.Feedback type="invalid">
              Invalid path format. Avoid special characters like &lt; &gt; : &quot; | ? *
            </Form.Control.Feedback>
            <Form.Text className="text-muted">
              Use variables: {'{device_name}'}, {'{timestamp}'}, {'{date}'}
            </Form.Text>
          </Form.Group>

          <Row>
            <Col md={4}>
              <Form.Group className="mb-3">
                <Form.Label>SFTP Server IP</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="192.168.1.100"
                  value={formData.sftp_server_ip || ''}
                  onChange={(e) => handleInputChange('sftp_server_ip', e.target.value)}
                  isInvalid={!!formData.sftp_server_ip && !isValidSftpIP}
                />
                <Form.Control.Feedback type="invalid">
                  Please enter a valid IP address (e.g., 192.168.1.100)
                </Form.Control.Feedback>
              </Form.Group>
            </Col>
            <Col md={4}>
              <Form.Group className="mb-3">
                <Form.Label>SFTP Username</Form.Label>
                <Form.Control
                  type="text"
                  placeholder="backup-user"
                  value={formData.sftp_username || ''}
                  onChange={(e) => handleInputChange('sftp_username', e.target.value)}
                />
              </Form.Group>
            </Col>
            <Col md={4}>
              <Form.Group className="mb-3">
                <Form.Label>SFTP Port</Form.Label>
                <Form.Control
                  type="number"
                  value={formData.sftp_port}
                  onChange={(e) => handleInputChange('sftp_port', Number(e.target.value))}
                  min={1}
                  max={65535}
                />
              </Form.Group>
            </Col>
          </Row>

          <Row>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>SFTP Password</Form.Label>
                <Form.Control
                  type="password"
                  placeholder="Enter password"
                  value={formData.sftp_password || ''}
                  onChange={(e) => handleInputChange('sftp_password', e.target.value)}
                />
              </Form.Group>
            </Col>
            <Col md={6}>
              <Form.Group className="mb-3">
                <Form.Label>Retention Days</Form.Label>
                <Form.Control
                  type="number"
                  value={formData.retention_days}
                  onChange={(e) => handleInputChange('retention_days', Number(e.target.value))}
                  min={1}
                  max={365}
                />
              </Form.Group>
            </Col>
          </Row>

          <Form.Group className="mb-3">
            <Form.Label>Notification Emails</Form.Label>
            <Form.Control
              type="text"
              placeholder="admin@company.com, ops@company.com"
              value={formData.notification_emails?.join(', ') || ''}
              onChange={(e) => handleEmailsChange(e.target.value)}
              isInvalid={!isValidEmails}
            />
            <Form.Control.Feedback type="invalid">
              Please enter valid email addresses
            </Form.Control.Feedback>
            <Form.Text className="text-muted">
              Separate multiple emails with commas
            </Form.Text>
          </Form.Group>

          <Row>
            <Col md={3}>
              <Form.Check
                type="checkbox"
                label="Enable Compression"
                checked={formData.compression_enabled}
                onChange={(e) => handleInputChange('compression_enabled', e.target.checked)}
              />
            </Col>
            <Col md={3}>
              <Form.Check
                type="checkbox"
                label="Enable Encryption"
                checked={formData.encryption_enabled}
                onChange={(e) => handleInputChange('encryption_enabled', e.target.checked)}
              />
            </Col>
            <Col md={3}>
              <Form.Check
                type="checkbox"
                label="Enable Notifications"
                checked={formData.notification_enabled}
                onChange={(e) => handleInputChange('notification_enabled', e.target.checked)}
              />
            </Col>
          </Row>
        </Modal.Body>
        <Modal.Footer>
          <Button variant="secondary" onClick={onHide} disabled={loading}>
            Cancel
          </Button>
          <Button 
            variant="primary" 
            type="submit" 
            disabled={loading || !isFormValid}
          >
            {loading ? 'Saving...' : (isEditing ? 'Update' : 'Create')}
          </Button>
        </Modal.Footer>
      </Form>
    </Modal>
  );
};

export default SchedulerJobModal;