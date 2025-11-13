import React from 'react';
import { Modal, Button, Row, Col, Badge, Table } from 'react-bootstrap';
import { SchedulerJob } from '../../types/scheduler';
import { Clock, Server, Mail, Shield, Archive } from 'lucide-react';

interface JobDetailsModalProps {
  show: boolean;
  onHide: () => void;
  job: SchedulerJob | null;
  onEdit: (job: SchedulerJob) => void;
  onTrigger: (job: SchedulerJob) => void;
}

const JobDetailsModal: React.FC<JobDetailsModalProps> = ({ show, onHide, job, onEdit, onTrigger }) => {
  if (!job) {
    return null;
  }

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  return (
    <Modal show={show} onHide={onHide} size="lg">
      <Modal.Header closeButton>
        <Modal.Title>Scheduler Job Details: {job.policy_name}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Row className="mb-4">
          <Col md={6}>
            <h6>Basic Information</h6>
            <Table borderless size="sm">
              <tbody>
                <tr>
                  <td><strong>Policy Name:</strong></td>
                  <td>{job.policy_name}</td>
                </tr>
                <tr>
                  <td><strong>Status:</strong></td>
                  <td>
                    <Badge bg={job.is_active ? 'success' : 'danger'}>
                      {job.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </td>
                </tr>
                <tr>
                  <td><strong>Category:</strong></td>
                  <td>
                    {job.job_category ? (
                      <Badge 
                        bg="info" 
                        style={{ backgroundColor: job.job_category.color_code || '#17a2b8' }}
                      >
                        {job.job_category.category_name}
                      </Badge>
                    ) : (
                      <span className="text-muted">No category</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td><strong>Template:</strong></td>
                  <td>{job.template?.template_name || 'Unknown Template'}</td>
                </tr>
                <tr>
                  <td><strong>Created:</strong></td>
                  <td>{formatDate(job.created_at)}</td>
                </tr>
              </tbody>
            </Table>
          </Col>
          <Col md={6}>
            <h6>Schedule & Storage</h6>
            <Table borderless size="sm">
              <tbody>
                <tr>
                  <td><strong>Schedule:</strong></td>
                  <td>
                    <Badge bg="secondary">
                      <Clock size={12} className="me-1" />
                      {job.cron_expression}
                    </Badge>
                  </td>
                </tr>
                <tr>
                  <td><strong>Backup Path:</strong></td>
                  <td><code>{job.backup_path}</code></td>
                </tr>
                <tr>
                  <td><strong>Retention:</strong></td>
                  <td>{job.retention_days} days</td>
                </tr>
                <tr>
                  <td><strong>SFTP Server:</strong></td>
                  <td>
                    {job.sftp_server_ip ? (
                      <span>
                        <Server size={12} className="me-1" />
                        {job.sftp_server_ip}:{job.sftp_port}
                      </span>
                    ) : (
                      <span className="text-muted">Not configured</span>
                    )}
                  </td>
                </tr>
                <tr>
                  <td><strong>SFTP User:</strong></td>
                  <td>{job.sftp_username || <span className="text-muted">Not configured</span>}</td>
                </tr>
              </tbody>
            </Table>
          </Col>
        </Row>

        <Row className="mb-4">
          <Col>
            <h6>Features & Options</h6>
            <div className="d-flex gap-2 flex-wrap">
                            {job.compression_enabled && (
                <div className="mb-2">
                  <Archive size={14} className="me-1" />
                  Compression Enabled
                </div>
              )}
              {job.encryption_enabled && (
                <Badge bg="warning" className="p-2">
                  <Shield size={14} className="me-1" />
                  Encryption Enabled
                </Badge>
              )}
              {job.notification_enabled && (
                <Badge bg="success" className="p-2">
                  <Mail size={14} className="me-1" />
                  Notifications Enabled
                </Badge>
              )}
              {!job.compression_enabled && !job.encryption_enabled && !job.notification_enabled && (
                <span className="text-muted">No additional features enabled</span>
              )}
            </div>
          </Col>
        </Row>

        {job.notification_emails && job.notification_emails.length > 0 && (
          <Row className="mb-4">
            <Col>
              <h6>Notification Recipients</h6>
              <div className="d-flex gap-1 flex-wrap">
                {job.notification_emails.map((email, index) => (
                  <Badge key={index} bg="outline-secondary">
                    {email}
                  </Badge>
                ))}
              </div>
            </Col>
          </Row>
        )}

        {job.template && (
          <Row>
            <Col>
              <h6>Template Details</h6>
              <Table borderless size="sm">
                <tbody>
                  <tr>
                    <td><strong>Device Type:</strong></td>
                    <td>
                      {job.template.device_type?.vendor} {job.template.device_type?.model}
                      {job.template.device_type?.firmware_version && (
                        <span className="text-muted"> ({job.template.device_type.firmware_version})</span>
                      )}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Command Format:</strong></td>
                    <td>
                      <Badge bg="secondary">{job.template.command_format}</Badge>
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Timeout:</strong></td>
                    <td>{job.template.timeout_seconds}s</td>
                  </tr>
                  <tr>
                    <td><strong>Retry Count:</strong></td>
                    <td>{job.template.retry_count}</td>
                  </tr>
                </tbody>
              </Table>
            </Col>
          </Row>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
        {job.is_active && (
          <Button variant="success" onClick={() => onTrigger(job)}>
            Trigger Now
          </Button>
        )}
        <Button variant="primary" onClick={() => onEdit(job)}>
          Edit Job
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default JobDetailsModal;