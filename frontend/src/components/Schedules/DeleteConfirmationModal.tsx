import React from 'react';
import { Modal, Button, Alert } from 'react-bootstrap';
import { SchedulerJob } from '../../types/scheduler';


interface DeleteConfirmationModalProps {
  show: boolean;
  onHide: () => void;
  onConfirm: () => void;
  job: SchedulerJob | null;
  loading: boolean;
}

const DeleteConfirmationModal: React.FC<DeleteConfirmationModalProps> = ({
  show,
  onHide,
  onConfirm,
  job,
  loading
}) => {
  if (!job) {
    return null;
  }
  return (
    <Modal show={show} onHide={onHide} centered>
      <Modal.Header closeButton>
        <Modal.Title>Confirm Deletion</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Alert variant="warning">
          <Alert.Heading>Are you sure?</Alert.Heading>
          <p>
            You are about to delete the scheduler job <strong>"{job.policy_name}"</strong>.
            This action will:
          </p>
          <ul>
            <li>Disable the job and prevent it from running</li>
            <li>Remove it from the active schedules</li>
            <li>Keep historical backup records intact</li>
          </ul>
          <p className="mb-0">
            <strong>Note:</strong> This action can be reversed by reactivating the job.
          </p>
        </Alert>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide} disabled={loading}>
          Cancel
        </Button>
        <Button variant="danger" onClick={onConfirm} disabled={loading}>
          {loading ? 'Deleting...' : 'Delete Job'}
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default DeleteConfirmationModal;