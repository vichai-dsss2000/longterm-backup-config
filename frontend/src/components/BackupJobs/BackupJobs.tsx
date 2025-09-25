import React from 'react';
import { Card, Alert } from 'react-bootstrap';

const BackupJobs: React.FC = () => {
  return (
    <div>
      <h2 className="mb-4">Backup Jobs</h2>
      
      <Card>
        <Card.Body>
          <Alert variant="info">
            Backup Jobs management interface coming soon...
          </Alert>
        </Card.Body>
      </Card>
    </div>
  );
};

export default BackupJobs;