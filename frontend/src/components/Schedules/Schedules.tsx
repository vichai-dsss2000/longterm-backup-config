import React from 'react';
import { Card, Alert } from 'react-bootstrap';

const Schedules: React.FC = () => {
  return (
    <div>
      <h2 className="mb-4">Backup Schedules</h2>
      
      <Card>
        <Card.Body>
          <Alert variant="info">
            Backup Schedules management interface coming soon...
          </Alert>
        </Card.Body>
      </Card>
    </div>
  );
};

export default Schedules;