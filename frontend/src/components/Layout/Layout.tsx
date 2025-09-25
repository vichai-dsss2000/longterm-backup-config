import React from 'react';
import { Container, Navbar, Nav, NavDropdown } from 'react-bootstrap';
import { LinkContainer } from 'react-router-bootstrap';
import { useAuth } from '../../context/AuthContext';
import { 
  FaHome, 
  FaServer, 
  FaDatabase, 
  FaFileAlt, 
  FaClock, 
  FaUser,
  FaSignOutAlt 
} from 'react-icons/fa';

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { user, logout } = useAuth();

  const handleLogout = () => {
    logout();
  };

  return (
    <>
      <Navbar bg="dark" variant="dark" expand="lg" className="mb-4">
        <Container fluid>
          <Navbar.Brand>
            <FaDatabase className="me-2" />
            Network Backup System
          </Navbar.Brand>
          
          <Navbar.Toggle aria-controls="basic-navbar-nav" />
          
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="me-auto">
              <LinkContainer to="/">
                <Nav.Link>
                  <FaHome className="me-1" />
                  Dashboard
                </Nav.Link>
              </LinkContainer>
              
              <LinkContainer to="/devices">
                <Nav.Link>
                  <FaServer className="me-1" />
                  Devices
                </Nav.Link>
              </LinkContainer>
              
              <LinkContainer to="/backups">
                <Nav.Link>
                  <FaDatabase className="me-1" />
                  Backup Jobs
                </Nav.Link>
              </LinkContainer>
              
              <LinkContainer to="/templates">
                <Nav.Link>
                  <FaFileAlt className="me-1" />
                  Templates
                </Nav.Link>
              </LinkContainer>
              
              <LinkContainer to="/schedules">
                <Nav.Link>
                  <FaClock className="me-1" />
                  Schedules
                </Nav.Link>
              </LinkContainer>
            </Nav>
            
            <Nav>
              <NavDropdown 
                title={
                  <>
                    <FaUser className="me-1" />
                    {user?.username || 'User'}
                  </>
                } 
                id="basic-nav-dropdown"
              >
                <NavDropdown.Item onClick={handleLogout}>
                  <FaSignOutAlt className="me-1" />
                  Logout
                </NavDropdown.Item>
              </NavDropdown>
            </Nav>
          </Navbar.Collapse>
        </Container>
      </Navbar>
      
      <Container fluid>
        {children}
      </Container>
    </>
  );
};

export default Layout;