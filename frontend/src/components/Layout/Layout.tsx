import React, { useState, useEffect } from 'react';
import { Container, Navbar, Nav, NavDropdown, Offcanvas, Button, Alert } from 'react-bootstrap';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import { 
  FaHome, 
  FaServer, 
  FaDatabase, 
  FaFileAlt, 
  FaClock, 
  FaUser,
  FaSignOutAlt,
  FaBars,
  FaChevronDown,
  FaChevronRight,
  FaMapMarkerAlt,
  FaNetworkWired,
  FaDesktop,
  FaExclamationTriangle,
  FaSpinner
} from 'react-icons/fa';
import './Layout.css';

// Updated interface to match database schema
interface Device {
  device_id: string;
  device_name: string;
  device_type_id: string;
  device_type?: string; // From joined device_types table
  location?: string;
  ip_address: string;
  hostname?: string;
  is_active: boolean;
}

interface DeviceTreeNode {
  location: string;
  deviceTypes: {
    [deviceType: string]: Device[];
  };
}

interface LayoutProps {
  children: React.ReactNode;
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [showSidebar, setShowSidebar] = useState(false);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expandedLocations, setExpandedLocations] = useState<Set<string>>(new Set());
  const [expandedDeviceTypes, setExpandedDeviceTypes] = useState<Set<string>>(new Set());

  const handleLogout = () => {
    logout();
  };

  const toggleSidebar = () => {
    setShowSidebar(!showSidebar);
  };

  const handleNavigation = (path: string) => {
    navigate(path);
  };

  // Check if current path matches the nav item
  const isActiveRoute = (path: string) => {
    return location.pathname === path;
  };

  // Fetch devices from API with proper error handling
  useEffect(() => {
    const fetchDevices = async () => {
      if (!showSidebar) return; // Only fetch when sidebar is opened
      
      setLoading(true);
      setError(null);
      
      try {
        const token = localStorage.getItem('token');
        if (!token) {
          throw new Error('No authentication token found');
        }

        // Try multiple possible API endpoints
        const endpoints = [
          '/api/devices',
          '/api/network-devices', 
          '/api/inventory/devices'
        ];

        let response;
        let lastError;

        for (const endpoint of endpoints) {
          try {
            response = await fetch(endpoint, {
              headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
              }
            });
            
            if (response.ok) {
              break; // Success, exit loop
            } else if (response.status === 404) {
              lastError = `Endpoint ${endpoint} not found`;
              continue; // Try next endpoint
            } else {
              throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
          } catch (err) {
            lastError = err instanceof Error ? err.message : 'Unknown error';
            continue;
          }
        }

        if (!response || !response.ok) {
          throw new Error(lastError || 'All API endpoints failed');
        }
        
        const data = await response.json();
        console.log('Fetched devices:', data); // Debug log
        
        // Handle different response formats
        const deviceList = Array.isArray(data) ? data : (data.devices || data.data || []);
        setDevices(deviceList);
        
      } catch (error) {
        console.error('Error fetching devices:', error);
        setError(error instanceof Error ? error.message : 'Failed to fetch devices');
        
        // Add some mock data for development/testing
        setDevices([
          {
            device_id: '1',
            device_name: 'Core-Switch-01',
            device_type_id: '1',
            device_type: 'Cisco Switch',
            location: 'Data Center',
            ip_address: '192.168.1.10',
            hostname: 'core-sw-01',
            is_active: true
          },
          {
            device_id: '2', 
            device_name: 'Router-WAN-01',
            device_type_id: '2',
            device_type: 'Cisco Router',
            location: 'Data Center',
            ip_address: '192.168.1.1',
            hostname: 'wan-rtr-01',
            is_active: true
          },
          {
            device_id: '3',
            device_name: 'Access-Switch-Floor2',
            device_type_id: '1', 
            device_type: 'Cisco Switch',
            location: 'Office Floor 2',
            ip_address: '192.168.2.10',
            hostname: 'acc-sw-f2',
            is_active: true
          }
        ]);
      } finally {
        setLoading(false);
      }
    };

    fetchDevices();
  }, [showSidebar]); // Fetch when sidebar opens

  // Organize devices into tree structure - only show active devices
  const deviceTree = devices
    .filter(device => device.is_active)
    .reduce((acc: { [location: string]: DeviceTreeNode }, device) => {
      const location = device.location || 'Unknown Location';
      const deviceType = device.device_type || `Type ID: ${device.device_type_id}`;

      if (!acc[location]) {
        acc[location] = {
          location,
          deviceTypes: {}
        };
      }

      if (!acc[location].deviceTypes[deviceType]) {
        acc[location].deviceTypes[deviceType] = [];
      }

      acc[location].deviceTypes[deviceType].push(device);
      return acc;
    }, {});

  const toggleLocationExpand = (location: string) => {
    const newExpanded = new Set(expandedLocations);
    if (newExpanded.has(location)) {
      newExpanded.delete(location);
    } else {
      newExpanded.add(location);
    }
    setExpandedLocations(newExpanded);
  };

  const toggleDeviceTypeExpand = (locationDeviceType: string) => {
    const newExpanded = new Set(expandedDeviceTypes);
    if (newExpanded.has(locationDeviceType)) {
      newExpanded.delete(locationDeviceType);
    } else {
      newExpanded.add(locationDeviceType);
    }
    setExpandedDeviceTypes(newExpanded);
  };

  const handleDeviceClick = (device: Device) => {
    // Navigate to device detail page
    navigate(`/devices/${device.device_id}`);
    setShowSidebar(false);
  };

  return (
    <>
      <Navbar bg="dark" variant="dark" expand="lg" className="mb-4">
        <Container fluid>
          <Button 
            variant="outline-light" 
            onClick={toggleSidebar}
            className="me-3"
            size="sm"
          >
            <FaBars />
          </Button>
          
          <Navbar.Brand style={{ cursor: 'pointer' }} onClick={() => handleNavigation('/')}>
            <FaDatabase className="me-2" />
            Network Backup System
          </Navbar.Brand>
          
          <Navbar.Toggle aria-controls="basic-navbar-nav" />
          
          <Navbar.Collapse id="basic-navbar-nav">
            <Nav className="me-auto">
              <Nav.Link 
                onClick={() => handleNavigation('/')}
                active={isActiveRoute('/')}
                style={{ cursor: 'pointer' }}
              >
                <FaHome className="me-1" />
                Dashboard
              </Nav.Link>
              
              <Nav.Link 
                onClick={() => handleNavigation('/devices')}
                active={isActiveRoute('/devices')}
                style={{ cursor: 'pointer' }}
              >
                <FaServer className="me-1" />
                Devices
              </Nav.Link>
              
              <Nav.Link 
                onClick={() => handleNavigation('/backups')}
                active={isActiveRoute('/backups')}
                style={{ cursor: 'pointer' }}
              >
                <FaDatabase className="me-1" />
                Backup Jobs
              </Nav.Link>
              
              <Nav.Link 
                onClick={() => handleNavigation('/templates')}
                active={isActiveRoute('/templates')}
                style={{ cursor: 'pointer' }}
              >
                <FaFileAlt className="me-1" />
                Templates
              </Nav.Link>
              
              <Nav.Link 
                onClick={() => handleNavigation('/schedules')}
                active={isActiveRoute('/schedules')}
                style={{ cursor: 'pointer' }}
              >
                <FaClock className="me-1" />
                Schedules
              </Nav.Link>
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

      {/* Device Navigator Sidebar */}
      <Offcanvas 
        show={showSidebar} 
        onHide={() => setShowSidebar(false)} 
        placement="start"
        style={{ width: '350px' }}
      >
        <Offcanvas.Header closeButton>
          <Offcanvas.Title>
            <FaNetworkWired className="me-2" />
            Device Navigator
          </Offcanvas.Title>
        </Offcanvas.Header>
        
        <Offcanvas.Body className="p-0">
          {/* Loading State */}
          {loading && (
            <div className="text-center p-4">
              <FaSpinner className="fa-spin mb-2" size={24} />
              <p>Loading devices...</p>
            </div>
          )}

          {/* Error State */}
          {error && !loading && (
            <div className="p-3">
              <Alert variant="warning" className="mb-0">
                <FaExclamationTriangle className="me-2" />
                <strong>API Error:</strong> {error}
                <br />
                <small>Showing mock data for development</small>
              </Alert>
            </div>
          )}

          {/* Device Tree */}
          {!loading && (
            <div className="device-tree">
              {Object.values(deviceTree).map((locationNode) => (
                <div key={locationNode.location} className="location-node">
                  {/* Location Level */}
                  <div 
                    className="tree-item location-item"
                    onClick={() => toggleLocationExpand(locationNode.location)}
                  >
                    {expandedLocations.has(locationNode.location) ? (
                      <FaChevronDown className="me-2" />
                    ) : (
                      <FaChevronRight className="me-2" />
                    )}
                    <FaMapMarkerAlt className="me-2 text-primary" />
                    <strong>{locationNode.location}</strong>
                    <span className="badge bg-secondary ms-2">
                      {Object.values(locationNode.deviceTypes).reduce((sum, devices) => sum + devices.length, 0)}
                    </span>
                  </div>

                  {/* Device Types Level */}
                  {expandedLocations.has(locationNode.location) && (
                    <div className="device-types">
                      {Object.entries(locationNode.deviceTypes).map(([deviceType, deviceList]) => {
                        const deviceTypeKey = `${locationNode.location}-${deviceType}`;
                        return (
                          <div key={deviceType}>
                            <div 
                              className="tree-item device-type-item"
                              onClick={() => toggleDeviceTypeExpand(deviceTypeKey)}
                            >
                              {expandedDeviceTypes.has(deviceTypeKey) ? (
                                <FaChevronDown className="me-2" />
                              ) : (
                                <FaChevronRight className="me-2" />
                              )}
                              <FaServer className="me-2 text-success" />
                              {deviceType}
                              <span className="badge bg-info ms-2">
                                {deviceList.length}
                              </span>
                            </div>

                            {/* Devices Level */}
                            {expandedDeviceTypes.has(deviceTypeKey) && (
                              <div className="devices">
                                {deviceList.map((device) => (
                                  <div 
                                    key={device.device_id}
                                    className="tree-item device-item"
                                    onClick={() => handleDeviceClick(device)}
                                  >
                                    <FaDesktop className="me-2 text-muted" />
                                    <span className="device-name">{device.device_name}</span>
                                    <br />
                                    <small className="text-muted ms-3">
                                      {device.ip_address}
                                    </small>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}
              
              {Object.keys(deviceTree).length === 0 && !loading && !error && (
                <div className="text-center p-4 text-muted">
                  <FaServer className="mb-2" size={24} />
                  <p>No active devices found</p>
                  <small>Check if devices are marked as active in the database</small>
                </div>
              )}
            </div>
          )}
        </Offcanvas.Body>
      </Offcanvas>
      
      <Container fluid>
        {children}
      </Container>
    </>
  );
};

export default Layout;