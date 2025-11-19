import React, { useState, useEffect } from 'react';
import { Container, Navbar, Nav, NavDropdown, Offcanvas, Button, Alert } from 'react-bootstrap';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';
import apiClient from '../../services/apiClient';
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
  FaSpinner,
  FaExpandArrowsAlt,
  FaCompressArrowsAlt
} from 'react-icons/fa';
import './Layout.css';

// Updated interface to match database schema
interface DeviceType {
  id: number;
  vendor: string;
  model: string;
  firmware_version?: string;
  device_category?: string;
  netmiko_device_type?: string;
  description?: string;
  is_active: boolean;
  created_at: string;
}

interface Device {
  id?: number;
  device_id?: string;
  device_name: string;
  device_type_id: string | number;
  device_type?: DeviceType | string; // Can be object (from API) or string (legacy)
  location?: string;
  ip_address: string;
  hostname?: string;
  is_active: boolean;
  last_backup_date?: string;
  last_backup_status?: string;
  created_at?: string;
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
  const [allExpanded, setAllExpanded] = useState(true); // Default to expanded

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

  // Expand all tree nodes
  const expandAll = React.useCallback(() => {
    const allLocations = new Set<string>();
    const allDeviceTypeKeys = new Set<string>();

    devices.filter(d => d.is_active).forEach(device => {
      const location = device.location || 'Unknown Location';
      allLocations.add(location);

      let deviceTypeStr = '';
      if (device.device_type && typeof device.device_type === 'object') {
        const dt = device.device_type as any;
        deviceTypeStr = `${dt.vendor} ${dt.model}`;
        if (dt.firmware_version) deviceTypeStr += ` (${dt.firmware_version})`;
      } else {
        deviceTypeStr = (device.device_type as string) || `Type ID: ${device.device_type_id}`;
      }

      allDeviceTypeKeys.add(`${location}-${deviceTypeStr}`);
    });

    setExpandedLocations(allLocations);
    setExpandedDeviceTypes(allDeviceTypeKeys);
    setAllExpanded(true);
  }, [devices]);

  // Collapse all tree nodes
  const collapseAll = () => {
    setExpandedLocations(new Set());
    setExpandedDeviceTypes(new Set());
    setAllExpanded(false);
  };

  // Toggle expand/collapse all
  const toggleExpandAll = () => {
    if (allExpanded) {
      collapseAll();
    } else {
      expandAll();
    }
  };

  // Fetch devices from API with proper error handling
  useEffect(() => {
    const fetchDevices = async () => {
      if (!showSidebar) return; // Only fetch when sidebar is opened
      
      setLoading(true);
      setError(null);
      
      try {
        // Use apiClient which already has baseURL and token configured
        const response = await apiClient.get('/devices/');
        
        console.log('Fetched devices:', response.data); // Debug log
        
        // Handle different response formats
        const deviceList = Array.isArray(response.data) ? response.data : (response.data.devices || response.data.data || []);
        setDevices(deviceList);
        
      } catch (error) {
        console.error('Error fetching devices:', error);
        setError(error instanceof Error ? error.message : 'Failed to fetch devices');
        
        // Add comprehensive mock data for development/testing
        setDevices([
          {
            id: 1,
            device_name: 'Core-Switch-01',
            device_type_id: 1,
            device_type: 'Cisco Catalyst Switch',
            location: 'Data Center - Rack A1',
            ip_address: '192.168.1.10',
            hostname: 'core-sw-01.company.com',
            is_active: true
          },
          {
            id: 2, 
            device_name: 'Core-Switch-02',
            device_type_id: 1,
            device_type: 'Cisco Catalyst Switch',
            location: 'Data Center - Rack A1',
            ip_address: '192.168.1.11',
            hostname: 'core-sw-02.company.com',
            is_active: true
          },
          {
            id: 3,
            device_name: 'Router-WAN-01',
            device_type_id: 2,
            device_type: 'Cisco ISR Router',
            location: 'Data Center - Rack A1',
            ip_address: '192.168.1.1',
            hostname: 'wan-rtr-01.company.com',
            is_active: true
          },
          {
            id: 4,
            device_name: 'Firewall-ASA-01',
            device_type_id: 3,
            device_type: 'Cisco ASA Firewall',
            location: 'Data Center - Rack A1',
            ip_address: '192.168.1.2',
            hostname: 'fw-asa-01.company.com',
            is_active: true
          },
          {
            id: 5,
            device_name: 'Access-Switch-Floor2-01',
            device_type_id: 1, 
            device_type: 'Cisco Catalyst Switch',
            location: 'Office Floor 2 - IDF Room',
            ip_address: '192.168.2.10',
            hostname: 'acc-sw-f2-01.company.com',
            is_active: true
          },
          {
            id: 6,
            device_name: 'Access-Switch-Floor2-02',
            device_type_id: 1,
            device_type: 'Cisco Catalyst Switch',
            location: 'Office Floor 2 - IDF Room',
            ip_address: '192.168.2.11',
            hostname: 'acc-sw-f2-02.company.com',
            is_active: true
          },
          {
            id: 7,
            device_name: 'Wireless-Controller-01',
            device_type_id: 4,
            device_type: 'Cisco Wireless Controller',
            location: 'Office Floor 2 - IDF Room',
            ip_address: '192.168.2.20',
            hostname: 'wlc-01.company.com',
            is_active: true
          },
          {
            id: 8,
            device_name: 'Access-Switch-Floor3-01',
            device_type_id: 1,
            device_type: 'Cisco Catalyst Switch',
            location: 'Office Floor 3 - Network Closet',
            ip_address: '192.168.3.10',
            hostname: 'acc-sw-f3-01.company.com',
            is_active: true
          },
          {
            id: 9,
            device_name: 'Juniper-EX-01',
            device_type_id: 5,
            device_type: 'Juniper EX Switch',
            location: 'Office Floor 3 - Network Closet',
            ip_address: '192.168.3.20',
            hostname: 'jun-ex-01.company.com',
            is_active: true
          },
          {
            id: 10,
            device_name: 'MikroTik-Router-01',
            device_type_id: 6,
            device_type: 'MikroTik RouterOS',
            location: 'Branch Office - Toronto',
            ip_address: '10.10.1.1',
            hostname: 'mikrotik-tor-01.company.com',
            is_active: true
          },
          {
            id: 11,
            device_name: 'FortiGate-FW-01',
            device_type_id: 7,
            device_type: 'Fortinet FortiGate',
            location: 'Branch Office - Toronto',
            ip_address: '10.10.1.2',
            hostname: 'fg-tor-01.company.com',
            is_active: true
          },
          {
            id: 12,
            device_name: 'HP-Switch-01',
            device_type_id: 8,
            device_type: 'HP ProCurve Switch',
            location: 'Branch Office - Vancouver',
            ip_address: '10.20.1.10',
            hostname: 'hp-van-01.company.com',
            is_active: true
          }
        ]);
      } finally {
        setLoading(false);
      }
    };

    fetchDevices();
  }, [showSidebar]); // Fetch when sidebar opens

  // Auto-expand all when devices are loaded
  useEffect(() => {
    if (devices.length > 0 && allExpanded) {
      // Small delay to ensure tree is rendered
      setTimeout(() => {
        expandAll();
      }, 100);
    }
  }, [devices, allExpanded, expandAll]);

  // Organize devices into tree structure - only show active devices
  const deviceTree = devices
    .filter(device => device.is_active)
    .reduce((acc: { [location: string]: DeviceTreeNode }, device) => {
      const location = device.location || 'Unknown Location';
      
      // Format device type string from object
      let deviceTypeStr = '';
      if (device.device_type && typeof device.device_type === 'object') {
        const dt = device.device_type;
        deviceTypeStr = `${dt.vendor} ${dt.model}`;
        if (dt.firmware_version) {
          deviceTypeStr += ` (${dt.firmware_version})`;
        }
      } else {
        deviceTypeStr = device.device_type || `Type ID: ${device.device_type_id}`;
      }

      if (!acc[location]) {
        acc[location] = {
          location,
          deviceTypes: {}
        };
      }

      if (!acc[location].deviceTypes[deviceTypeStr]) {
        acc[location].deviceTypes[deviceTypeStr] = [];
      }

      acc[location].deviceTypes[deviceTypeStr].push(device);
      return acc;
    }, {});

  const toggleLocationExpand = (location: string) => {
    const newExpanded = new Set(expandedLocations);
    if (newExpanded.has(location)) {
      newExpanded.delete(location);
      // Also collapse all device types in this location
      const deviceTypesToRemove = new Set<string>();
      expandedDeviceTypes.forEach(key => {
        if (key.startsWith(`${location}-`)) {
          deviceTypesToRemove.add(key);
        }
      });
      const newExpandedDeviceTypes = new Set(expandedDeviceTypes);
      deviceTypesToRemove.forEach(key => newExpandedDeviceTypes.delete(key));
      setExpandedDeviceTypes(newExpandedDeviceTypes);
    } else {
      newExpanded.add(location);
    }
    setExpandedLocations(newExpanded);
    
    // Update allExpanded state
    setAllExpanded(false);
  };

  const toggleDeviceTypeExpand = (locationDeviceType: string) => {
    const newExpanded = new Set(expandedDeviceTypes);
    if (newExpanded.has(locationDeviceType)) {
      newExpanded.delete(locationDeviceType);
    } else {
      newExpanded.add(locationDeviceType);
    }
    setExpandedDeviceTypes(newExpanded);
    
    // Update allExpanded state
    setAllExpanded(false);
  };

  const handleDeviceClick = (device: Device) => {
    // Navigate to device detail page
    const deviceId = device.id || device.device_id;
    if (deviceId) {
      navigate(`/devices/${deviceId}`);
      setShowSidebar(false);
    } else {
      console.error('Device ID not found:', device);
    }
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
        style={{ width: '400px' }}
      >
        <Offcanvas.Header closeButton>
          <Offcanvas.Title>
            <FaNetworkWired className="me-2" />
            Device Navigator
          </Offcanvas.Title>
        </Offcanvas.Header>
        
        <Offcanvas.Body className="p-0">
          {/* Expand/Collapse All Controls */}
          {!loading && Object.keys(deviceTree).length > 0 && (
            <div className="tree-controls p-3 border-bottom">
              <Button 
                variant="outline-secondary" 
                size="sm" 
                onClick={toggleExpandAll}
                className="w-100"
              >
                {allExpanded ? (
                  <>
                    <FaCompressArrowsAlt className="me-2" />
                    Collapse All
                  </>
                ) : (
                  <>
                    <FaExpandArrowsAlt className="me-2" />
                    Expand All
                  </>
                )}
              </Button>
              <small className="text-muted d-block mt-2 text-center">
                {Object.values(deviceTree).reduce((sum, node) => 
                  sum + Object.values(node.deviceTypes).reduce((typeSum, devices) => 
                    typeSum + devices.length, 0), 0)} devices in {Object.keys(deviceTree).length} locations
              </small>
            </div>
          )}

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
                      <FaChevronDown className="me-2 chevron-icon" />
                    ) : (
                      <FaChevronRight className="me-2 chevron-icon" />
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
                          <div key={deviceTypeKey}>
                            <div 
                              className="tree-item device-type-item"
                              onClick={() => toggleDeviceTypeExpand(deviceTypeKey)}
                            >
                              {expandedDeviceTypes.has(deviceTypeKey) ? (
                                <FaChevronDown className="me-2 chevron-icon" />
                              ) : (
                                <FaChevronRight className="me-2 chevron-icon" />
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
                                    key={device.id || device.device_name}
                                    className="tree-item device-item"
                                    onClick={() => handleDeviceClick(device)}
                                    title={`${device.device_name} (${device.hostname || device.ip_address})`}
                                  >
                                    <FaDesktop className="me-2 text-muted" />
                                    <div className="device-info">
                                      <div className="device-name">{device.device_name}</div>
                                      <small className="text-muted d-block">
                                        {device.ip_address}
                                      </small>
                                      {device.hostname && (
                                        <small className="text-muted d-block hostname-info">
                                          {device.hostname}
                                        </small>
                                      )}
                                    </div>
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