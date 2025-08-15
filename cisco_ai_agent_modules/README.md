# Cisco AI Agent Topology Discovery Modules

This directory contains the agent-side modules for network topology discovery and monitoring. These modules enable agents to discover network devices, monitor their status, and report topology information back to the backend.

## 🚀 **Overview**

The agent topology discovery system consists of three main modules:

1. **TopologyDiscovery** - Discovers network devices and neighbor relationships
2. **DeviceMonitor** - Continuously monitors device health and status
3. **InterfaceTracker** - Tracks interface status and configuration changes

## 📁 **Module Structure**

```
cisco_ai_agent_modules/
├── __init__.py              # Main integration manager
├── topology_discovery.py    # Network discovery module
├── device_monitoring.py     # Device monitoring module
├── interface_tracker.py     # Interface tracking module
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## 🔧 **Installation**

1. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Optional SNMP support:**
   ```bash
   pip install pysnmp pysnmp-mibs
   ```

## ⚙️ **Configuration**

Create a configuration file or environment variables:

```python
config = {
    'backend_url': 'https://cisco-ai-backend-production.up.railway.app',
    'agent_token': 'your_agent_token_here',
    'agent_id': 123,
    'networks': [
        {
            'id': 1,
            'name': 'Main Network',
            'network_range': '192.168.1.0/24'
        }
    ],
    'discovery_config': {
        'snmp_community': 'public',
        'snmp_version': '2c',
        'ping_timeout': 2,
        'max_concurrent_discoveries': 10,
        'discovery_interval': 300
    },
    'monitoring_config': {
        'ping_interval': 60,
        'snmp_interval': 300,
        'ssh_interval': 600,
        'health_interval': 900
    },
    'interface_tracking_config': {
        'interface_check_interval': 120,
        'bandwidth_check_interval': 300,
        'error_check_interval': 60,
        'config_check_interval': 1800
    }
}
```

## 🎯 **Usage Examples**

### **Basic Usage**

```python
from cisco_ai_agent_modules import AgentTopologyManager

# Create agent manager
agent_manager = AgentTopologyManager(config)

# Start all services
await agent_manager.start_all_services()

# Keep running
while agent_manager.is_running:
    await asyncio.sleep(10)
```

### **Manual Discovery Trigger**

```python
# Trigger discovery for a specific network
success = await agent_manager.trigger_discovery(network_id=1, discovery_type="full")

if success:
    print("Discovery started successfully")
else:
    print("Failed to start discovery")
```

### **Service Status Check**

```python
# Get overall service status
status = agent_manager.get_service_status()
print(f"Services running: {status['is_running']}")

# Get network summary
summary = agent_manager.get_network_summary(network_id=1)
print(f"Network {summary['network_id']}: {summary['device_count']} devices")
```

### **Health Check**

```python
# Perform health check
health = await agent_manager.health_check()
print(f"Overall health: {health['overall_status']}")

for service, info in health['services'].items():
    print(f"{service}: {info['status']}")
```

## 🔍 **Module Details**

### **TopologyDiscovery**

**Purpose:** Discovers network devices and topology

**Features:**
- Network scanning via ping
- SNMP device information gathering
- CDP/LLDP neighbor discovery
- Interface information collection
- Backend reporting

**Key Methods:**
- `start_discovery(network_id, discovery_type)` - Start discovery
- `start_continuous_discovery()` - Continuous discovery loop

### **DeviceMonitor**

**Purpose:** Monitors device health and status

**Features:**
- Continuous ping monitoring
- SNMP status checking
- SSH connectivity testing
- Health metrics collection
- Real-time status reporting

**Key Methods:**
- `start_monitoring()` - Start monitoring
- `get_device_status_summary(network_id)` - Get status summary

### **InterfaceTracker**

**Purpose:** Tracks interface status and changes

**Features:**
- Interface status monitoring
- Configuration change detection
- Bandwidth utilization tracking
- Error rate monitoring
- Historical data storage

**Key Methods:**
- `start_tracking()` - Start tracking
- `get_interface_summary(network_id)` - Get interface summary

## 📊 **Data Flow**

```
Network Devices → Agent Modules → Backend API → Database → Frontend UI
     ↓
1. TopologyDiscovery scans network
2. DeviceMonitor tracks status
3. InterfaceTracker monitors interfaces
4. Data sent to backend via API
5. Backend stores in database
6. Frontend displays topology
```

## 🔐 **Security Considerations**

- **Agent Authentication:** Uses secure tokens for backend communication
- **Network Access:** Agents only access networks they're authorized for
- **Data Encryption:** HTTPS communication with backend
- **Access Control:** Backend validates agent permissions

## 🚨 **Troubleshooting**

### **Common Issues**

1. **Discovery not starting:**
   - Check agent token validity
   - Verify network access permissions
   - Check backend connectivity

2. **No devices discovered:**
   - Verify network range configuration
   - Check SNMP community strings
   - Ensure devices are reachable

3. **Monitoring not working:**
   - Check monitoring intervals
   - Verify device credentials
   - Check backend API endpoints

### **Debug Mode**

Enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### **Health Checks**

Regular health checks help identify issues:

```python
# Check service health every minute
async def health_monitor():
    while True:
        health = await agent_manager.health_check()
        if health['overall_status'] != 'healthy':
            logger.warning(f"Health check failed: {health}")
        await asyncio.sleep(60)
```

## 🔄 **Integration with Main Agent**

To integrate with your main `cisco_ai_agent.py`:

```python
# In your main agent file
from cisco_ai_agent_modules import AgentTopologyManager

class CiscoAIAgent:
    def __init__(self):
        # ... existing initialization ...
        
        # Initialize topology manager
        self.topology_manager = AgentTopologyManager(self.config)
    
    async def start_topology_services(self):
        """Start topology discovery and monitoring."""
        await self.topology_manager.start_all_services()
    
    async def stop_topology_services(self):
        """Stop topology services."""
        await self.topology_manager.stop_all_services()
```

## 📈 **Performance Tuning**

### **Discovery Settings**

- **Concurrent discoveries:** Adjust `max_concurrent_discoveries`
- **Ping timeout:** Reduce for faster scanning
- **Discovery interval:** Balance between freshness and overhead

### **Monitoring Settings**

- **Ping interval:** More frequent = faster failure detection
- **SNMP interval:** Balance between detail and overhead
- **Health interval:** Longer intervals reduce backend load

## 🤝 **Contributing**

1. Follow Python PEP 8 style guidelines
2. Add proper error handling and logging
3. Include unit tests for new features
4. Update documentation for API changes

## 📝 **License**

This module is part of the Cisco AI Backend project and follows the same licensing terms.

## 🆘 **Support**

For issues and questions:
1. Check the troubleshooting section above
2. Review backend API documentation
3. Check agent logs for error details
4. Verify network connectivity and permissions 