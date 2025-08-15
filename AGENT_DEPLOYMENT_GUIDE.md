# Cisco AI Agent Deployment Guide

## Overview

The Cisco AI Agent is a local service that runs on your network to discover and monitor network devices. It communicates securely with the cloud backend to provide real-time device information and configuration management.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Cloud Backend │◄──►│  Local Agent     │◄──►│ Network Devices │
│                 │    │                  │    │                 │
│ • User Interface│    │ • Device Discovery│    │ • Routers       │
│ • Data Storage  │    │ • SNMP/SSH       │    │ • Switches      │
│ • Analytics     │    │ • Configuration  │    │ • Servers       │
│ • Compliance    │    │ • Monitoring     │    │ • Firewalls     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+, CentOS 7+)
- **Python**: 3.7 or higher
- **Memory**: 512MB RAM minimum, 1GB recommended
- **Storage**: 100MB free space
- **Network**: Internet access for initial setup

### Network Requirements
- **Outbound Access**: HTTPS (443) to backend
- **Inbound Access**: SNMP (161), SSH (22) to target devices
- **Firewall**: Allow agent to scan local subnets

## Installation

### Option 1: Graphical Installer (Recommended)

1. **Download the installer**:
   ```bash
   # Windows
   cisco_ai_agent_installer.exe
   
   # Linux
   python3 cisco_ai_agent_installer.py
   ```

2. **Run the installer**:
   - Follow the wizard interface
   - Enter your backend URL and agent token
   - Configure discovery settings
   - The installer will handle all dependencies

3. **Verify installation**:
   - Check system services for "Cisco AI Agent"
   - Monitor logs in the web interface

### Option 2: Command Line Installation

1. **Install dependencies**:
   ```bash
   pip install -r agent_requirements.txt
   ```

2. **Configure the agent**:
   ```bash
   # Create config.json
   {
     "backend_url": "https://your-backend-url.com",
     "agent_token": "your-agent-token",
     "agent_name": "My Network Agent",
     "heartbeat_interval": 30
   }
   ```

3. **Run the agent**:
   ```bash
   python cisco_ai_agent.py
   ```

## Configuration

### Agent Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `backend_url` | Cloud backend URL | Required |
| `agent_token` | Authentication token | Required |
| `agent_name` | Descriptive name | Required |
| `heartbeat_interval` | Status update frequency (seconds) | 30 |
| `log_level` | Logging detail level | INFO |

### Discovery Configuration

The agent supports multiple discovery methods:

#### SNMP Discovery
- **Community Strings**: public, private, cisco, admin
- **OIDs**: System description, hostname, location
- **Timeout**: 2 seconds per device
- **Retries**: 1 attempt

#### SSH Discovery
- **Credentials**: admin/admin, cisco/cisco, root/root
- **Commands**: hostname, uname -a
- **Timeout**: 5 seconds per connection
- **Port**: 22

#### Auto Discovery
- Combines SNMP and SSH methods
- Eliminates duplicate devices
- Optimizes discovery time

## Usage

### Starting the Agent

#### Windows Service
```cmd
# Start service
sc start CiscoAIAgent

# Stop service
sc stop CiscoAIAgent

# Check status
sc query CiscoAIAgent
```

#### Linux Service
```bash
# Start service
sudo systemctl start cisco-ai-agent

# Stop service
sudo systemctl stop cisco-ai-agent

# Check status
sudo systemctl status cisco-ai-agent

# Enable auto-start
sudo systemctl enable cisco-ai-agent
```

### Manual Operation
```bash
# Run in foreground
python cisco_ai_agent.py

# Run in background
nohup python cisco_ai_agent.py > agent.log 2>&1 &
```

### Monitoring

#### Log Files
- **Location**: `~/cisco_ai_agent/cisco_ai_agent.log`
- **Rotation**: Automatic (10MB max)
- **Levels**: DEBUG, INFO, WARNING, ERROR

#### Web Interface
- **Status**: Real-time agent status
- **Devices**: Discovered device list
- **Discovery**: Active discovery jobs
- **Logs**: Recent activity logs

## Discovery Process

### 1. Subnet Scanning
The agent scans specified subnets for network devices:
```
192.168.1.0/24 → Scan 192.168.1.1 to 192.168.1.254
10.0.0.0/16   → Scan 10.0.0.1 to 10.0.255.254
```

### 2. Device Detection
For each IP address, the agent:
1. **SNMP Query**: Try common community strings
2. **SSH Connection**: Attempt standard credentials
3. **Device Classification**: Identify device type
4. **Capability Detection**: Determine supported protocols

### 3. Data Collection
For discovered devices:
- **Basic Info**: Hostname, description, location
- **Device Type**: Router, switch, server, firewall
- **Capabilities**: SNMP, SSH, CLI support
- **Configuration**: Available config files

### 4. Backend Communication
- **Real-time**: WebSocket connection for commands
- **Batch**: HTTP API for device data
- **Status**: Regular heartbeat updates

## Security

### Authentication
- **Agent Token**: Unique per agent, company-scoped
- **Token Rotation**: Support for token updates
- **Secure Storage**: Encrypted configuration files

### Network Security
- **HTTPS**: All backend communication encrypted
- **WebSocket**: Secure real-time communication
- **Local Access**: Agent only accesses specified subnets

### Data Protection
- **No Credentials**: Agent doesn't store device passwords
- **Minimal Data**: Only essential device information
- **Company Isolation**: Data segregated by company

## Troubleshooting

### Common Issues

#### Agent Won't Start
```bash
# Check Python installation
python --version

# Verify dependencies
pip list | grep -E "(requests|pysnmp|paramiko)"

# Check configuration
cat ~/cisco_ai_agent/config.json
```

#### No Devices Discovered
```bash
# Test network connectivity
ping 192.168.1.1

# Check SNMP access
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0

# Test SSH access
ssh admin@192.168.1.1
```

#### Backend Connection Issues
```bash
# Test HTTPS connectivity
curl -I https://your-backend-url.com

# Check firewall rules
netstat -an | grep :443

# Verify agent token
curl -H "X-Agent-Token: your-token" https://your-backend-url.com/api/v1/agents/status
```

### Log Analysis

#### Error Patterns
```
ERROR: SNMP timeout - Device not responding
WARNING: SSH authentication failed - Invalid credentials
INFO: Device discovered - 192.168.1.1 (Cisco Router)
```

#### Performance Issues
- **High CPU**: Too many concurrent connections
- **Memory Leak**: Long-running discovery jobs
- **Network Timeout**: Firewall blocking access

### Support

#### Log Collection
```bash
# Collect diagnostic information
tar -czf agent_diagnostics.tar.gz \
  ~/cisco_ai_agent/config.json \
  ~/cisco_ai_agent/cisco_ai_agent.log \
  ~/cisco_ai_agent/
```

#### Contact Information
- **Documentation**: [Link to docs]
- **Support Portal**: [Link to support]
- **Email**: support@cisco-ai.com

## Advanced Configuration

### Custom Discovery Scripts
```python
# Custom device detection
def custom_device_detection(ip_address):
    # Your custom logic here
    return device_info
```

### SNMP Customization
```python
# Custom SNMP OIDs
custom_oids = [
    '1.3.6.1.2.1.1.1.0',  # System description
    '1.3.6.1.2.1.1.5.0',  # System name
    '1.3.6.1.2.1.1.6.0',  # System location
]
```

### SSH Customization
```python
# Custom SSH commands
ssh_commands = [
    'show version',
    'show running-config',
    'show interfaces',
]
```

## API Reference

### Agent Endpoints

#### Status Update
```http
PUT /api/v1/agents/status
X-Agent-Token: your-token
Content-Type: application/json

{
  "status": "online",
  "last_seen": "2025-01-27T10:00:00Z",
  "agent_name": "My Agent"
}
```

#### Device Discovery
```http
POST /api/v1/agents/discovery
X-Agent-Token: your-token
Content-Type: application/json

{
  "agent_name": "My Agent",
  "discovered_devices": [...],
  "timestamp": "2025-01-27T10:00:00Z"
}
```

#### Discovery Status
```http
POST /api/v1/agents/discovery-status
X-Agent-Token: your-token
Content-Type: application/json

{
  "agent_name": "My Agent",
  "subnet": "192.168.1.0/24",
  "status": "completed",
  "device_count": 15
}
```

## Best Practices

### Network Planning
1. **Subnet Segmentation**: Deploy agents per subnet
2. **Load Distribution**: Balance discovery across agents
3. **Redundancy**: Multiple agents for critical networks

### Security
1. **Token Management**: Rotate tokens regularly
2. **Network Access**: Limit agent network permissions
3. **Monitoring**: Monitor agent activity logs

### Performance
1. **Discovery Timing**: Schedule during low-traffic periods
2. **Resource Limits**: Monitor CPU and memory usage
3. **Network Impact**: Minimize discovery bandwidth usage

### Maintenance
1. **Regular Updates**: Keep agent software current
2. **Log Rotation**: Manage log file sizes
3. **Health Checks**: Monitor agent status regularly

## Migration Guide

### From Manual Discovery
1. **Export existing data**: Backup current device inventory
2. **Deploy agents**: Install agents in target networks
3. **Verify discovery**: Confirm all devices are found
4. **Switch over**: Enable agent-based discovery

### From Other Tools
1. **Data mapping**: Map existing device attributes
2. **Credential migration**: Update authentication methods
3. **Integration testing**: Verify data consistency
4. **Gradual rollout**: Deploy agents incrementally

## Conclusion

The Cisco AI Agent provides a robust, scalable solution for network device discovery and monitoring. By following this guide, you can successfully deploy and manage agents across your network infrastructure.

For additional support or questions, please refer to the documentation or contact our support team. 