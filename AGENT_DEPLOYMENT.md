# Local Agent Deployment Guide

This guide explains how to deploy and use the Local Agent system for multi-tenant device discovery in your Cisco AI Backend.

## Overview

The Local Agent system allows you to run device discovery and management on your local network while keeping your backend in the cloud. This solves the network connectivity issue when your cloud backend cannot directly access devices on your local network.

## Architecture

```
Your Local Network ←→ Local Agent ←→ Cloud Backend ←→ Web UI
     ↑                    ↑              ↑              ↑
  Devices              Agent Service   API/Web UI    Users
```

## Multi-Tenant Structure

The system enforces strict company isolation - users can only access their own company's data:

```
Company A (Acme Corp)
├── User 1 (company_admin) - Can only see Acme Corp data
│   ├── Organization 1 (owned by User 1)
│   │   ├── Network 1 ←→ Agent A1
│   │   │   ├── Device 1
│   │   │   └── Device 2
│   │   └── Network 2 ←→ Agent A1
│   │       ├── Device 3
│   │       └── Device 4
│   └── Organization 2 (owned by User 1)
│       └── Network 3 ←→ Agent A2
│           └── Device 5
└── User 2 (engineer) - Can only see Acme Corp data
    └── (has access to Organization 1)

Company B (TechStart) - Completely isolated
├── User 3 (company_admin) - Can only see TechStart data
│   └── Organization 3 (owned by User 3)
│       └── Network 4 ←→ Agent B1
│           └── Device 6
└── User 4 (engineer) - Can only see TechStart data
    └── (has access to Organization 3)
```

**Key Security Features:**
- ✅ **Company Isolation**: Users cannot see or access other companies' data
- ✅ **Automatic Company Assignment**: Agents are automatically assigned to user's company
- ✅ **Organization Validation**: Users can only register agents for their company's organizations
- ✅ **Network Validation**: Users can only access networks in their company's organizations

## Prerequisites

1. **Python 3.8+** installed on your local machine
2. **Network access** to your devices (SNMP and SSH)
3. **Authentication token** from your cloud backend
4. **Company and Organization IDs** from your cloud backend

## Quick Start

### 1. Automatic Setup (Recommended)

Run the deployment script to automatically set up your agent:

```bash
python deploy_agent.py
```

The script will:
- Connect to your cloud backend
- Fetch your companies, organizations, and networks
- Register your agent
- Create the configuration file

### 2. Manual Setup

If you prefer manual setup:

#### Step 1: Install Dependencies

```bash
pip install -r agent_requirements.txt
```

#### Step 2: Create Configuration

Copy the sample configuration:

```bash
cp agent_config_sample.json agent_config.json
```

Edit `agent_config.json` with your details:

```json
{
  "agent_token": "your_agent_token_from_cloud",
  "cloud_url": "https://your-cloud-backend.com",
  "company_id": 1,
  "organization_id": 1,
  "networks": [1, 2, 3],
  "capabilities": [
    "snmp_discovery",
    "ssh_config", 
    "health_monitoring"
  ],
  "version": "1.0.0"
}
```

#### Step 3: Register Agent

You need to register your agent with the cloud backend to get an agent token. You can do this through:

1. **API Call**: Use the `/api/v1/agents/register` endpoint
2. **Web UI**: Use the agent management interface
3. **Deployment Script**: Use the automatic setup

#### Step 4: Run Agent

```bash
python local_agent.py
```

## Configuration Details

### Agent Configuration File (`agent_config.json`)

| Field | Description | Required |
|-------|-------------|----------|
| `agent_token` | Secure token for agent authentication | Yes |
| `cloud_url` | URL of your cloud backend | Yes |
| `company_id` | Your company ID (automatically set) | Yes |
| `organization_id` | Your organization ID | Yes |
| `networks` | List of network IDs this agent can access | Yes |
| `capabilities` | List of agent capabilities | No |
| `version` | Agent version | No |

**Note**: The `company_id` is automatically set based on your user account - you cannot change it or access other companies' data.

### Agent Capabilities

- `snmp_discovery`: Discover devices using SNMP
- `ssh_config`: Configure devices using SSH
- `health_monitoring`: Monitor device health

## Usage

### Starting the Agent

```bash
# Start agent in foreground
python local_agent.py

# Start agent in background (Linux/Mac)
nohup python local_agent.py > agent.log 2>&1 &

# Start agent as Windows service
# Use a service manager like NSSM or create a Windows service
```

### Agent Status

The agent will:
1. **Connect** to your cloud backend via WebSocket
2. **Send heartbeats** every 30 seconds
3. **Handle discovery requests** from the cloud
4. **Log activities** to `local_agent.log`

### Monitoring

You can monitor your agent through:

1. **Cloud Dashboard**: View agent status in your web UI
2. **Logs**: Check `local_agent.log` for detailed information
3. **API**: Use `/api/v1/agents/status/{agent_id}` endpoint

## Multi-Tenant Deployment Scenarios

### Scenario 1: Single Company, Multiple Organizations

```
Company A
├── Organization 1 (HQ) ←→ Agent A1
│   ├── Network 1 (Main Office)
│   └── Network 2 (Data Center)
└── Organization 2 (Branch) ←→ Agent A2
    └── Network 3 (Branch Office)
```

**Setup**: Deploy one agent per organization

### Scenario 2: Multiple Companies

```
Company A: Organization 1 ←→ Agent A1
Company B: Organization 2 ←→ Agent B1
Company C: Organization 3 ←→ Agent C1
```

**Setup**: Deploy one agent per company/organization

### Scenario 3: Complex Multi-Tenant

```
Company A:
  ├── Organization 1: Networks 1,2 ←→ Agent A1
  └── Organization 2: Networks 3,4 ←→ Agent A2

Company B:
  ├── Organization 3: Networks 5,6 ←→ Agent B1
  └── Organization 4: Networks 7,8 ←→ Agent B2
```

**Setup**: Deploy agents based on your access control needs

## Security

### Authentication
- **Agent Token**: Secure 32-character token for agent authentication
- **User Authentication**: Standard JWT tokens for user access
- **Network Isolation**: Agents only access networks they're assigned to

### Access Control
- **Company Isolation**: Users and agents can only access their company's data
- **Organization Isolation**: Users can only register agents for their company's organizations
- **Network Isolation**: Agents can only access networks in their assigned organizations
- **User Validation**: All operations validate user's company membership

### Communication
- **HTTPS**: All communication with cloud backend uses HTTPS
- **WebSocket**: Real-time communication for discovery requests
- **Heartbeat**: Regular status updates to cloud backend

## Troubleshooting

### Common Issues

#### 1. Agent Won't Connect
```
Error: Failed to connect to WebSocket
```
**Solution**: Check your `cloud_url` and network connectivity

#### 2. Invalid Agent Token
```
Error: Invalid agent token
```
**Solution**: Re-register your agent to get a new token

#### 3. No Network Access
```
Error: No access to network X
```
**Solution**: Check that the network ID is in your agent's `networks` list

#### 4. SNMP Discovery Fails
```
Error: SNMP connection failed
```
**Solution**: Check SNMP configuration and network connectivity

### Logs

Check `local_agent.log` for detailed error information:

```bash
# View recent logs
tail -f local_agent.log

# Search for errors
grep ERROR local_agent.log

# Search for specific device
grep "192.168.1.1" local_agent.log
```

### Health Check

You can check agent health via API:

```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
     https://your-cloud-backend.com/api/v1/agents/status/AGENT_ID
```

## API Reference

### Agent Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agents/register` | POST | Register new agent |
| `/api/v1/agents/heartbeat` | POST | Update agent heartbeat |
| `/api/v1/agents/` | GET | List agents |
| `/api/v1/agents/{agent_id}` | GET | Get agent details |
| `/api/v1/agents/{agent_id}` | PUT | Update agent |
| `/api/v1/agents/{agent_id}` | DELETE | Delete agent |
| `/api/v1/agents/status/{agent_id}` | GET | Get agent status |
| `/api/v1/agents/discovery` | POST | Route discovery request |

### Discovery Request Format

```json
{
  "network_id": 1,
  "ip_range": "192.168.1.0/24",
  "username": "admin",
  "password": "password",
  "device_type": "cisco_ios",
  "location": "Main Office",
  "snmp_version": "v2c",
  "community": "public",
  "snmp_port": "161"
}
```

## Support

For issues and questions:

1. Check the troubleshooting section above
2. Review the logs in `local_agent.log`
3. Check agent status in your cloud dashboard
4. Contact your system administrator

## Development

### Adding New Capabilities

To add new agent capabilities:

1. Update the agent code in `local_agent.py`
2. Add the capability to your agent configuration
3. Update the cloud backend to handle the new capability

### Customizing Discovery

You can customize the discovery process by modifying the `scan_single_device` method in `local_agent.py`.

## License

This agent system is part of the Cisco AI Backend project and follows the same licensing terms. 