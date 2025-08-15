from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime

class AgentTopologyDiscoveryRequest(BaseModel):
    """Request to start topology discovery on an agent."""
    network_id: int = Field(..., description="Network ID to discover")
    discovery_type: str = Field(default="full", description="Type of discovery: full, neighbors, interfaces")
    force_refresh: bool = Field(default=False, description="Force refresh existing data")

class AgentTopologyDiscoveryStatus(BaseModel):
    """Status of topology discovery on an agent."""
    agent_id: int
    network_id: int
    status: str = Field(..., description="Discovery status: idle, discovering, completed, failed")
    progress: int = Field(default=0, description="Discovery progress percentage (0-100)")
    discovered_devices: int = Field(default=0, description="Number of devices discovered")
    discovered_connections: int = Field(default=0, description="Number of connections discovered")
    start_time: Optional[datetime] = Field(default=None, description="When discovery started")
    end_time: Optional[datetime] = Field(default=None, description="When discovery completed")
    error_message: Optional[str] = Field(default=None, description="Error message if failed")
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class AgentDeviceDiscovery(BaseModel):
    """Device information discovered by an agent."""
    ip_address: str = Field(..., description="Device IP address")
    hostname: str = Field(..., description="Device hostname")
    device_type: str = Field(..., description="Device type (router, switch, etc.)")
    platform: str = Field(..., description="Device platform/model")
    vendor: str = Field(..., description="Device vendor")
    os_version: str = Field(..., description="Operating system version")
    serial_number: str = Field(..., description="Device serial number")
    uptime: Optional[str] = Field(default=None, description="Device uptime")
    ping_status: bool = Field(default=False, description="Device ping status")
    snmp_status: bool = Field(default=False, description="Device SNMP status")
    ssh_status: bool = Field(default=False, description="Device SSH status")
    discovery_timestamp: datetime = Field(default_factory=datetime.utcnow)

class AgentInterfaceDiscovery(BaseModel):
    """Interface information discovered by an agent."""
    interface_name: str = Field(..., description="Interface name")
    interface_description: Optional[str] = Field(default=None, description="Interface description")
    interface_type: str = Field(..., description="Interface type")
    operational_status: str = Field(..., description="Operational status (up/down)")
    administrative_status: str = Field(..., description="Administrative status (up/down)")
    speed: Optional[str] = Field(default=None, description="Interface speed")
    mac_address: Optional[str] = Field(default=None, description="Interface MAC address")
    ip_address: Optional[str] = Field(default=None, description="Interface IP address")
    vlan: Optional[str] = Field(default=None, description="VLAN information")

class AgentNeighborDiscovery(BaseModel):
    """Neighbor information discovered by an agent."""
    local_device_ip: str = Field(..., description="Local device IP")
    local_interface: str = Field(..., description="Local interface name")
    neighbor_device_ip: str = Field(..., description="Neighbor device IP")
    neighbor_hostname: str = Field(..., description="Neighbor hostname")
    neighbor_interface: str = Field(..., description="Neighbor interface name")
    neighbor_platform: Optional[str] = Field(default=None, description="Neighbor platform")
    discovery_protocol: str = Field(..., description="Discovery protocol (CDP/LLDP)")
    discovery_timestamp: datetime = Field(default_factory=datetime.utcnow)

class AgentTopologyUpdate(BaseModel):
    """Complete topology update from an agent."""
    agent_id: int = Field(..., description="Agent ID")
    network_id: int = Field(..., description="Network ID")
    discovery_timestamp: datetime = Field(default_factory=datetime.utcnow)
    devices: List[AgentDeviceDiscovery] = Field(default=[], description="Discovered devices")
    interfaces: List[AgentInterfaceDiscovery] = Field(default=[], description="Discovered interfaces")
    neighbors: List[AgentNeighborDiscovery] = Field(default=[], description="Discovered neighbors")
    summary: Dict[str, Any] = Field(default={}, description="Discovery summary")

class AgentTopologyResponse(BaseModel):
    """Response containing agent topology data."""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Response message")
    data: Optional[AgentTopologyUpdate] = Field(default=None, description="Topology data")
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class AgentTopologyListResponse(BaseModel):
    """Response containing list of agent topology discoveries."""
    success: bool = Field(..., description="Whether the operation was successful")
    message: str = Field(..., description="Response message")
    discoveries: List[AgentTopologyDiscoveryStatus] = Field(default=[], description="List of discoveries")
    total_count: int = Field(default=0, description="Total number of discoveries")
    timestamp: datetime = Field(default_factory=datetime.utcnow) 