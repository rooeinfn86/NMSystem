from pydantic import BaseModel, Field, constr
from typing import List, Optional, Literal
from datetime import datetime
from enum import Enum
from pydantic import validator

# ------------------- SNMP Schemas -------------------

class DeviceSNMPBase(BaseModel):
    snmp_version: str = 'v2c'
    community: Optional[str] = 'public'
    username: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_password: Optional[str] = None
    port: int = 161

class DeviceSNMPCreate(DeviceSNMPBase):
    device_id: int

class DeviceSNMP(DeviceSNMPBase):
    id: int
    device_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

# ------------------- Device Schemas -------------------

class DeviceBase(BaseModel):
    name: str
    ip: str
    location: str
    type: str
    username: str
    password: str
    is_active: Optional[bool] = True
    discovery_method: Optional[str] = 'manual'
    snmp_config: Optional[DeviceSNMPBase] = None

class DeviceCreate(DeviceBase):
    network_id: int

class NetworkSimple(BaseModel):
    id: int
    name: str
    organization_id: int

    class Config:
        from_attributes = True

class Device(BaseModel):
    id: int
    name: str
    ip: str
    location: str
    type: str
    platform: str = "cisco_ios"
    username: str
    password: str
    network_id: Optional[int] = None
    owner_id: int
    company_id: Optional[int] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    ping_status: Optional[bool] = None
    snmp_status: Optional[bool] = None
    ssh_status: Optional[bool] = None
    last_status_check: Optional[datetime] = None
    discovery_method: Optional[str] = 'manual'

    class Config:
        from_attributes = True

# ------------------- Network Schemas -------------------

class NetworkBase(BaseModel):
    name: str

class NetworkCreate(NetworkBase):
    organization_id: int

class OrganizationSimple(BaseModel):
    id: int
    name: str

    class Config:
        from_attributes = True

class Network(NetworkBase):
    id: int
    organization_id: int
    devices: List[Device] = Field(default_factory=list)
    organization: Optional[OrganizationSimple] = None

    class Config:
        from_attributes = True

# ------------------- Organization Schemas -------------------

class OrganizationBase(BaseModel):
    name: str

class OrganizationCreate(OrganizationBase):
    pass

class Organization(OrganizationBase):
    id: int
    devices: List[Device] = Field(default_factory=list)
    organization: Optional[OrganizationSimple] = None

    class Config:
        from_attributes = True

# ------------------- User Schemas -------------------

class UserBase(BaseModel):
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    position: Optional[str] = None
    email: Optional[str] = None
    telephone: Optional[str] = None
    address: Optional[str] = None

class UserCreate(UserBase):
    password: str
    role: Literal["superadmin", "company_admin", "full_control", "engineer", "viewer"] = "engineer"
    company_id: Optional[int] = None
    engineer_tier: Optional[int] = None

class UserLogin(BaseModel):
    username: str
    password: str

class UserFeatureAccess(BaseModel):
    feature_name: str
    class Config:
        orm_mode = True

class User(UserBase):
    id: int
    role: Optional[str] = None
    engineer_tier: Optional[int] = None
    company_id: Optional[int] = None
    devices: List[Device] = Field(default_factory=list)
    organizations: List[Organization] = Field(default_factory=list)
    networks: List[Network] = Field(default_factory=list)
    feature_access_display: List[dict] = Field(default_factory=list)

    class Config:
        from_attributes = True

class UserPublic(BaseModel):
    id: int
    username: str
    role: str

    class Config:
        from_attributes = True

# ------------------- Company Schemas -------------------

class CompanyBase(BaseModel):
    name: str

class CompanyCreate(CompanyBase):
    username: str
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    position: Optional[str] = None
    email: Optional[str] = None
    telephone: Optional[str] = None
    address: Optional[str] = None
    config_assistant_enabled: Optional[bool] = False
    verification_enabled: Optional[bool] = False
    compliance_enabled: Optional[bool] = False

class Company(CompanyBase):
    id: int
    config_assistant_enabled: bool = False
    verification_enabled: bool = False
    compliance_enabled: bool = False
    users: List[User] = Field(default_factory=list)

    class Config:
        from_attributes = True

# ✅ Add a clean response model for feature access
class FeatureAccessResponse(BaseModel):
    company_id: int
    config_assistant_enabled: bool
    verification_enabled: bool
    compliance_enabled: bool

    class Config:
        from_attributes = True

# ------------------- Team Member Management -------------------

class TeamMemberCreate(BaseModel):
    username: str
    password: str
    role: Literal["full_control", "engineer", "viewer"]
    organization_ids: Optional[List[int]] = None
    network_ids: Optional[List[int]] = None
    feature_names: Optional[List[str]] = None
    engineer_tier: Optional[int] = None

class TeamMemberAccess(BaseModel):
    user_id: int
    organization_ids: List[int] = Field(default_factory=list)
    network_ids: List[int] = Field(default_factory=list)
    feature_names: List[str] = Field(default_factory=list)

    class Config:
        from_attributes = True

class DeviceLogBase(BaseModel):
    ip_address: str
    log_type: Literal["unknown_device", "invalid_credentials", "unreachable", "success"]
    message: str
    network_id: int

class DeviceLogCreate(DeviceLogBase):
    pass

class DeviceLog(DeviceLogBase):
    id: int
    created_at: datetime
    company_id: Optional[int] = None

    class Config:
        from_attributes = True


class UserFeatureAccessCreate(BaseModel):
    user_id: int
    feature_name: str

    class Config:
        from_attributes = True


class AgentBase(BaseModel):
    name: str
    company_id: int
    organization_id: int
    capabilities: Optional[List[str]] = ["snmp_discovery", "ssh_config", "health_monitoring"]
    version: Optional[str] = "1.0.0"

    class Config:
        from_attributes = True


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    capabilities: Optional[List[str]] = None
    version: Optional[str] = None

    class Config:
        from_attributes = True


class AgentResponse(AgentBase):
    id: int
    agent_token: str
    status: str
    last_heartbeat: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    # New agent token management fields
    token_status: str
    scopes: Optional[list] = None
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    rotated_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    last_used_ip: Optional[str] = None
    created_by: Optional[int] = None

    class Config:
        from_attributes = True

# New: AgentTokenAuditLog schema
class AgentTokenAuditLogResponse(BaseModel):
    id: int
    agent_id: int
    event_type: str
    timestamp: datetime
    ip_address: Optional[str] = None
    user_id: Optional[int] = None
    details: Optional[dict] = None

    class Config:
        from_attributes = True


class AgentNetworkAccessBase(BaseModel):
    agent_id: int
    network_id: int
    company_id: int
    organization_id: int

    class Config:
        from_attributes = True


class AgentNetworkAccessCreate(AgentNetworkAccessBase):
    pass


class AgentNetworkAccessResponse(AgentNetworkAccessBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class AgentRegistration(BaseModel):
    name: str
    organization_id: int
    capabilities: Optional[List[str]] = ["snmp_discovery", "ssh_config", "health_monitoring"]
    version: Optional[str] = "1.0.0"
    networks: List[int]  # List of network IDs this agent can access

    class Config:
        from_attributes = True


class AgentHeartbeat(BaseModel):
    agent_token: str
    status: str = "online"
    capabilities: Optional[List[str]] = None
    version: Optional[str] = None

    class Config:
        from_attributes = True


class DiscoveryRequest(BaseModel):
    network_id: int
    ip_range: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    username: str
    password: str
    device_type: str = "cisco_ios"
    location: str = ""
    snmp_version: Optional[str] = None
    community: Optional[str] = None
    snmp_username: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_password: Optional[str] = None
    snmp_port: str = "161"

    class Config:
        from_attributes = True


class DiscoveryResponse(BaseModel):
    status: str
    message: str
    discovered_devices: Optional[List[dict]] = None
    errors: Optional[List[str]] = None

    class Config:
        from_attributes = True


class CompanyAPITokenBase(BaseModel):
    name: str

    class Config:
        from_attributes = True


class CompanyAPITokenCreate(CompanyAPITokenBase):
    pass


class CompanyAPITokenUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None

    class Config:
        from_attributes = True


class CompanyAPITokenResponse(CompanyAPITokenBase):
    id: int
    company_id: int
    created_by: int
    created_at: datetime
    is_active: bool
    last_used: Optional[datetime] = None
    token: Optional[str] = None  # Only shown when creating

    class Config:
        from_attributes = True


class CompanyTokenValidation(BaseModel):
    token: str

    class Config:
        from_attributes = True


class SNMPv3Config(BaseModel):
    """SNMPv3 configuration schema."""
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "noAuthNoPriv"
    username: str
    auth_protocol: Optional[Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[Literal["DES", "AES", "AES192", "AES256", "AES192CISCO", "AES256CISCO"]] = None
    priv_password: Optional[str] = None

    class Config:
        from_attributes = True


class DiscoveryMethod(BaseModel):
    """Discovery method configuration."""
    method: Literal["auto", "snmp_only", "ssh_only", "ping_only"] = "auto"
    snmp_config: Optional[SNMPv3Config] = None
    snmp_community: Optional[str] = None
    snmp_version: Optional[Literal["v1", "v2c", "v3"]] = None
    snmp_port: int = 161
    ssh_port: int = 22
    timeout: int = 5

    class Config:
        from_attributes = True


class AgentDiscoveryRequest(BaseModel):
    """Enhanced discovery request with agent selection and SNMP configuration."""
    network_id: int
    agent_ids: List[int]  # Multiple agents for parallel discovery
    ip_range: Optional[str] = None
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    discovery_method: DiscoveryMethod
    credentials: Optional[dict] = None  # SSH credentials if needed
    location: str = ""
    device_type: str = "auto"

    class Config:
        from_attributes = True


class DiscoverySession(BaseModel):
    """Discovery session tracking."""
    session_id: str
    network_id: int
    agent_ids: List[int]
    status: Literal["pending", "started", "in_progress", "completed", "failed", "cancelled"]
    progress: int = 0  # 0-100
    started_at: datetime
    completed_at: Optional[datetime] = None
    discovered_devices: List[dict] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    total_ips: Optional[int] = None
    processed_ips: int = 0

    class Config:
        from_attributes = True


class DiscoveryDevice(BaseModel):
    """Discovered device information."""
    ip_address: str
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    os_version: Optional[str] = None
    serial_number: Optional[str] = None
    location: Optional[str] = None
    status: Literal["online", "offline", "unknown"] = "unknown"
    discovery_method: Literal["snmp", "ssh", "ping"] = "ping"
    discovered_by_agent: int
    discovered_at: datetime
    snmp_info: Optional[dict] = None
    ssh_info: Optional[dict] = None

    class Config:
        from_attributes = True


class DiscoveryProgress(BaseModel):
    """Discovery progress update."""
    session_id: str
    agent_id: int
    progress: int
    processed_ips: int
    discovered_devices: List[DiscoveryDevice]
    errors: List[str]
    status: Literal["running", "completed", "failed"]

    class Config:
        from_attributes = True

