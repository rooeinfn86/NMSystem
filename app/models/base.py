from sqlalchemy import Column, Integer, String, ForeignKey, Table, Boolean, UniqueConstraint, DateTime, Enum, CheckConstraint, Float, Text, ARRAY, func, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime
import enum
import pytz

# Import DeviceTopology to resolve relationship
from app.models.topology import DeviceTopology

def pst_now():
    utc_now = datetime.utcnow()
    pst_tz = pytz.timezone('America/Los_Angeles')
    return utc_now.replace(tzinfo=pytz.UTC).astimezone(pst_tz)

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(
        String,
        CheckConstraint("role IN ('superadmin', 'company_admin', 'full_control', 'engineer', 'viewer')"),
        default="engineer"
    )  # Added full_control role
    engineer_tier = Column(Integer, nullable=True)  # 1, 2, or 3 for engineer roles
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    position = Column(String, nullable=True)
    email = Column(String, nullable=True)
    telephone = Column(String, nullable=True)
    address = Column(String, nullable=True)

    devices = relationship("Device", back_populates="owner", cascade="all, delete-orphan")
    company = relationship("Company", back_populates="users")

    org_access = relationship("UserOrganizationAccess", back_populates="user", cascade="all, delete-orphan")
    net_access = relationship("UserNetworkAccess", back_populates="user", cascade="all, delete-orphan")
    feature_access = relationship("UserFeatureAccess", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


class Company(Base):
    __tablename__ = "companies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, unique=True)

    users = relationship("User", back_populates="company", cascade="all, delete-orphan")
    features = relationship("CompanyFeature", back_populates="company", cascade="all, delete-orphan")
    agents = relationship("Agent", back_populates="company", cascade="all, delete-orphan")
    api_tokens = relationship("CompanyAPIToken", back_populates="company", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Company(id={self.id}, name='{self.name}')>"


class Feature(Base):
    __tablename__ = "features"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    company_features = relationship("CompanyFeature", back_populates="feature")

    def __repr__(self):
        return f"<Feature(id={self.id}, name='{self.name}')>"


class CompanyFeature(Base):
    __tablename__ = "company_features"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    feature_id = Column(Integer, ForeignKey("features.id"), nullable=False)
    enabled = Column(Boolean, default=True)

    company = relationship("Company", back_populates="features")
    feature = relationship("Feature", back_populates="company_features")

    def __repr__(self):
        return f"<CompanyFeature(company_id={self.company_id}, feature_id={self.feature_id}, enabled={self.enabled})>"


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    networks = relationship("Network", back_populates="organization", cascade="all, delete-orphan")
    agents = relationship("Agent", back_populates="organization", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Organization(id={self.id}, name='{self.name}')>"


class Network(Base):
    __tablename__ = "networks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    organization = relationship("Organization", back_populates="networks")
    devices = relationship("Device", back_populates="network", cascade="all, delete-orphan")
    logs = relationship("DeviceLog", back_populates="network", cascade="all, delete-orphan")
    compliance_scans = relationship("ComplianceScan", back_populates="network", cascade="all, delete-orphan", lazy="dynamic")
    topology = relationship("DeviceTopology", back_populates="network", cascade="all, delete-orphan")
    agent_access = relationship("AgentNetworkAccess", back_populates="network", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Network(id={self.id}, name='{self.name}', org_id={self.organization_id})>"


class DeviceSNMP(Base):
    __tablename__ = "device_snmp"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    snmp_version = Column(String, nullable=False)  # v1, v2c, or v3
    community = Column(String, nullable=True)  # For v1/v2c
    username = Column(String, nullable=True)  # For v3
    auth_protocol = Column(String, nullable=True)  # For v3
    auth_password = Column(String, nullable=True)  # For v3
    priv_protocol = Column(String, nullable=True)  # For v3
    priv_password = Column(String, nullable=True)  # For v3
    port = Column(Integer, default=161)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    device = relationship("Device", back_populates="snmp_config")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    ip = Column(String, nullable=False)
    location = Column(String, nullable=False)
    type = Column(String, nullable=False)
    platform = Column(String, default="cisco_ios")
    username = Column(String, nullable=False)
    password = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    os_version = Column(String, nullable=True)
    serial_number = Column(String, nullable=True)
    interfaces = Column(String, nullable=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    ping_status = Column(Boolean, default=False)
    ssh_status = Column(Boolean, default=False)
    snmp_status = Column(Boolean, default=False)  # New field for SNMP status
    discovery_method = Column(String, default='manual')  # New field for discovery method
    snmp_config = relationship("DeviceSNMP", back_populates="device", uselist=False, cascade="all, delete-orphan")
    topology = relationship("DeviceTopology", back_populates="device", uselist=False, cascade="all, delete-orphan")

    owner = relationship("User", back_populates="devices")
    network = relationship("Network", back_populates="devices")

    def __repr__(self):
        return f"<Device(id={self.id}, name='{self.name}', ip='{self.ip}')>"


class UserOrganizationAccess(Base):
    __tablename__ = "user_organization_access"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    user = relationship("User", back_populates="org_access")
    organization = relationship("Organization")


class UserNetworkAccess(Base):
    __tablename__ = "user_network_access"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)

    user = relationship("User", back_populates="net_access")
    network = relationship("Network")


class UserFeatureAccess(Base):
    __tablename__ = "user_feature_access"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    feature_name = Column(String, nullable=False)  # e.g., 'config_assistant', 'verification'

    user = relationship("User", back_populates="feature_access")


class Agent(Base):
    __tablename__ = "agents"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    agent_token = Column(String, unique=True, nullable=False)
    status = Column(String, default="offline")  # online/offline/error
    last_heartbeat = Column(DateTime, default=datetime.utcnow)
    capabilities = Column(JSON)  # List of agent capabilities
    version = Column(String, default="1.0.0")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # New agent token management fields
    token_status = Column(String, nullable=False, default='active')
    scopes = Column(JSON, nullable=True, default=lambda: ["monitoring", "heartbeat"])
    issued_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    last_used_ip = Column(String, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Topology discovery fields
    topology_discovery_status = Column(String, default="idle")  # idle, discovering, completed, failed
    last_topology_discovery = Column(DateTime, nullable=True)
    topology_discovery_config = Column(JSON, nullable=True)  # Discovery settings and preferences
    discovered_devices_count = Column(Integer, default=0)
    topology_last_updated = Column(DateTime, nullable=True)
    topology_discovery_progress = Column(Integer, default=0)  # Progress percentage (0-100)
    topology_error_message = Column(Text, nullable=True)  # Error message if discovery failed

    company = relationship("Company", back_populates="agents")
    organization = relationship("Organization", back_populates="agents")
    network_access = relationship("AgentNetworkAccess", back_populates="agent", cascade="all, delete-orphan")
    # New: audit log relationship
    audit_logs = relationship("AgentTokenAuditLog", back_populates="agent", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Agent(id={self.id}, name='{self.name}', company_id={self.company_id}, org_id={self.organization_id})>"


class AgentNetworkAccess(Base):
    __tablename__ = "agent_network_access"
    
    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    network_id = Column(Integer, ForeignKey("networks.id", ondelete="CASCADE"), nullable=False)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    agent = relationship("Agent", back_populates="network_access")
    network = relationship("Network")
    company = relationship("Company")
    organization = relationship("Organization")

    __table_args__ = (
        UniqueConstraint('agent_id', 'network_id', name='uq_agent_network'),
    )

    def __repr__(self):
        return f"<AgentNetworkAccess(agent_id={self.agent_id}, network_id={self.network_id})>"


class CompanyAPIToken(Base):
    __tablename__ = "company_api_tokens"
    
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    token_hash = Column(String, unique=True, nullable=False)
    name = Column(String, nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    
    company = relationship("Company", back_populates="api_tokens")
    creator = relationship("User")

    def __repr__(self):
        return f"<CompanyAPIToken(id={self.id}, company_id={self.company_id}, name='{self.name}')>"


class LogType(str, enum.Enum):
    INVALID_CREDENTIALS = "invalid_credentials"
    UNREACHABLE = "unreachable"
    SUCCESS = "success"


class DeviceLog(Base):
    __tablename__ = "device_logs"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, nullable=False)
    log_type = Column(Enum(LogType), nullable=False)
    message = Column(String, nullable=False)
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)
    created_at = Column(DateTime, default=pst_now)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)

    network = relationship("Network", back_populates="logs")

    def __repr__(self):
        return f"<DeviceLog(id={self.id}, ip='{self.ip_address}', type='{self.log_type}')>"


# New: AgentTokenAuditLog model
class AgentTokenAuditLog(Base):
    __tablename__ = "agent_token_audit_logs"
    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False)
    event_type = Column(String, nullable=False)  # e.g., 'issued', 'used', 'rotated', 'revoked', 'failed_auth'
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    ip_address = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    details = Column(JSON, nullable=True)

    agent = relationship("Agent", back_populates="audit_logs")






