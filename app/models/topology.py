from sqlalchemy import Column, Integer, String, Float, Boolean, ForeignKey, DateTime, JSON
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime

class DeviceTopology(Base):
    __tablename__ = "device_topology"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)
    hostname = Column(String)
    vendor = Column(String)
    model = Column(String)
    uptime = Column(Integer)  # in seconds
    last_polled = Column(DateTime, default=datetime.utcnow)
    health_data = Column(JSONB)
    
    # Relationships
    device = relationship("Device", back_populates="topology")
    network = relationship("Network", back_populates="topology")
    interfaces = relationship("InterfaceTopology", back_populates="device", cascade="all, delete-orphan")
    neighbors = relationship("NeighborTopology", back_populates="device", cascade="all, delete-orphan")

class InterfaceTopology(Base):
    __tablename__ = "interface_topology"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("device_topology.id"), nullable=False)
    interface_index = Column(Integer)
    name = Column(String)
    admin_status = Column(String)
    oper_status = Column(String)
    speed = Column(Integer, nullable=True)  # in bits per second, nullable
    mac_address = Column(String)
    last_polled = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("DeviceTopology", back_populates="interfaces")

class NeighborTopology(Base):
    __tablename__ = "neighbor_topology"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("device_topology.id"), nullable=False)
    local_interface = Column(String)
    neighbor_id = Column(String)
    neighbor_port = Column(String)
    neighbor_platform = Column(String)
    discovery_protocol = Column(String)  # 'cdp' or 'lldp'
    last_polled = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("DeviceTopology", back_populates="neighbors") 