from sqlalchemy import Column, Integer, String, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime

class NetworkDiagramNetwork(Base):
    __tablename__ = "network_diagram_networks"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String, nullable=True)

class NetworkTopology(Base):
    __tablename__ = "network_topologies"

    id = Column(Integer, primary_key=True, index=True)
    network_id = Column(Integer, ForeignKey("network_diagram_networks.id"))
    name = Column(String)
    description = Column(String, nullable=True)
    nodes = Column(JSON)  # Store node data as JSON
    edges = Column(JSON)  # Store edge data as JSON
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    network = relationship("NetworkDiagramNetwork", back_populates="topologies")

class DeviceNode(Base):
    __tablename__ = "device_nodes"

    id = Column(Integer, primary_key=True, index=True)
    topology_id = Column(Integer, ForeignKey("network_topologies.id"))
    device_id = Column(Integer)
    position_x = Column(Integer)
    position_y = Column(Integer)
    node_type = Column(String)  # e.g., 'router', 'switch', 'firewall'
    status = Column(String)  # e.g., 'active', 'inactive', 'warning'
    node_data = Column(JSON, nullable=True)  # Additional device-specific data

    # Relationships
    topology = relationship("NetworkTopology", back_populates="device_nodes")

class ConnectionEdge(Base):
    __tablename__ = "connection_edges"

    id = Column(Integer, primary_key=True, index=True)
    topology_id = Column(Integer, ForeignKey("network_topologies.id"))
    source_node_id = Column(Integer, ForeignKey("device_nodes.id"))
    target_node_id = Column(Integer, ForeignKey("device_nodes.id"))
    connection_type = Column(String)  # e.g., 'ethernet', 'serial', 'vpn'
    status = Column(String)  # e.g., 'up', 'down', 'degraded'
    edge_data = Column(JSON, nullable=True)  # Additional connection-specific data

    # Relationships
    topology = relationship("NetworkTopology", back_populates="connection_edges")
    source_node = relationship("DeviceNode", foreign_keys=[source_node_id])
    target_node = relationship("DeviceNode", foreign_keys=[target_node_id]) 