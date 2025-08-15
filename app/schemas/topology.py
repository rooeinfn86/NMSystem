from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from datetime import datetime

class DeviceTopologyBase(BaseModel):
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    uptime: Optional[int] = None
    health_data: Optional[Dict[str, Any]] = None

class DeviceTopologyCreate(DeviceTopologyBase):
    device_id: int
    network_id: int

class DeviceTopology(DeviceTopologyBase):
    id: int
    device_id: int
    network_id: int
    last_polled: datetime

    class Config:
        from_attributes = True

class InterfaceTopologyBase(BaseModel):
    interface_index: Optional[int] = None
    name: Optional[str] = None
    admin_status: Optional[str] = None
    oper_status: Optional[str] = None
    speed: Optional[int] = None
    mac_address: Optional[str] = None

class InterfaceTopologyCreate(InterfaceTopologyBase):
    device_id: int

class InterfaceTopology(InterfaceTopologyBase):
    id: int
    device_id: int
    last_polled: datetime

    class Config:
        from_attributes = True

class NeighborTopologyBase(BaseModel):
    local_interface: Optional[str] = None
    neighbor_id: Optional[str] = None
    neighbor_port: Optional[str] = None
    neighbor_platform: Optional[str] = None
    discovery_protocol: Optional[str] = None

class NeighborTopologyCreate(NeighborTopologyBase):
    device_id: int

class NeighborTopology(NeighborTopologyBase):
    id: int
    device_id: int
    last_polled: datetime

    class Config:
        from_attributes = True

class TopologyNode(BaseModel):
    id: str
    label: str
    type: str
    data: Optional[Dict[str, Any]] = None

class TopologyLink(BaseModel):
    source: str
    target: str
    type: str
    data: Optional[Dict[str, Any]] = None

class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    links: List[TopologyLink] 