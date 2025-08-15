from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

class NetworkDiagramNetworkBase(BaseModel):
    name: str
    description: Optional[str] = None

class NetworkDiagramNetworkCreate(NetworkDiagramNetworkBase):
    pass

class NetworkDiagramNetwork(NetworkDiagramNetworkBase):
    id: int
    class Config:
        orm_mode = True

class DeviceNodeBase(BaseModel):
    device_id: int
    position_x: int
    position_y: int
    node_type: str
    status: str
    node_data: Optional[Dict[str, Any]] = None

class DeviceNodeCreate(DeviceNodeBase):
    topology_id: int

class DeviceNodeUpdate(DeviceNodeBase):
    pass

class DeviceNode(DeviceNodeBase):
    id: int
    topology_id: int

    class Config:
        orm_mode = True

class ConnectionEdgeBase(BaseModel):
    source_node_id: int
    target_node_id: int
    connection_type: str
    status: str
    edge_data: Optional[Dict[str, Any]] = None

class ConnectionEdgeCreate(ConnectionEdgeBase):
    topology_id: int

class ConnectionEdgeUpdate(ConnectionEdgeBase):
    pass

class ConnectionEdge(ConnectionEdgeBase):
    id: int
    topology_id: int

    class Config:
        orm_mode = True

class NetworkTopologyBase(BaseModel):
    network_id: int
    name: str
    description: Optional[str] = None
    nodes: Optional[List[Dict[str, Any]]] = None
    edges: Optional[List[Dict[str, Any]]] = None

class NetworkTopologyCreate(NetworkTopologyBase):
    pass

class NetworkTopologyUpdate(NetworkTopologyBase):
    pass

class NetworkTopologyResponse(NetworkTopologyBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True 