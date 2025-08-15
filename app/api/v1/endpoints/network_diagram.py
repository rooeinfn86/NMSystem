from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.core.dependencies import get_db, get_current_user
from app.models.network_diagram import NetworkTopology, DeviceNode, ConnectionEdge, NetworkDiagramNetwork
from app.schemas.network_diagram import (
    NetworkTopologyCreate,
    NetworkTopologyUpdate,
    NetworkTopologyResponse,
    DeviceNodeCreate,
    DeviceNodeUpdate,
    ConnectionEdgeCreate,
    ConnectionEdgeUpdate,
    NetworkDiagramNetworkCreate,
    NetworkDiagramNetwork
)
from app.crud import network_diagram as crud

router = APIRouter()

@router.get("/topologies/{network_id}", response_model=List[NetworkTopologyResponse])
def get_network_topologies(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all topologies for a specific network"""
    return crud.get_network_topologies(db, network_id)

@router.post("/topologies/", response_model=NetworkTopologyResponse)
def create_network_topology(
    topology: NetworkTopologyCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new network topology"""
    return crud.create_network_topology(db, topology)

@router.put("/topologies/{topology_id}", response_model=NetworkTopologyResponse)
def update_network_topology(
    topology_id: int,
    topology: NetworkTopologyUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an existing network topology"""
    return crud.update_network_topology(db, topology_id, topology)

@router.delete("/topologies/{topology_id}")
def delete_network_topology(
    topology_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a network topology"""
    return crud.delete_network_topology(db, topology_id)

@router.get("/nodes/{topology_id}", response_model=List[DeviceNode])
def get_topology_nodes(
    topology_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all nodes for a specific topology"""
    return crud.get_topology_nodes(db, topology_id)

@router.post("/nodes/", response_model=DeviceNode)
def create_device_node(
    node: DeviceNodeCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new device node"""
    return crud.create_device_node(db, node)

@router.put("/nodes/{node_id}", response_model=DeviceNode)
def update_device_node(
    node_id: int,
    node: DeviceNodeUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an existing device node"""
    return crud.update_device_node(db, node_id, node)

@router.delete("/nodes/{node_id}")
def delete_device_node(
    node_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a device node"""
    return crud.delete_device_node(db, node_id)

@router.get("/edges/{topology_id}", response_model=List[ConnectionEdge])
def get_topology_edges(
    topology_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all edges for a specific topology"""
    return crud.get_topology_edges(db, topology_id)

@router.post("/edges/", response_model=ConnectionEdge)
def create_connection_edge(
    edge: ConnectionEdgeCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new connection edge"""
    return crud.create_connection_edge(db, edge)

@router.put("/edges/{edge_id}", response_model=ConnectionEdge)
def update_connection_edge(
    edge_id: int,
    edge: ConnectionEdgeUpdate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update an existing connection edge"""
    return crud.update_connection_edge(db, edge_id, edge)

@router.delete("/edges/{edge_id}")
def delete_connection_edge(
    edge_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a connection edge"""
    return crud.delete_connection_edge(db, edge_id)

@router.get("/diagram-networks/", response_model=List[NetworkDiagramNetwork])
def get_diagram_networks(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    return crud.get_network_diagram_networks(db)

@router.post("/diagram-networks/", response_model=NetworkDiagramNetwork)
def create_diagram_network(
    network: NetworkDiagramNetworkCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    return crud.create_network_diagram_network(db, network) 