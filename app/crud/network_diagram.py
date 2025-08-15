from sqlalchemy.orm import Session
from app.models.network_diagram import NetworkTopology, DeviceNode, ConnectionEdge, NetworkDiagramNetwork
from app.schemas.network_diagram import (
    NetworkTopologyCreate,
    NetworkTopologyUpdate,
    DeviceNodeCreate,
    DeviceNodeUpdate,
    ConnectionEdgeCreate,
    ConnectionEdgeUpdate,
    NetworkDiagramNetworkCreate
)

def create_network_diagram_network(db: Session, network: NetworkDiagramNetworkCreate):
    db_network = NetworkDiagramNetwork(**network.dict())
    db.add(db_network)
    db.commit()
    db.refresh(db_network)
    return db_network

def get_network_diagram_networks(db: Session):
    return db.query(NetworkDiagramNetwork).all()

def get_network_topologies(db: Session, network_id: int):
    return db.query(NetworkTopology).filter(NetworkTopology.network_id == network_id).all()

def get_network_topology(db: Session, topology_id: int):
    return db.query(NetworkTopology).filter(NetworkTopology.id == topology_id).first()

def create_network_topology(db: Session, topology: NetworkTopologyCreate):
    db_topology = NetworkTopology(**topology.dict())
    db.add(db_topology)
    db.commit()
    db.refresh(db_topology)
    return db_topology

def update_network_topology(db: Session, topology_id: int, topology: NetworkTopologyUpdate):
    db_topology = get_network_topology(db, topology_id)
    if not db_topology:
        return None
    
    for key, value in topology.dict(exclude_unset=True).items():
        setattr(db_topology, key, value)
    
    db.commit()
    db.refresh(db_topology)
    return db_topology

def delete_network_topology(db: Session, topology_id: int):
    db_topology = get_network_topology(db, topology_id)
    if not db_topology:
        return False
    
    db.delete(db_topology)
    db.commit()
    return True

def get_topology_nodes(db: Session, topology_id: int):
    return db.query(DeviceNode).filter(DeviceNode.topology_id == topology_id).all()

def get_device_node(db: Session, node_id: int):
    return db.query(DeviceNode).filter(DeviceNode.id == node_id).first()

def create_device_node(db: Session, node: DeviceNodeCreate):
    db_node = DeviceNode(**node.dict())
    db.add(db_node)
    db.commit()
    db.refresh(db_node)
    return db_node

def update_device_node(db: Session, node_id: int, node: DeviceNodeUpdate):
    db_node = get_device_node(db, node_id)
    if not db_node:
        return None
    
    for key, value in node.dict(exclude_unset=True).items():
        setattr(db_node, key, value)
    
    db.commit()
    db.refresh(db_node)
    return db_node

def delete_device_node(db: Session, node_id: int):
    db_node = get_device_node(db, node_id)
    if not db_node:
        return False
    
    db.delete(db_node)
    db.commit()
    return True

def get_topology_edges(db: Session, topology_id: int):
    return db.query(ConnectionEdge).filter(ConnectionEdge.topology_id == topology_id).all()

def get_connection_edge(db: Session, edge_id: int):
    return db.query(ConnectionEdge).filter(ConnectionEdge.id == edge_id).first()

def create_connection_edge(db: Session, edge: ConnectionEdgeCreate):
    db_edge = ConnectionEdge(**edge.dict())
    db.add(db_edge)
    db.commit()
    db.refresh(db_edge)
    return db_edge

def update_connection_edge(db: Session, edge_id: int, edge: ConnectionEdgeUpdate):
    db_edge = get_connection_edge(db, edge_id)
    if not db_edge:
        return None
    
    for key, value in edge.dict(exclude_unset=True).items():
        setattr(db_edge, key, value)
    
    db.commit()
    db.refresh(db_edge)
    return db_edge

def delete_connection_edge(db: Session, edge_id: int):
    db_edge = get_connection_edge(db, edge_id)
    if not db_edge:
        return False
    
    db.delete(db_edge)
    db.commit()
    return True 