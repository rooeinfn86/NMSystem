from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from datetime import datetime
import logging
from app.models.base import Agent, Device, Network, DeviceSNMP, AgentNetworkAccess
from app.models.interface import Interface
from app.models.topology import DeviceTopology, InterfaceTopology, NeighborTopology
from app.schemas.agent_topology import (
    AgentTopologyUpdate,
    AgentDeviceDiscovery,
    AgentInterfaceDiscovery,
    AgentNeighborDiscovery,
    AgentTopologyDiscoveryStatus
)

logger = logging.getLogger(__name__)

class AgentTopologyDiscoveryService:
    """Service for managing agent-based topology discovery."""
    
    def __init__(self, db: Session):
        self.db = db
    
    def start_discovery(self, agent_id: int, network_id: int, discovery_type: str = "full") -> bool:
        """Start topology discovery on an agent."""
        try:
            # Verify agent exists and has access to the network
            agent = self.db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                logger.error(f"Agent {agent_id} not found")
                return False
            
            # Check if agent has access to the network
            network_access = self.db.query(AgentNetworkAccess).filter(
                AgentNetworkAccess.agent_id == agent_id,
                AgentNetworkAccess.network_id == network_id
            ).first()
            
            if not network_access:
                logger.error(f"Agent {agent_id} does not have access to network {network_id}")
                return False
            
            # Update agent discovery status
            agent.topology_discovery_status = "discovering"
            agent.last_topology_discovery = datetime.utcnow()
            agent.topology_discovery_progress = 0
            agent.topology_error_message = None
            agent.topology_discovery_config = {
                "discovery_type": discovery_type,
                "start_time": datetime.utcnow().isoformat(),
                "network_id": network_id
            }
            
            self.db.commit()
            logger.info(f"Started topology discovery for agent {agent_id} on network {network_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error starting topology discovery: {str(e)}")
            self.db.rollback()
            return False
    
    def update_discovery_progress(self, agent_id: int, progress: int, discovered_devices: int = 0) -> bool:
        """Update discovery progress for an agent."""
        try:
            agent = self.db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                return False
            
            agent.topology_discovery_progress = progress
            agent.discovered_devices_count = discovered_devices
            agent.topology_last_updated = datetime.utcnow()
            
            self.db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error updating discovery progress: {str(e)}")
            self.db.rollback()
            return False
    
    def complete_discovery(self, agent_id: int, topology_data: AgentTopologyUpdate) -> bool:
        """Complete topology discovery and store results."""
        try:
            agent = self.db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                logger.error(f"Agent {agent_id} not found")
                return False
            
            # Update agent status
            agent.topology_discovery_status = "completed"
            agent.topology_discovery_progress = 100
            agent.discovered_devices_count = len(topology_data.devices)
            agent.topology_last_updated = datetime.utcnow()
            agent.topology_discovery_config = {
                **agent.topology_discovery_config,
                "end_time": datetime.utcnow().isoformat(),
                "discovered_devices": len(topology_data.devices),
                "discovered_connections": len(topology_data.neighbors)
            }
            
            # Store discovered devices
            self._store_discovered_devices(topology_data, agent)
            
            # Store discovered interfaces
            self._store_discovered_interfaces(topology_data, agent)
            
            # Store discovered neighbors
            self._store_discovered_neighbors(topology_data, agent)
            
            self.db.commit()
            logger.info(f"Completed topology discovery for agent {agent_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error completing topology discovery: {str(e)}")
            self.db.rollback()
            return False
    
    def fail_discovery(self, agent_id: int, error_message: str) -> bool:
        """Mark discovery as failed."""
        try:
            agent = self.db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                return False
            
            agent.topology_discovery_status = "failed"
            agent.topology_error_message = error_message
            agent.topology_last_updated = datetime.utcnow()
            
            self.db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Error marking discovery as failed: {str(e)}")
            self.db.rollback()
            return False
    
    def get_discovery_status(self, agent_id: int) -> Optional[AgentTopologyDiscoveryStatus]:
        """Get current discovery status for an agent."""
        try:
            agent = self.db.query(Agent).filter(Agent.id == agent_id).first()
            if not agent:
                return None
            
            return AgentTopologyDiscoveryStatus(
                agent_id=agent.id,
                network_id=agent.topology_discovery_config.get("network_id") if agent.topology_discovery_config else None,
                status=agent.topology_discovery_status,
                progress=agent.topology_discovery_progress,
                discovered_devices=agent.discovered_devices_count,
                discovered_connections=agent.topology_discovery_config.get("discovered_connections", 0) if agent.topology_discovery_config else 0,
                start_time=agent.last_topology_discovery,
                end_time=datetime.fromisoformat(agent.topology_discovery_config["end_time"]) if agent.topology_discovery_config and "end_time" in agent.topology_discovery_config else None,
                error_message=agent.topology_error_message,
                last_updated=agent.topology_last_updated or datetime.utcnow()
            )
            
        except Exception as e:
            logger.error(f"Error getting discovery status: {str(e)}")
            return None
    
    def _store_discovered_devices(self, topology_data: AgentTopologyUpdate, agent: Agent):
        """Store discovered devices in the database."""
        for device_data in topology_data.devices:
            # Check if device already exists
            existing_device = self.db.query(Device).filter(Device.ip == device_data.ip_address).first()
            
            if existing_device:
                # Update existing device
                existing_device.name = device_data.hostname
                existing_device.type = device_data.device_type
                existing_device.platform = device_data.platform
                existing_device.os_version = device_data.os_version
                existing_device.serial_number = device_data.serial_number
                existing_device.ping_status = device_data.ping_status
                existing_device.snmp_status = device_data.snmp_status
                existing_device.updated_at = datetime.utcnow()
            else:
                # Create new device
                new_device = Device(
                    name=device_data.hostname,
                    ip=device_data.ip_address,
                    type=device_data.device_type,
                    platform=device_data.platform,
                    os_version=device_data.os_version,
                    serial_number=device_data.serial_number,
                    ping_status=device_data.ping_status,
                    snmp_status=device_data.snmp_status,
                    network_id=topology_data.network_id,
                    company_id=topology_data.agent.company_id,
                    organization_id=topology_data.agent.organization_id,
                    discovery_method="auto",
                    is_active=True
                )
                self.db.add(new_device)
    
    def _store_discovered_interfaces(self, topology_data: AgentTopologyUpdate, agent: Agent):
        """Store discovered interfaces in the database."""
        for interface_data in topology_data.interfaces:
            # Find the device
            device = self.db.query(Device).filter(Device.ip == interface_data.local_device_ip).first()
            if not device:
                continue
            
            # Check if interface already exists
            existing_interface = self.db.query(Interface).filter(
                Interface.device_id == device.id,
                Interface.name == interface_data.interface_name
            ).first()
            
            if existing_interface:
                # Update existing interface
                existing_interface.description = interface_data.interface_description
                existing_interface.operational_status = interface_data.operational_status
                existing_interface.administrative_status = interface_data.administrative_status
                existing_interface.speed = interface_data.speed
                existing_interface.mac_address = interface_data.mac_address
                existing_interface.updated_at = datetime.utcnow()
            else:
                # Create new interface
                new_interface = Interface(
                    device_id=device.id,
                    name=interface_data.interface_name,
                    description=interface_data.interface_description,
                    operational_status=interface_data.operational_status,
                    administrative_status=interface_data.administrative_status,
                    speed=interface_data.speed,
                    mac_address=interface_data.mac_address,
                    ip_address=interface_data.ip_address,
                    vlan=interface_data.vlan
                )
                self.db.add(new_interface)
    
    def _store_discovered_neighbors(self, topology_data: AgentTopologyUpdate, agent: Agent):
        """Store discovered neighbors in the database."""
        for neighbor_data in topology_data.neighbors:
            # Find the local device
            local_device = self.db.query(Device).filter(Device.ip == neighbor_data.local_device_ip).first()
            if not local_device:
                continue
            
            # Find or create the neighbor device
            neighbor_device = self.db.query(Device).filter(Device.ip == neighbor_data.neighbor_device_ip).first()
            if not neighbor_device:
                # Create neighbor device if it doesn't exist
                neighbor_device = Device(
                    name=neighbor_data.neighbor_hostname,
                    ip=neighbor_data.neighbor_device_ip,
                    type="unknown",
                    platform=neighbor_data.neighbor_platform or "unknown",
                    network_id=topology_data.network_id,
                    company_id=topology_data.agent.company_id,
                    organization_id=topology_data.agent.organization_id,
                    discovery_method="auto",
                    is_active=True
                )
                self.db.add(neighbor_device)
                self.db.flush()  # Get the ID
            
            # Store neighbor relationship
            neighbor_topology = NeighborTopology(
                device_id=local_device.id,
                neighbor_id=neighbor_device.id,
                local_interface=neighbor_data.local_interface,
                neighbor_port=neighbor_data.neighbor_interface,
                neighbor_platform=neighbor_data.neighbor_platform,
                discovery_protocol=neighbor_data.discovery_protocol
            )
            self.db.add(neighbor_topology)
    
    def get_agent_topology_data(self, agent_id: int, network_id: int) -> Optional[Dict[str, Any]]:
        """Get topology data discovered by an agent."""
        try:
            # Get the agent's discovery status
            status = self.get_discovery_status(agent_id)
            if not status or status.status != "completed":
                return None
            
            # Get devices discovered by this agent
            devices = self.db.query(Device).filter(
                Device.network_id == network_id,
                Device.discovery_method == "auto"
            ).all()
            
            # Get interfaces for these devices
            interfaces = self.db.query(Interface).join(Device).filter(
                Device.network_id == network_id,
                Device.discovery_method == "auto"
            ).all()
            
            # Get neighbor relationships
            neighbors = self.db.query(NeighborTopology).join(Device).filter(
                Device.network_id == network_id,
                Device.discovery_method == "auto"
            ).all()
            
            return {
                "devices": [self._device_to_dict(device) for device in devices],
                "interfaces": [self._interface_to_dict(interface) for interface in interfaces],
                "neighbors": [self._neighbor_to_dict(neighbor) for neighbor in neighbors],
                "discovery_status": status.dict(),
                "last_updated": status.last_updated
            }
            
        except Exception as e:
            logger.error(f"Error getting agent topology data: {str(e)}")
            return None
    
    def _device_to_dict(self, device: Device) -> Dict[str, Any]:
        """Convert device model to dictionary."""
        return {
            "id": device.id,
            "name": device.name,
            "ip": device.ip,
            "type": device.type,
            "platform": device.platform,
            "os_version": device.os_version,
            "serial_number": device.serial_number,
            "ping_status": device.ping_status,
            "snmp_status": device.snmp_status,
            "is_active": device.is_active,
            "discovery_method": device.discovery_method,
            "created_at": device.created_at,
            "updated_at": device.updated_at
        }
    
    def _interface_to_dict(self, interface: Interface) -> Dict[str, Any]:
        """Convert interface model to dictionary."""
        return {
            "id": interface.id,
            "device_id": interface.device_id,
            "name": interface.name,
            "description": interface.description,
            "operational_status": interface.operational_status,
            "administrative_status": interface.administrative_status,
            "speed": interface.speed,
            "mac_address": interface.mac_address,
            "ip_address": interface.ip_address,
            "vlan": interface.vlan,
            "created_at": interface.created_at,
            "updated_at": interface.updated_at
        }
    
    def _neighbor_to_dict(self, neighbor: NeighborTopology) -> Dict[str, Any]:
        """Convert neighbor topology model to dictionary."""
        return {
            "id": neighbor.id,
            "device_id": neighbor.device_id,
            "neighbor_id": neighbor.neighbor_id,
            "local_interface": neighbor.local_interface,
            "neighbor_port": neighbor.neighbor_port,
            "neighbor_platform": neighbor.neighbor_platform,
            "discovery_protocol": neighbor.discovery_protocol,
            "created_at": neighbor.created_at
        } 