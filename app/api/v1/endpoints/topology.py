from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime

from app.api import deps
from app.core.snmp_poller import SNMPPoller
from app.models.topology import DeviceTopology, InterfaceTopology, NeighborTopology
from app.models.base import Device, Network, DeviceSNMP
from app.schemas.topology import (
    TopologyResponse,
    DeviceTopologyCreate,
    InterfaceTopologyCreate,
    NeighborTopologyCreate
)
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.services.topology_cache import topology_cache
import logging

# Import ping and SNMP check functions
# from app.api.v1.endpoints.devices import ping_device, check_snmp

router = APIRouter(
    tags=["topology"]
)

@router.get("/{network_id}", response_model=TopologyResponse)
async def get_network_topology(
    network_id: int,
    force_refresh: bool = False,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get the network topology for a specific network.
    Now uses agent-discovered data instead of direct SNMP connections.
    """
    user_id = current_user.get('user_id')
    
    # Invalidate cache if force_refresh is requested
    if force_refresh:
        topology_cache.invalidate(network_id, user_id)
        logging.info(f"Force refresh requested - invalidated topology cache for network {network_id}")
    
    # Check cache first
    cached_topology = topology_cache.get(network_id, user_id)
    if cached_topology:
        logging.info(f"Returning cached topology for network {network_id}")
        return cached_topology
    
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get all devices in the network (including agent-discovered ones)
    devices = db.query(Device).filter(Device.network_id == network_id).all()
    if not devices:
        raise HTTPException(status_code=404, detail="No devices found in network")

    # Get topology data for all devices
    nodes = []
    links = []
    processed_connections = set()  # Track which device pairs have already been processed
    
    for device in devices:
        # Use stored device status from agent reports
        ping_status = device.ping_status if device.ping_status is not None else False
        snmp_status = device.snmp_status if device.snmp_status is not None else True  # Default to True if not set
        is_active = device.is_active
        
        logging.info(f"Device {device.name} ({device.ip}) stored status: ping={ping_status}, snmp={snmp_status}, active={is_active}")
        
        nodes.append({
            "id": f"device_{device.id}",
            "label": device.name,
            "type": "device",
            "data": {
                "ip": device.ip,
                "type": device.type,
                "platform": device.platform,
                "ping_status": ping_status,
                "snmp_status": snmp_status,
                "is_active": is_active,
                "discovery_method": device.discovery_method
            }
        })
        
        # Get device topology data (now from agent discoveries)
        device_topology = db.query(DeviceTopology).filter(DeviceTopology.device_id == device.id).first()
        if device_topology:
            # Add neighbor connections
            neighbors = db.query(NeighborTopology).filter(NeighborTopology.device_id == device_topology.id).all()
            for neighbor in neighbors:
                # Find the neighbor device - try exact match first, then try without domain
                neighbor_device = db.query(Device).filter(Device.name == neighbor.neighbor_id).first()
                
                if not neighbor_device:
                    # Try matching without domain suffix (e.g., "PERFECT.test" -> "PERFECT")
                    neighbor_name_clean = neighbor.neighbor_id.split('.')[0] if '.' in neighbor.neighbor_id else neighbor.neighbor_id
                    neighbor_device = db.query(Device).filter(Device.name == neighbor_name_clean).first()
                    logging.info(f"Trying to match neighbor '{neighbor.neighbor_id}' as '{neighbor_name_clean}'")
                
                if neighbor_device:
                    logging.info(f"Found neighbor device: {neighbor_device.name} (ID: {neighbor_device.id}) for neighbor_id: {neighbor.neighbor_id}")
                    
                    # Create a unique key for this device pair to prevent duplicates
                    device_pair = tuple(sorted([device.id, neighbor_device.id]))
                    if device_pair in processed_connections:
                        continue  # Skip if we've already processed this connection
                    
                    processed_connections.add(device_pair)
                    
                    # Get interface info for the local interface
                    local_interface = db.query(InterfaceTopology).filter(
                        InterfaceTopology.device_id == device_topology.id,
                        InterfaceTopology.interface_index == neighbor.local_interface
                    ).first()
                    
                    # Format interface names
                    local_if_name = local_interface.name if local_interface else f"Interface {neighbor.local_interface}"
                    remote_if_name = neighbor.neighbor_port  # Use the neighbor_port directly since it's already the interface name
                    
                    # Clean up interface names
                    local_if_name = local_if_name.replace("GigabitEthernet", "Gi")
                    local_if_name = local_if_name.replace("FastEthernet", "Fa")
                    local_if_name = local_if_name.replace("TenGigabitEthernet", "Te")
                    local_if_name = local_if_name.replace("Ethernet", "Eth")
                    local_if_name = local_if_name.replace("Loopback", "Lo")
                    local_if_name = local_if_name.replace("Vlan", "Vl")
                    local_if_name = local_if_name.replace("Port-channel", "Po")
                    
                    remote_if_name = remote_if_name.replace("GigabitEthernet", "Gi")
                    remote_if_name = remote_if_name.replace("FastEthernet", "Fa")
                    remote_if_name = remote_if_name.replace("TenGigabitEthernet", "Te")
                    remote_if_name = remote_if_name.replace("Ethernet", "Eth")
                    remote_if_name = remote_if_name.replace("Loopback", "Lo")
                    remote_if_name = remote_if_name.replace("Vlan", "Vl")
                    remote_if_name = remote_if_name.replace("Port-channel", "Po")
                    
                    links.append({
                        "source": f"device_{device.id}",
                        "target": f"device_{neighbor_device.id}",
                        "type": "neighbor",
                        "data": {
                            "discovery_protocol": neighbor.discovery_protocol,
                            "local_interface": local_if_name,
                            "remote_interface": remote_if_name
                        }
                    })
                    logging.info(f"Added link between {device.name} ({local_if_name}) and {neighbor_device.name} ({remote_if_name})")
                else:
                    logging.warning(f"Could not find device for neighbor_id: {neighbor.neighbor_id}")

    topology_data = {
        "nodes": nodes,
        "links": links
    }
    
    # Cache the topology data
    topology_cache.set(network_id, user_id, topology_data)
    logging.info(f"Cached topology data for network {network_id}")
    
    return topology_data

@router.post("/{network_id}/discover", response_model=Dict[str, Any])
async def discover_network_topology(
    network_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Discover network topology for a specific network.
    This endpoint now triggers agent-based discovery instead of direct SNMP connections.
    """
    user_id = current_user.get('user_id')
    
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get all devices in the network
    devices = db.query(Device).filter(Device.network_id == network_id).all()
    if not devices:
        raise HTTPException(status_code=404, detail="No devices found in network")

    # Invalidate cache before starting discovery
    topology_cache.invalidate(network_id, user_id)
    logging.info(f"Invalidated topology cache for network {network_id} before discovery")

    # Start background task for agent-based topology discovery
    background_tasks.add_task(
        discover_topology_via_agents,
        network_id=network_id,
        devices=devices,
        db=db,
        user_id=user_id
    )

    return {
        "message": "Agent-based topology discovery started",
        "network_id": network_id,
        "device_count": len(devices),
        "discovery_method": "agent"
    }

@router.post("/{network_id}/device/{device_id}/discover", response_model=Dict[str, Any])
async def discover_device_neighbors(
    network_id: int,
    device_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Discover neighbors for a specific device.
    This endpoint triggers an asynchronous discovery process for a single device.
    """
    user_id = current_user.get('user_id')
    
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get the specific device
    device = db.query(Device).filter(Device.id == device_id, Device.network_id == network_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Invalidate cache before starting discovery
    topology_cache.invalidate(network_id, user_id)
    logging.info(f"Invalidated topology cache for network {network_id} before device discovery")

    # Start background task for device-specific topology discovery
    background_tasks.add_task(
        discover_device_topology,
        network_id=network_id,
        device=device,
        db=db,
        user_id=user_id
    )

    return {
        "message": f"Neighbor discovery started for device {device.name}",
        "network_id": network_id,
        "device_id": device_id,
        "device_name": device.name
    }

async def discover_device_topology(network_id: int, device: Device, db: Session, user_id: int):
    """
    Background task to discover neighbors for a specific device.
    """
    def clean_string(value: str) -> str:
        """Clean string by removing null bytes and other invalid characters."""
        if not value:
            return ""
        # Remove null bytes and other control characters
        return ''.join(char for char in str(value) if ord(char) >= 32)

    try:
        # Get SNMP configuration
        snmp_config = db.query(DeviceSNMP).filter(DeviceSNMP.device_id == device.id).first()
        if not snmp_config:
            logging.warning(f"No SNMP configuration for device {device.name}")
            return
        
        # Initialize SNMP poller with correct version and credentials
        poller = SNMPPoller(
            community=snmp_config.community if snmp_config.snmp_version in ["1", "2c", "v2c"] else None,
            version=snmp_config.snmp_version,
            username=snmp_config.username if snmp_config.snmp_version == "3" else None,
            auth_protocol=snmp_config.auth_protocol if snmp_config.snmp_version == "3" else None,
            auth_password=snmp_config.auth_password if snmp_config.snmp_version == "3" else None,
            priv_protocol=snmp_config.priv_protocol if snmp_config.snmp_version == "3" else None,
            priv_password=snmp_config.priv_password if snmp_config.snmp_version == "3" else None
        )
        
        # Test SNMP connection first
        if not poller.test_connection(device.ip):
            logging.error(f"Failed to establish SNMP connection to device {device.name} ({device.ip})")
            return
        
        # Get device info
        device_info = poller.get_basic_device_info(device.ip)
        if device_info:
            # Update or create device topology
            device_topology = db.query(DeviceTopology).filter(DeviceTopology.device_id == device.id).first()
            if not device_topology:
                device_topology = DeviceTopology(
                    device_id=device.id,
                    network_id=network_id
                )
            
            # Clean and set device info
            device_topology.hostname = clean_string(device_info.get("sysName"))
            sys_descr = clean_string(device_info.get("sysDescr", ""))
            device_topology.vendor = sys_descr.split()[0] if sys_descr else ""  # First word is usually vendor
            device_topology.model = sys_descr.split()[1] if len(sys_descr.split()) > 1 else ""
            device_topology.uptime = int(device_info.get("sysUpTime", "0").split()[0]) if device_info.get("sysUpTime") else 0
            device_topology.last_polled = datetime.utcnow()
            
            db.add(device_topology)
            db.commit()
            
            # Get interface info
            interfaces = poller.get_interfaces(device.ip)
            for interface in interfaces:
                interface_topology = db.query(InterfaceTopology).filter(
                    InterfaceTopology.device_id == device_topology.id,
                    InterfaceTopology.interface_index == interface["ifIndex"]
                ).first()
                
                if not interface_topology:
                    interface_topology = InterfaceTopology(
                        device_id=device_topology.id,
                        interface_index=interface["ifIndex"]
                    )
                
                interface_topology.name = clean_string(interface["ifDescr"])
                interface_topology.description = clean_string(interface.get("ifAlias", ""))
                interface_topology.oper_status = clean_string(interface["ifOperStatus"])
                interface_topology.admin_status = clean_string(interface["ifAdminStatus"])
                interface_topology.speed = interface.get("ifSpeed", "Unknown")
                interface_topology.mac_address = clean_string(interface.get("ifPhysAddress", ""))
                
                db.add(interface_topology)
            
            # Get neighbor information (CDP/LLDP)
            neighbors = poller.get_cdp_neighbors(device.ip)
            logging.info(f"Found {len(neighbors)} CDP neighbors for device {device.name}")
            
            for neighbor in neighbors:
                logging.info(f"Processing neighbor: {neighbor}")
                neighbor_topology = NeighborTopology(
                    device_id=device_topology.id,
                    neighbor_id=clean_string(neighbor["device_id"]),
                    local_interface=neighbor["local_port"],
                    neighbor_port=clean_string(neighbor["remote_port"]),
                    neighbor_platform=clean_string(neighbor.get("platform", "Unknown")),
                    discovery_protocol="cdp"
                )
                db.add(neighbor_topology)
                logging.info(f"Added CDP neighbor for {device.name}: {neighbor['device_id']} on interface {neighbor['local_port']}")
            
            db.commit()
            logging.info(f"Device topology discovery completed for {device.name}")
        else:
            logging.error(f"Failed to get device info for {device.name} ({device.ip})")
    
    except Exception as e:
        logging.error(f"Error during topology discovery for device {device.name}: {str(e)}")
        db.rollback()

async def discover_topology_via_agents(network_id: int, devices: List[Device], db: Session, user_id: int):
    """
    Background task to discover network topology via agents.
    This replaces the direct SNMP approach with agent-based discovery.
    """
    try:
        # Find agents that have access to this network
        from app.models.base import Agent, AgentNetworkAccess
        
        network_agents = db.query(Agent).join(AgentNetworkAccess).filter(
            AgentNetworkAccess.network_id == network_id,
            Agent.status == "online"
        ).all()
        
        if not network_agents:
            logging.warning(f"No online agents found for network {network_id}")
            return
        
        logging.info(f"Found {len(network_agents)} online agents for network {network_id}")
        
        # For now, we'll just log that agent discovery should be triggered
        # The actual discovery will happen when agents call the topology endpoints
        for agent in network_agents:
            logging.info(f"Agent {agent.name} (ID: {agent.id}) should trigger topology discovery for network {network_id}")
            
            # Update agent discovery status
            agent.topology_discovery_status = "discovering"
            agent.last_topology_discovery = datetime.utcnow()
            agent.topology_discovery_progress = 0
            agent.topology_error_message = None
            
            db.add(agent)
        
        db.commit()
        logging.info(f"Updated agent discovery status for network {network_id}")
        
    except Exception as e:
        logging.error(f"Error during agent-based topology discovery for network {network_id}: {str(e)}")
        db.rollback()


async def discover_topology(network_id: int, devices: List[Device], db: Session, user_id: int):
    """
    Legacy direct SNMP discovery function (kept for backward compatibility).
    This is now deprecated in favor of agent-based discovery.
    """
    logging.warning("Direct SNMP discovery is deprecated. Use agent-based discovery instead.")
    
    def clean_string(value: str) -> str:
        """Clean string by removing null bytes and other invalid characters."""
        if not value:
            return ""
        # Remove null bytes and other control characters
        return ''.join(char for char in str(value) if ord(char) >= 32)

    for device in devices:
        try:
            # Get SNMP configuration
            snmp_config = db.query(DeviceSNMP).filter(DeviceSNMP.device_id == device.id).first()
            if not snmp_config:
                logging.warning(f"No SNMP configuration for device {device.name}")
                continue
            
            # Initialize SNMP poller with correct version and credentials
            poller = SNMPPoller(
                community=snmp_config.community if snmp_config.snmp_version in ["1", "2c", "v2c"] else None,
                version=snmp_config.snmp_version,
                username=snmp_config.username if snmp_config.snmp_version == "3" else None,
                auth_protocol=snmp_config.auth_protocol if snmp_config.snmp_version == "3" else None,
                auth_password=snmp_config.auth_password if snmp_config.snmp_version == "3" else None,
                priv_protocol=snmp_config.priv_protocol if snmp_config.snmp_version == "3" else None,
                priv_password=snmp_config.priv_password if snmp_config.snmp_version == "3" else None
            )
            
            # Test SNMP connection first
            if not poller.test_connection(device.ip):
                logging.error(f"Failed to establish SNMP connection to device {device.name} ({device.ip})")
                continue
            
            # Get device info
            device_info = poller.get_basic_device_info(device.ip)
            if device_info:
                # Update or create device topology
                device_topology = db.query(DeviceTopology).filter(DeviceTopology.device_id == device.id).first()
                if not device_topology:
                    device_topology = DeviceTopology(
                        device_id=device.id,
                        network_id=network_id
                    )
                
                # Clean and set device info
                device_topology.hostname = clean_string(device_info.get("sysName"))
                sys_descr = clean_string(device_info.get("sysDescr", ""))
                device_topology.vendor = sys_descr.split()[0] if sys_descr else ""  # First word is usually vendor
                device_topology.model = sys_descr.split()[1] if len(sys_descr.split()) > 1 else ""
                device_topology.uptime = int(device_info.get("sysUpTime", "0").split()[0]) if device_info.get("sysUpTime") else 0
                device_topology.last_polled = datetime.utcnow()
                
                db.add(device_topology)
                db.commit()
                
                # Get interface info
                interfaces = poller.get_interfaces(device.ip)
                for interface in interfaces:
                    interface_topology = db.query(InterfaceTopology).filter(
                        InterfaceTopology.device_id == device_topology.id,
                        InterfaceTopology.interface_index == interface["ifIndex"]
                    ).first()
                    
                    if not interface_topology:
                        interface_topology = InterfaceTopology(
                            device_id=device_topology.id,
                            interface_index=interface["ifIndex"]
                        )
                    
                    # Clean and set interface info
                    interface_topology.name = clean_string(interface["ifDescr"])
                    interface_topology.admin_status = clean_string(interface["ifAdminStatus"])
                    interface_topology.oper_status = clean_string(interface["ifOperStatus"])
                    
                    # Handle speed - convert empty string to None
                    speed = interface["ifSpeed"]
                    interface_topology.speed = None if not speed else int(speed)
                    
                    # Handle MAC address - convert empty string to None
                    mac = interface["ifPhysAddress"]
                    interface_topology.mac_address = None if not mac else clean_string(mac)
                    
                    interface_topology.last_polled = datetime.utcnow()
                    
                    db.add(interface_topology)
                    db.commit()
                
                # Get CDP neighbors
                neighbors = poller.get_cdp_neighbors(device.ip)
                for neighbor in neighbors:
                    try:
                        # Clean the neighbor ID
                        neighbor_id = clean_string(neighbor["device_id"])
                        if not neighbor_id:
                            continue

                        # Get or create neighbor topology
                        neighbor_topology = db.query(NeighborTopology).filter(
                            NeighborTopology.device_id == device_topology.id,
                            NeighborTopology.neighbor_id == neighbor_id
                        ).first()
                        
                        if not neighbor_topology:
                            neighbor_topology = NeighborTopology(
                                device_id=device_topology.id,
                                neighbor_id=neighbor_id
                            )
                        
                        # Clean and set neighbor info
                        neighbor_topology.local_interface = clean_string(neighbor["local_port"])
                        neighbor_topology.neighbor_port = clean_string(neighbor["remote_port"])
                        neighbor_topology.neighbor_platform = clean_string(neighbor.get("platform", "Unknown"))
                        neighbor_topology.discovery_protocol = "cdp"
                        neighbor_topology.last_polled = datetime.utcnow()
                        
                        db.add(neighbor_topology)
                        db.commit()
                        
                        logging.info(f"Added CDP neighbor for {device.name}: {neighbor_id} on interface {neighbor_topology.local_interface}")
                        
                    except Exception as e:
                        logging.error(f"Error processing CDP neighbor for device {device.name}: {str(e)}")
                        continue
                
                # Get device health with device_id for enhanced temperature monitoring
                health_data = poller.get_device_health(device.ip, db, device.id)
                if health_data:
                    # Clean health data values
                    cleaned_health_data = {
                        k: clean_string(str(v)) for k, v in health_data.items()
                    }
                    device_topology.health_data = cleaned_health_data
                    db.commit()
                
                # Log device information for debugging
                logging.info(f"Device {device.name} ({device.ip}) - Type: {device.type}, Platform: {device.platform}")
                logging.info(f"SNMP Config - Version: {snmp_config.snmp_version}, Community: {snmp_config.community}")
                
        except Exception as e:
            logging.error(f"Error discovering topology for device {device.name}: {str(e)}")
            db.rollback()  # Rollback the transaction on error
            continue
    
    # Invalidate cache after discovery is complete to ensure fresh data
    topology_cache.invalidate(network_id, user_id)
    logging.info(f"Topology discovery completed for network {network_id}, cache invalidated")

@router.get("/{network_id}/device/{device_id}/info", response_model=Dict[str, Any])
async def get_device_info(
    network_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed device information from agent-discovered data for a specific device.
    """
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get the device
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.network_id == network_id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        # Get device topology data (already discovered by agents) using the relationship
        device_topology = device.topology
        
        if not device_topology:
            # If no topology data, return basic device info
            return {
                "device_id": device.id,
                "device_name": device.name,
                "device_ip": device.ip,
                "device_type": device.type,
                "device_platform": device.platform,
                "status": "No topology data available",
                "last_updated": datetime.utcnow().isoformat()
            }

        # Return agent-discovered information
        formatted_info = {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "device_type": device.type,
            "device_platform": device.platform,
            "agent_discovered_info": {
                "hostname": device_topology.hostname or "Not available",
                "description": f"{device_topology.vendor or 'Unknown'} {device_topology.model or 'Unknown'}" if device_topology.vendor or device_topology.model else "Not available",
                "vendor": device_topology.vendor or "Not available",
                "model": device_topology.model or "Not available",
                "uptime": device_topology.uptime or "Not available",
                "ping_status": device.ping_status,
                "snmp_status": device.snmp_status,
                "is_active": device.is_active
            },
            "last_updated": device_topology.last_polled.isoformat() if device_topology.last_polled else datetime.utcnow().isoformat()
        }

        return formatted_info

    except Exception as e:
        logging.error(f"Error getting device info for {device.name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device information")

@router.get("/{network_id}/device/{device_id}/interfaces", response_model=Dict[str, Any])
async def get_device_interfaces(
    network_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed interface information from agent-discovered data for a specific device.
    """
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get the device
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.network_id == network_id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    try:
        # Get interface topology data (already discovered by agents)
        interface_topologies = db.query(InterfaceTopology).filter(
            InterfaceTopology.device_id == device.id
        ).all()
        
        if not interface_topologies:
            # If no interface data, return basic device info
            return {
                "device_id": device.id,
                "device_name": device.name,
                "device_ip": device.ip,
                "interfaces": [],
                "interface_count": 0,
                "status": "No interface data available",
                "last_updated": datetime.utcnow().isoformat()
            }

        # Format the response with agent-discovered interface data
        formatted_interfaces = []
        for interface in interface_topologies:
            formatted_interface = {
                "ifIndex": interface.if_index or "Unknown",
                "ifDescr": interface.if_descr or "Unknown",
                "name": interface.if_name or "Unknown",
                "description": interface.if_description or "Not set",
                "ifOperStatus": interface.if_oper_status or "Unknown",
                "ifAdminStatus": interface.if_admin_status or "Unknown",
                "ifSpeed": interface.if_speed or "Unknown",
                "ifPhysAddress": interface.if_phys_address or "Not available",
                "ip": interface.if_ip or "Not configured",
                "status": interface.if_oper_status or "Unknown"
            }
            formatted_interfaces.append(formatted_interface)

        return {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "interfaces": formatted_interfaces,
            "interface_count": len(formatted_interfaces),
            "last_updated": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logging.error(f"Error getting interface info for {device.name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve interface information")

@router.delete("/{network_id}/cache", response_model=Dict[str, Any])
async def clear_network_topology_cache(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Clear the topology cache for a specific network.
    """
    user_id = current_user.get('user_id')
    
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")
    
    # Clear cache for this network and user
    topology_cache.invalidate(network_id, user_id)
    
    return {
        "message": "Topology cache cleared",
        "network_id": network_id,
        "user_id": user_id
    }

@router.get("/cache/stats", response_model=Dict[str, Any])
async def get_cache_statistics(
    current_user: dict = Depends(get_current_user)
):
    """
    Get topology cache statistics.
    """
    stats = topology_cache.get_stats()
    
    return {
        "cache_statistics": stats,
        "message": "Cache statistics retrieved successfully"
    }

@router.delete("/cache/clear", response_model=Dict[str, Any])
async def clear_all_topology_cache(
    current_user: dict = Depends(get_current_user)
):
    """
    Clear all topology cache entries.
    """
    topology_cache.clear()
    
    return {
        "message": "All topology cache cleared successfully"
    }

@router.post("/cache/cleanup", response_model=Dict[str, Any])
async def cleanup_expired_cache(
    current_user: dict = Depends(get_current_user)
):
    """
    Clean up expired cache entries.
    """
    topology_cache.cleanup_expired()
    
    return {
        "message": "Expired cache entries cleaned up successfully"
    }

@router.get("/{network_id}/device/{device_id}/health", response_model=Dict[str, Any])
async def get_device_health(
    network_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get detailed system health information including CPU, memory, and temperature for a specific device.
    """
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get the device
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.network_id == network_id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get SNMP configuration
    snmp_config = db.query(DeviceSNMP).filter(DeviceSNMP.device_id == device.id).first()
    if not snmp_config:
        raise HTTPException(status_code=404, detail="SNMP configuration not found for device")

    try:
        # Initialize SNMP poller
        poller = SNMPPoller(
            community=snmp_config.community if snmp_config.snmp_version in ["1", "2c", "v2c"] else None,
            version=snmp_config.snmp_version,
            username=snmp_config.username if snmp_config.snmp_version == "3" else None,
            auth_protocol=snmp_config.auth_protocol if snmp_config.snmp_version == "3" else None,
            auth_password=snmp_config.auth_password if snmp_config.snmp_version == "3" else None,
            priv_protocol=snmp_config.priv_protocol if snmp_config.snmp_version == "3" else None,
            priv_password=snmp_config.priv_password if snmp_config.snmp_version == "3" else None
        )

        # Test SNMP connection
        if not poller.test_connection(device.ip):
            raise HTTPException(status_code=503, detail="SNMP connection failed")

        # Log device information for debugging
        logging.info(f"Device {device.name} ({device.ip}) - Type: {device.type}, Platform: {device.platform}")
        logging.info(f"SNMP Config - Version: {snmp_config.snmp_version}, Community: {snmp_config.community}")

        # Get device health metrics with device_id for enhanced temperature monitoring
        health_data = poller.get_device_health(device.ip, db, device.id)
        
        # Debug logging to see what health_data contains
        logging.info(f"Raw health_data keys: {list(health_data.keys())}")
        logging.info(f"Raw health_data memory fields: memory_usage={health_data.get('memory_usage')}, memory_used_gb={health_data.get('memory_used_gb')}, memory_free_gb={health_data.get('memory_free_gb')}, memory_total_gb={health_data.get('memory_total_gb')}")
        logging.info(f"Raw health_data type: {type(health_data)}")
        logging.info(f"Raw health_data content: {health_data}")
        
        # Helper function to safely convert SNMP values to integers
        def safe_int_convert(value, default=0):
            try:
                if isinstance(value, str):
                    # Remove any non-numeric characters except decimal points
                    cleaned = ''.join(c for c in value if c.isdigit() or c == '.')
                    if cleaned:
                        return int(float(cleaned))
                    return default
                elif isinstance(value, (int, float)):
                    return int(value)
                else:
                    return default
            except (ValueError, TypeError):
                return default
        
        # Extract CPU percentage from discovered data
        cpu_usage_percent = 0
        cpu_data = health_data.get("cpu_details", {})
        
        if cpu_data:
            # Find the best CPU percentage from discovered data
            best_cpu_percent = 0
            for cpu_name, cpu_value in cpu_data.items():
                try:
                    if isinstance(cpu_value, str):
                        # Extract numeric value from string (e.g., "25%" -> 25)
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', cpu_value)
                        if match:
                            numeric_cpu = float(match.group(1))
                            if numeric_cpu > best_cpu_percent:
                                best_cpu_percent = numeric_cpu
                    elif isinstance(cpu_value, (int, float)):
                        if cpu_value > best_cpu_percent:
                            best_cpu_percent = float(cpu_value)
                except (ValueError, TypeError):
                    continue
            
            cpu_usage_percent = best_cpu_percent
        else:
            # Try to extract from processed cpu_usage field
            cpu_usage_str = health_data.get("cpu_usage", "0%")
            try:
                import re
                match = re.search(r'(\d+(?:\.\d+)?)', cpu_usage_str)
                if match:
                    cpu_usage_percent = float(match.group(1))
            except (ValueError, TypeError):
                cpu_usage_percent = 0

        # Extract memory usage and GB values from health_data
        memory_usage_percent = health_data.get("memory_usage", 0)
        memory_used_gb = health_data.get("memory_used_gb", 0)
        memory_free_gb = health_data.get("memory_free_gb", 0)
        memory_total_gb = health_data.get("memory_total_gb", 0)
        
        # Debug logging to see what values we're getting
        logging.info(f"API extracted memory values - usage: {memory_usage_percent}%, used: {memory_used_gb}GB, free: {memory_free_gb}GB, total: {memory_total_gb}GB")

        # Extract temperature from discovered data
        temperature_value = 0
        temperature_data = health_data.get("temperature_details", {})
        
        if temperature_data:
            # Find the best temperature from discovered data
            best_temp = 0
            for temp_name, temp_value in temperature_data.items():
                try:
                    if isinstance(temp_value, str):
                        # Extract numeric value from string (e.g., "43°C" -> 43)
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', temp_value)
                        if match:
                            numeric_temp = float(match.group(1))
                            if numeric_temp > best_temp:
                                best_temp = numeric_temp
                    elif isinstance(temp_value, (int, float)):
                        if temp_value > best_temp:
                            best_temp = float(temp_value)
                except (ValueError, TypeError):
                    continue
            
            temperature_value = best_temp
        else:
            # Try to extract from processed temperature field
            temperature_str = health_data.get("temperature", "0°C")
            try:
                import re
                match = re.search(r'(\d+(?:\.\d+)?)', temperature_str)
                if match:
                    temperature_value = float(match.group(1))
            except (ValueError, TypeError):
                temperature_value = 0

        # Extract power consumption and status from discovered data
        power_consumption = 0
        power_status = "unknown"
        power_data = health_data.get("power_details", {})
        
        if power_data:
            # Find the best power value and status from discovered data
            best_power = 0
            best_status = "unknown"
            for power_name, power_value in power_data.items():
                try:
                    if isinstance(power_value, dict):
                        # Enhanced PSU data structure
                        power_consumption_str = power_value.get("power_consumption", "0W")
                        psu_status = power_value.get("status", "unknown")
                        
                        if isinstance(power_consumption_str, str):
                            # Extract numeric value from string (e.g., "715W" -> 715)
                            import re
                            match = re.search(r'(\d+(?:\.\d+)?)', power_consumption_str)
                            if match:
                                numeric_power = float(match.group(1))
                                if numeric_power > best_power:
                                    best_power = numeric_power
                                    best_status = psu_status
                    elif isinstance(power_value, str):
                        # Extract numeric value from string
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', power_value)
                        if match:
                            numeric_power = float(match.group(1))
                            if numeric_power > best_power:
                                best_power = numeric_power
                    elif isinstance(power_value, (int, float)):
                        if power_value > best_power:
                            best_power = float(power_value)
                except (ValueError, TypeError):
                    continue
            
            power_consumption = best_power
            power_status = best_status
        else:
            # Try to extract from processed power_consumption field
            power_consumption = health_data.get("power_consumption", 0)

        # Extract fan speed from discovered data
        fan_speed = 0
        fan_data = health_data.get("fan_details", {})
        
        if fan_data:
            # Find the best fan speed from discovered data
            best_fan = 0
            for fan_name, fan_value in fan_data.items():
                try:
                    if isinstance(fan_value, str):
                        # Extract numeric value from string
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', fan_value)
                        if match:
                            numeric_fan = float(match.group(1))
                            if numeric_fan > best_fan:
                                best_fan = numeric_fan
                    elif isinstance(fan_value, (int, float)):
                        if fan_value > best_fan:
                            best_fan = float(fan_value)
                except (ValueError, TypeError):
                    continue
            
            fan_speed = best_fan
        else:
            # Try to extract from processed fan_speed field
            fan_speed = health_data.get("fan_speed", 0)
        
        # Extract power status from discovered data
        power_status = 'unknown'
        power_data = health_data.get("power_details", {})
        
        if power_data:
            # Try to get the first PSU status if available
            for power_value in power_data.values():
                if isinstance(power_value, dict) and power_value.get("status"):
                    power_status = power_value["status"]
                    break
                elif isinstance(power_value, dict) and power_value.get("overall_status"):
                    power_status = power_value["overall_status"]
                    break
                elif isinstance(power_value, str):
                    power_status = power_value
                    break
        
        formatted_health = {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "device_type": device.type,
            "device_platform": device.platform,
            "health_metrics": {
                "cpu_load": {
                    "value": cpu_usage_percent,
                    "unit": "%",
                    "description": "CPU 5-minute average load",
                    "status": "normal" if cpu_usage_percent < 80 else "warning" if cpu_usage_percent < 95 else "critical"
                },
                "memory_used_percent": {
                    "value": memory_usage_percent,
                    "unit": "%",
                    "description": "Memory utilization percentage",
                    "status": "normal" if memory_usage_percent < 80 else "warning" if memory_usage_percent < 95 else "critical"
                },
                "memory_used_gb": {
                    "value": memory_used_gb,
                    "unit": "GB",
                    "description": "Used memory in GB",
                    "status": "normal"
                },
                "memory_free_gb": {
                    "value": memory_free_gb,
                    "unit": "GB",
                    "description": "Free memory in GB",
                    "status": "normal"
                },
                "memory_total_gb": {
                    "value": memory_total_gb,
                    "unit": "GB",
                    "description": "Total memory in GB",
                    "status": "normal"
                },
                "temperature": {
                    "value": temperature_value,
                    "unit": "°C",
                    "description": "Device temperature",
                    "status": "normal" if temperature_value < 60 else "warning" if temperature_value < 80 else "critical"
                },
                "power_consumption": {
                    "value": power_consumption,
                    "unit": "W",
                    "description": "Power status monitoring",
                    "status": "normal" if str(power_status).strip().upper() in ["OK", "GOOD", "NORMAL"] else "critical",
                    "status_text": power_status
                },
                "fan_speed": {
                    "value": fan_speed,
                    "unit": "RPM",
                    "description": "Fan speed",
                    "status": "normal" if fan_speed > 0 else "unknown"
                }
            },
            "calculated_metrics": {}
        }
        
        # Add detailed temperature information if available
        if health_data.get("temperature_details"):
            temp_data = health_data.get("temperature_details", {})
            formatted_health["temperature_details"] = {
                "inlet_temperature": {
                    "value": safe_int_convert(temp_data.get("inlet_temp", 0)),
                    "unit": "°C",
                    "description": "Inlet Temperature"
                },
                "hotspot_temperature": {
                    "value": safe_int_convert(temp_data.get("hotspot_temp", 0)),
                    "unit": "°C",
                    "description": "Hotspot Temperature"
                },
                "system_temperature": {
                    "value": 0,  # System temperature not available as numeric value
                    "unit": "°C",
                    "description": f"System Status: {temp_data.get('system_status', 'Unknown')}"
                },
                "yellow_threshold": {
                    "value": safe_int_convert(temp_data.get("threshold_yellow", 0)),
                    "unit": "°C",
                    "description": "Yellow Threshold"
                },
                "red_threshold": {
                    "value": safe_int_convert(temp_data.get("threshold_red", 0)),
                    "unit": "°C",
                    "description": "Red Threshold"
                },
                "temperature_status": {
                    "value": temp_data.get("temp_status", "Unknown"),
                    "unit": "",
                    "description": "Temperature Status"
                }
            }

        # Add detailed power information if available
        if health_data.get("power_details"):
            power_data = health_data.get("power_details", {})
            formatted_health["power_details"] = {}
            
            # Check if we have PSU information (enhanced power monitoring)
            if any(isinstance(value, dict) for value in power_data.values()):
                # Enhanced PSU data structure
                for psu_name, psu_info in power_data.items():
                    if isinstance(psu_info, dict):
                        # PSU information with model, serial, capacity, status
                        formatted_health["power_details"][psu_name] = {
                            "model": psu_info.get("model", "Unknown"),
                            "serial": psu_info.get("serial", "Unknown"),
                            "capacity": psu_info.get("capacity", "Unknown"),
                            "status": psu_info.get("status", "Unknown"),
                            "power_consumption": psu_info.get("power_consumption", "Unknown"),
                            "voltage": psu_info.get("voltage", "Unknown"),
                            "type": "PSU"
                        }
                    else:
                        # Fallback for simple power values
                        formatted_health["power_details"][psu_name] = {
                            "value": safe_int_convert(psu_info),
                            "unit": "W",
                            "description": f"Power sensor: {psu_name}",
                            "type": "sensor"
                        }
            else:
                # Legacy power sensor data
                for power_name, power_value in power_data.items():
                    formatted_health["power_details"][power_name] = {
                        "value": safe_int_convert(power_value),
                        "unit": "W",
                        "description": f"Power sensor: {power_name}",
                        "type": "sensor"
                    }

        # Add detailed fan information if available
        if health_data.get("fan_details"):
            fan_data = health_data.get("fan_details", {})
            formatted_health["fan_details"] = {}
            for fan_name, fan_value in fan_data.items():
                formatted_health["fan_details"][fan_name] = {
                    "value": safe_int_convert(fan_value),
                    "unit": "RPM",
                    "description": f"Fan sensor: {fan_name}"
                }

        # Calculate additional metrics using the new memory fields
        memory_usage_percent = health_data.get("memory_usage", 0)
        memory_used_gb = health_data.get("memory_used_gb", 0)
        memory_free_gb = health_data.get("memory_free_gb", 0)
        memory_total_gb = health_data.get("memory_total_gb", 0)
        
        # Calculate memory percentage from GB values if not already calculated
        if memory_usage_percent == 0 and memory_total_gb > 0 and memory_used_gb > 0:
            memory_usage_percent = (memory_used_gb / memory_total_gb) * 100
        
        # Add memory metrics to calculated_metrics
        if memory_usage_percent > 0 or memory_used_gb > 0:
            formatted_health["calculated_metrics"]["memory_usage_percent"] = {
                "value": round(memory_usage_percent, 2),
                "unit": "%",
                "description": "Memory usage percentage",
                "status": "normal" if memory_usage_percent < 80 else "warning" if memory_usage_percent < 95 else "critical"
            }
        
        if memory_used_gb > 0:
            formatted_health["calculated_metrics"]["memory_used_gb"] = {
                "value": round(memory_used_gb, 2),
                "unit": "GB",
                "description": "Used memory in GB",
                "status": "normal"
            }
        
        if memory_free_gb > 0:
            formatted_health["calculated_metrics"]["memory_free_gb"] = {
                "value": round(memory_free_gb, 2),
                "unit": "GB",
                "description": "Free memory in GB",
                "status": "normal"
            }
        
        if memory_total_gb > 0:
            formatted_health["calculated_metrics"]["memory_total_gb"] = {
                "value": round(memory_total_gb, 2),
                "unit": "GB",
                "description": "Total memory in GB",
                "status": "normal"
            }
        
        # Add overall health status
        critical_count = sum(1 for metric in formatted_health["health_metrics"].values() if metric["status"] == "critical")
        warning_count = sum(1 for metric in formatted_health["health_metrics"].values() if metric["status"] == "warning")
        
        if critical_count > 0:
            formatted_health["overall_status"] = "critical"
        elif warning_count > 0:
            formatted_health["overall_status"] = "warning"
        else:
            formatted_health["overall_status"] = "normal"
        
        formatted_health["last_updated"] = datetime.utcnow().isoformat()
        
        # Add debug information
        logging.info(f"Health data for {device.name}: CPU={cpu_usage_percent:.1f}%, Memory={memory_usage_percent:.1f}%, Temperature={temperature_value}°C, Power={power_consumption}W, Fan={fan_speed}RPM")
        if health_data.get("cpu_details"):
            logging.info(f"CPU details for {device.name}: {health_data.get('cpu_details')}")
        if health_data.get("memory_details"):
            logging.info(f"Memory details for {device.name}: {health_data.get('memory_details')}")
        if health_data.get("temperature_details"):
            logging.info(f"Temperature details for {device.name}: {health_data.get('temperature_details')}")
        if health_data.get("power_details"):
            logging.info(f"Power details for {device.name}: {health_data.get('power_details')}")
        if health_data.get("fan_details"):
            logging.info(f"Fan details for {device.name}: {health_data.get('fan_details')}")
        
        return formatted_health

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error getting device health for {device.name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device health information")

@router.get("/{network_id}/device/{device_id}/snmp-discovery", response_model=Dict[str, Any])
async def discover_device_snmp_oids(
    network_id: int,
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Discover available SNMP OIDs on a device to help identify available sensors.
    """
    # Verify network exists and user has access
    network = db.query(Network).filter(Network.id == network_id).first()
    if not network:
        raise HTTPException(status_code=404, detail="Network not found")

    # Get the device
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.network_id == network_id
    ).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Get SNMP configuration
    snmp_config = db.query(DeviceSNMP).filter(DeviceSNMP.device_id == device.id).first()
    if not snmp_config:
        raise HTTPException(status_code=404, detail="SNMP configuration not found for device")

    try:
        # Initialize SNMP poller
        poller = SNMPPoller(
            community=snmp_config.community if snmp_config.snmp_version in ["1", "2c", "v2c"] else None,
            version=snmp_config.snmp_version,
            username=snmp_config.username if snmp_config.snmp_version == "3" else None,
            auth_protocol=snmp_config.auth_protocol if snmp_config.snmp_version == "3" else None,
            auth_password=snmp_config.auth_password if snmp_config.snmp_version == "3" else None,
            priv_protocol=snmp_config.priv_protocol if snmp_config.snmp_version == "3" else None,
            priv_password=snmp_config.priv_password if snmp_config.snmp_version == "3" else None
        )

        # Test SNMP connection
        if not poller.test_connection(device.ip):
            raise HTTPException(status_code=503, detail="SNMP connection failed")

        # Get basic device info
        device_info = poller.get_basic_device_info(device.ip)
        
        # Try to discover available MIBs
        available_mibs = poller.discover_available_mibs(device.ip)
        
        return {
            "device_id": device.id,
            "device_name": device.name,
            "device_ip": device.ip,
            "device_type": device.type,
            "device_platform": device.platform,
            "snmp_config": {
                "version": snmp_config.snmp_version,
                "community": snmp_config.community if snmp_config.snmp_version in ["1", "2c", "v2c"] else None
            },
            "device_info": device_info,
            "available_mibs": available_mibs,
            "discovery_time": datetime.utcnow().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error discovering SNMP OIDs for {device.name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to discover SNMP OIDs")

@router.get("/learning/statistics", response_model=Dict[str, Any])
async def get_learning_statistics(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Get statistics about the adaptive learning system.
    """
    try:
        from app.services.adaptive_learning import AdaptiveLearningEngine
        
        # Initialize learning engine
        learning_engine = AdaptiveLearningEngine(db)
        
        # Get learning statistics
        stats = learning_engine.get_learning_statistics()
        
        return {
            "status": "success",
            "statistics": stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error getting learning statistics: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to retrieve learning statistics")

@router.post("/learning/config", response_model=Dict[str, Any])
async def update_learning_config(
    config: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Update adaptive learning configuration.
    """
    try:
        from app.models.learning import AdaptiveLearningConfig
        
        # Update or create configuration
        for key, value in config.items():
            config_record = db.query(AdaptiveLearningConfig).filter(
                AdaptiveLearningConfig.config_key == key
            ).first()
            
            if config_record:
                config_record.config_value = value
                config_record.last_updated = datetime.utcnow()
            else:
                config_record = AdaptiveLearningConfig(
                    config_key=key,
                    config_value=value,
                    description=f"Configuration for {key}",
                    last_updated=datetime.utcnow()
                )
                db.add(config_record)
        
        db.commit()
        
        return {
            "status": "success",
            "message": "Learning configuration updated successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error updating learning config: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update learning configuration")

@router.delete("/learning/clear", response_model=Dict[str, Any])
async def clear_learning_data(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """
    Clear all learning data (patterns, strategies, history).
    """
    try:
        from app.models.learning import (
            LearnedPatterns, DiscoveryStrategies, DeviceCapabilities, 
            DiscoveryHistory, AdaptiveLearningConfig
        )
        
        # Clear all learning tables
        db.query(LearnedPatterns).delete()
        db.query(DiscoveryStrategies).delete()
        db.query(DeviceCapabilities).delete()
        db.query(DiscoveryHistory).delete()
        # Don't clear AdaptiveLearningConfig as it contains system settings
        
        db.commit()
        
        return {
            "status": "success",
            "message": "All learning data cleared successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logging.error(f"Error clearing learning data: {str(e)}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to clear learning data")

@router.get("/health-cache/info", response_model=Dict[str, Any])
async def get_health_cache_info(
    current_user: dict = Depends(get_current_user)
):
    """
    Get information about the health cache status.
    """
    try:
        # Create a temporary SNMP poller to access cache info
        snmp_poller = SNMPPoller()
        cache_info = snmp_poller.get_cache_info()
        
        return {
            "status": "success",
            "cache_info": cache_info,
            "message": "Health cache information retrieved successfully"
        }
    except Exception as e:
        logging.error(f"Error getting health cache info: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving cache info: {str(e)}")

@router.delete("/health-cache/clear", response_model=Dict[str, Any])
async def clear_health_cache(
    host: str = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Clear the health cache for a specific host or all hosts.
    """
    try:
        # Create a temporary SNMP poller to access cache methods
        snmp_poller = SNMPPoller()
        snmp_poller.clear_health_cache(host)
        
        message = f"Cleared health cache for {host}" if host else "Cleared all health cache"
        
        return {
            "status": "success",
            "message": message
        }
    except Exception as e:
        logging.error(f"Error clearing health cache: {e}")
        raise HTTPException(status_code=500, detail=f"Error clearing cache: {str(e)}")

@router.post("/health-cache/cleanup", response_model=Dict[str, Any])
async def cleanup_health_cache(
    current_user: dict = Depends(get_current_user)
):
    """
    Clean up expired health cache entries.
    """
    try:
        # Create a temporary SNMP poller to access cache methods
        snmp_poller = SNMPPoller()
        snmp_poller.cleanup_expired_cache()
        
        return {
            "status": "success",
            "message": "Health cache cleanup completed"
        }
    except Exception as e:
        logging.error(f"Error cleaning up health cache: {e}")
        raise HTTPException(status_code=500, detail=f"Error cleaning up cache: {str(e)}") 