from fastapi import APIRouter, Depends, HTTPException, Query, Body, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.base import Device, UserOrganizationAccess, UserNetworkAccess, User, Network, Organization, DeviceLog, LogType, DeviceSNMP as DeviceSNMPModel
from app.schemas.base import DeviceCreate, Device as DeviceSchema, DeviceLogCreate, DeviceLog as DeviceLogSchema, DeviceSNMPCreate, DeviceSNMP as DeviceSNMPSchema
from typing import List, Optional, Dict, Union, Any
from datetime import datetime, timedelta
import subprocess
import asyncio
from concurrent.futures import ThreadPoolExecutor
import platform
import netmiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetMikoAuthenticationException as AuthenticationException, NetMikoTimeoutException
import ipaddress
import concurrent.futures
from pydantic import BaseModel, Field
import re
from enum import Enum
import socket
from functools import partial
from sqlalchemy import insert
import json
from app.services.ssh_engine.ssh_connector import is_ssh_reachable
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd
)
import time

class DeviceSNMP(BaseModel):
    snmp_version: str = 'v2c'
    community: str = 'public'
    username: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None
    priv_password: Optional[str] = None
    port: int = 161

# Update the LogType class to match database values
class LogType(str, Enum):
    UNKNOWN_DEVICE = "unknown_device"
    INVALID_CREDENTIALS = "invalid_credentials"
    UNREACHABLE = "unreachable"

    @classmethod
    def _missing_(cls, value):
        # Handle case-insensitive matching
        for member in cls:
            if member.value.lower() == value.lower():
                return member
        return cls.UNKNOWN_DEVICE  # Default to UNKNOWN_DEVICE if no match

# Function to check network access
def check_network_access(db: Session, user: User, network_id: int) -> Optional[Network]:
    """Check if user has access to the network."""
    if user.role in ["superadmin", "company_admin", "full_control"]:
        return db.query(Network).filter(Network.id == network_id).first()
    else:
        # For engineers, check network access through UserNetworkAccess
        network_access = db.query(UserNetworkAccess).filter(
            UserNetworkAccess.user_id == user.id,
            UserNetworkAccess.network_id == network_id
        ).first()
        if network_access:
            return db.query(Network).filter(Network.id == network_id).first()
    return None

router = APIRouter(
    tags=["Devices"]
)

def check_engineer_permissions(current_user: dict, db: Session) -> Optional[User]:
    """Check engineer permissions based on their tier."""
    if current_user["role"] != "engineer":
        return None
        
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

def ping_device(ip: str) -> bool:
    try:
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]

        output = subprocess.run(cmd, stdout=subprocess.DEVNULL)
        print(f"[PING] {ip} -> {'✅' if output.returncode == 0 else '❌'}")
        return output.returncode == 0
    except Exception as e:
        print(f"[PING ERROR] {ip}: {e}")
        return False

# Cache for device status
class DeviceStatusCache:
    def __init__(self):
        self._cache = {}
        self._lock = asyncio.Lock()

    async def get(self, device_id):
        async with self._lock:
            return self._cache.get(device_id)

    async def set(self, device_id, status):
        async with self._lock:
            self._cache[device_id] = {
                "status": status,
                "ping": status.get("ping", False),
                "snmp": status.get("snmp", False),
                "timestamp": datetime.utcnow()
            }

    async def clear(self, device_id=None):
        async with self._lock:
            if device_id:
                self._cache.pop(device_id, None)
            else:
                self._cache.clear()

# Initialize the cache
device_status_cache = DeviceStatusCache()

@router.get("/", response_model=List[DeviceSchema])
async def get_devices(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all devices for a network."""
    devices = db.query(Device).filter(Device.network_id == network_id).all()
    device_list = []
    
    for device in devices:
        # Get the stored status from the database
        ping_status = device.ping_status if device.ping_status is not None else False
        snmp_status = device.snmp_status if device.snmp_status is not None else True  # Default to True if not set
        
        print(f"Device {device.name} ({device.ip}) status from database:", {
            "ping_status": ping_status,
            "snmp_status": snmp_status,
            "is_active": device.is_active,
            "discovery_method": device.discovery_method
        })
        
        # Create device dictionary with stored status
        device_dict = {
            "id": device.id,
            "name": device.name,
            "ip": device.ip,
            "location": device.location,
            "type": device.type,
            "platform": device.platform,
            "username": device.username,
            "password": device.password,
            "owner_id": device.owner_id,
            "network_id": device.network_id,
            "is_active": device.is_active,
            "created_at": device.created_at,
            "updated_at": device.updated_at,
            "os_version": device.os_version,
            "serial_number": device.serial_number,
            "company_id": device.company_id,
            "ping_status": ping_status,
            "snmp_status": snmp_status,
            "discovery_method": device.discovery_method
        }
        device_list.append(device_dict)
    
    print(f"Returning {len(device_list)} devices with status:", [
        {
            "name": d["name"],
            "ping": d["ping_status"],
            "snmp": d["snmp_status"],
            "discovery_method": d["discovery_method"]
        } for d in device_list
    ])
    
    return device_list

@router.post("/", response_model=DeviceSchema)
def create_device(
    device: DeviceCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new device if user has permission."""
    # Full Control users can create devices
    if current_user["role"] == "full_control":
        device_data = device.dict()
        device_data["is_active"] = True
        device_data["discovery_method"] = "manual"  # Set discovery method for manual creation
        new_device = Device(**device_data, owner_id=current_user["user_id"], company_id=current_user["company_id"])
        try:
            db.add(new_device)
            db.commit()
            db.refresh(new_device)
            return new_device
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    if current_user["role"] == "engineer":
        user = check_engineer_permissions(current_user, db)
        if not user or user.engineer_tier == 1:
            raise HTTPException(
                status_code=403,
                detail="Tier 1 engineers cannot create devices"
            )
        
        network_access = db.query(UserNetworkAccess).filter(
            UserNetworkAccess.user_id == current_user["user_id"],
            UserNetworkAccess.network_id == device.network_id
        ).first()
        
        if not network_access:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to create devices in this network"
            )

    # Create device with is_active=True
    device_data = device.dict()
    device_data["is_active"] = True
    device_data["discovery_method"] = "manual"  # Set discovery method for manual creation
    new_device = Device(**device_data, owner_id=current_user["user_id"], company_id=current_user["company_id"])
    
    try:
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        return new_device
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.put("/{device_id}", response_model=DeviceSchema)
def update_device(
    device_id: int,
    updated_data: DeviceCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Update a device if user has permission."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Full Control users can update any device
    if current_user["role"] == "full_control":
        # Preserve discovery_method if it's 'auto'
        discovery_method = device.discovery_method
        for key, value in updated_data.dict().items():
            if key != 'discovery_method':  # Don't update discovery_method
                setattr(device, key, value)
        if discovery_method == 'auto':
            device.discovery_method = 'auto'
        try:
            db.commit()
            db.refresh(device)
            return device
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=400, detail=str(e))

    if current_user["role"] == "engineer":
        user = check_engineer_permissions(current_user, db)
        if not user or user.engineer_tier == 1:
            raise HTTPException(
                status_code=403,
                detail="Tier 1 engineers cannot modify devices"
            )
        
        network_access = db.query(UserNetworkAccess).filter(
            UserNetworkAccess.user_id == current_user["user_id"],
            UserNetworkAccess.network_id == device.network_id
        ).first()
        
        if not network_access:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to modify devices in this network"
            )
    elif current_user["role"] == "company_admin":
        if device.company_id != current_user["company_id"]:
            raise HTTPException(status_code=403, detail="Not authorized to modify this device")
    else:
        raise HTTPException(status_code=403, detail="Not authorized to modify devices")

    # Update the device
    for key, value in updated_data.dict().items():
        setattr(device, key, value)
    try:
        db.commit()
        db.refresh(device)
        return device
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/{device_id}", status_code=204)
def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a device if user has permission."""
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Full Control users can delete any device
        if current_user["role"] == "full_control":
            # Delete all related records first
            from sqlalchemy import text
            db.execute(text("DELETE FROM device_interfaces WHERE device_id = :device_id"), {"device_id": device_id})
            db.execute(text("DELETE FROM device_status WHERE device_id = :device_id"), {"device_id": device_id})
            db.query(DeviceLog).filter(DeviceLog.ip_address == device.ip).delete()
            # Delete the device
            db.delete(device)
            db.commit()
            return

        # Company admin can delete devices in their company
        if current_user["role"] == "company_admin":
            if device.company_id != current_user["company_id"]:
                raise HTTPException(status_code=403, detail="Not authorized to delete this device")
            # Delete all related records first
            from sqlalchemy import text
            db.execute(text("DELETE FROM device_interfaces WHERE device_id = :device_id"), {"device_id": device_id})
            db.execute(text("DELETE FROM device_status WHERE device_id = :device_id"), {"device_id": device_id})
            db.query(DeviceLog).filter(DeviceLog.ip_address == device.ip).delete()
            # Delete the device
            db.delete(device)
            db.commit()
            return

        # Engineer permissions
        if current_user["role"] == "engineer":
            user = check_engineer_permissions(current_user, db)
            if not user or user.engineer_tier == 1:
                raise HTTPException(
                    status_code=403,
                    detail="Tier 1 engineers cannot delete devices"
                )
            
            network_access = db.query(UserNetworkAccess).filter(
                UserNetworkAccess.user_id == current_user["user_id"],
                UserNetworkAccess.network_id == device.network_id
            ).first()
            
            if not network_access:
                raise HTTPException(
                    status_code=403,
                    detail="Not authorized to delete devices in this network"
                )
            
            # Delete all related records first
            from sqlalchemy import text
            db.execute(text("DELETE FROM device_interfaces WHERE device_id = :device_id"), {"device_id": device_id})
            db.execute(text("DELETE FROM device_status WHERE device_id = :device_id"), {"device_id": device_id})
            db.query(DeviceLog).filter(DeviceLog.ip_address == device.ip).delete()
            # Delete the device
            db.delete(device)
            db.commit()
            return

        raise HTTPException(status_code=403, detail="Not authorized to delete devices")
    except Exception as e:
        db.rollback()
        print(f"Error deleting device {device_id}: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/status/{device_id}", response_model=dict)
async def get_device_status(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Get the stored status from the database
        ping_status = device.ping_status if device.ping_status is not None else False
        snmp_status = device.snmp_status if device.snmp_status is not None else False
        
        # Calculate status based on ping and SNMP
        status = "green" if (ping_status and snmp_status) else "yellow" if ping_status else "red"
        
        return {
            "status": status,
            "ping": ping_status,
            "snmp": snmp_status,
            "ip": device.ip,
            "last_checked": device.updated_at.isoformat()
        }
        
    except Exception as e:
        print(f"Error getting device status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/status/{device_id}/refresh")
async def refresh_device_status(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Force refresh the status of a device"""
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Perform fresh checks
        ping_ok = ping_device(device.ip)
        print(f"[PING] {device.ip} -> {'✅' if ping_ok else '❌'}")
        
        snmp_ok = False
        
        # Always check SNMP if configuration exists, regardless of ping status
        if hasattr(device, 'snmp_config') and device.snmp_config:
            try:
                device_snmp = DeviceSNMP(
                    snmp_version=device.snmp_config.snmp_version,
                    community=device.snmp_config.community,
                    username=device.snmp_config.username,
                    auth_protocol=device.snmp_config.auth_protocol,
                    auth_password=device.snmp_config.auth_password,
                    priv_protocol=device.snmp_config.priv_protocol,
                    priv_password=device.snmp_config.priv_password,
                    port=device.snmp_config.port
                )
                snmp_ok, _ = check_snmp(device.ip, device_snmp)
                print(f"[SNMP] {device.ip} -> {'✅' if snmp_ok else '❌'}")
            except Exception as e:
                print(f"Error checking SNMP for device {device.ip}: {str(e)}")
                snmp_ok = False
        else:
            print(f"[SNMP] {device.ip} -> ⚠️ (No SNMP config)")

        # Update device in database
        try:
            device.ping_status = ping_ok
            device.snmp_status = snmp_ok
            device.updated_at = datetime.utcnow()
            db.add(device)
            db.commit()
            db.refresh(device)  # Refresh to get the updated values
        except Exception as e:
            print(f"Error updating device status: {str(e)}")
            db.rollback()
            raise HTTPException(status_code=500, detail=str(e))

        # Calculate status
        if ping_ok and snmp_ok:
            status = "green"
        elif ping_ok and not snmp_ok:
            status = "orange"
        else:
            status = "red"

        return {
            "status": status,
            "ping": ping_ok,
            "snmp": snmp_ok,
            "ip": device.ip,
            "last_checked": device.updated_at.isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/status/refresh-all")
async def refresh_all_device_status(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Refresh status for all devices in a network using agents"""
    try:
        print(f"[STATUS] Starting status refresh for network {network_id}")
        
        # Get all devices in the network
        devices = db.query(Device).filter(Device.network_id == network_id).all()
        print(f"[STATUS] Found {len(devices)} devices in network")
        
        # Get available agents for this network
        from app.api.v1.endpoints.agents import get_available_agents_for_network
        agents_response = await get_available_agents_for_network(network_id, current_user, db)
        agents = agents_response.get("available_agents", [])
        print(f"[STATUS] Found {len(agents)} available agents")
        
        if not agents:
            print(f"[STATUS] No agents available for network {network_id}")
            return {
                "message": "No agents available for status testing",
                "updated": 0,
                "total": len(devices),
                "session_id": None,
                "status": "no_agents"
            }
        
        # Use the first available agent
        agent = agents[0]
        agent_id = agent['id']
        print(f"[STATUS] Using agent ID: {agent_id}")
        
        # Create a session ID for tracking this status refresh
        import uuid
        session_id = f"status_refresh_{uuid.uuid4().hex[:8]}"
        print(f"[STATUS] Created session ID: {session_id}")
        
        # Prepare device data for agent
        device_data = []
        print(f"[STATUS] Starting to prepare device data for {len(devices)} devices")
        
        for device in devices:
            try:
                print(f"[STATUS] Processing device: {device.ip}")
                print(f"[STATUS] Device object type: {type(device)}")
                print(f"[STATUS] Device attributes: {dir(device)}")
                
                # Check if device has SNMP configuration
                has_snmp_config = hasattr(device, 'snmp_config') and device.snmp_config
                print(f"[STATUS] Device {device.ip} has SNMP config: {has_snmp_config}")
                
                if has_snmp_config:
                    print(f"[STATUS] Device {device.ip} SNMP config: version={device.snmp_config.snmp_version}, community={device.snmp_config.community}, port={device.snmp_config.port}")
                else:
                    print(f"[STATUS] Device {device.ip} has no SNMP config, using defaults")
                
                # Try to get SNMP config from device
                snmp_config = None
                if hasattr(device, 'snmp_config') and device.snmp_config:
                    snmp_config = {
                        'snmp_version': device.snmp_config.snmp_version,
                        'community': device.snmp_config.community,
                        'port': device.snmp_config.port
                    }
                    print(f"[STATUS] Device {device.ip} has stored SNMP config: {snmp_config}")
                else:
                    # Since we don't have SNMP config stored, we need to ask the user
                    # For now, we'll skip SNMP testing and only test ping
                    print(f"[STATUS] Device {device.ip} has no SNMP config stored. SNMP testing will be skipped.")
                    snmp_config = None
                
                device_info = {
                    'ip': device.ip,
                    'snmp_config': snmp_config
                }
                
                print(f"[STATUS] Final SNMP config for {device.ip}: {device_info['snmp_config']}")
                device_data.append(device_info)
                print(f"[STATUS] Prepared device data for {device.ip}")
            except Exception as e:
                print(f"[STATUS] Error processing device {device.ip}: {str(e)}")
                import traceback
                print(f"[STATUS] Full traceback: {traceback.format_exc()}")
                continue
        
        print(f"[STATUS] Prepared {len(device_data)} devices for status testing")
        
        # Store status test request for agent to pick up
        try:
            # Import the global variable from agents module
            from app.api.v1.endpoints.agents import pending_discovery_requests
            
            status_request = {
                "type": "status_test",
                "session_id": session_id,
                "network_id": network_id,
                "devices": device_data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            pending_discovery_requests[agent_id] = status_request
            print(f"[STATUS] Stored status test request for {len(devices)} devices")
            print(f"[STATUS] Request details: agent_id={agent_id}, network_id={network_id}, session_id={session_id}, devices={len(device_data)}")
            
        except Exception as e:
            print(f"[STATUS] Error storing agent status test request: {str(e)}")
            print(f"[STATUS] Error type: {type(e)}")
            import traceback
            print(f"[STATUS] Full traceback: {traceback.format_exc()}")
        
        db.commit()
        
        return {
            "message": f"Requested agent test for {len(devices)} devices",
            "updated": 0,
            "total": len(devices),
            "agent_id": agent_id,
            "session_id": session_id,
            "status": "requested"
        }
        
    except Exception as e:
        print(f"[STATUS] Error in refresh_all_device_status: {str(e)}")
        print(f"[STATUS] Error type: {type(e)}")
        import traceback
        print(f"[STATUS] Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/status-report")
async def report_device_status(
    network_id: int,
    device_statuses: List[dict],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Report device status from agent (for local network devices)"""
    try:
        updated_count = 0
        
        for status_data in device_statuses:
            try:
                device_ip = status_data.get("ip")
                ping_status = status_data.get("ping_status", False)
                snmp_status = status_data.get("snmp_status", False)
                timestamp = status_data.get("timestamp")
                
                if not device_ip:
                    continue
                
                # Find device by IP in the network
                device = db.query(Device).filter(
                    Device.ip == device_ip,
                    Device.network_id == network_id
                ).first()
                
                if device:
                    # Update device status
                    device.ping_status = ping_status
                    device.snmp_status = snmp_status
                    if timestamp:
                        try:
                            device.updated_at = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        except:
                            device.updated_at = datetime.utcnow()
                    else:
                        device.updated_at = datetime.utcnow()
                    
                    db.add(device)
                    updated_count += 1
                    print(f"[AGENT REPORT] {device_ip} -> ping={ping_status}, snmp={snmp_status}")
                
            except Exception as e:
                print(f"Error processing status report for {device_ip}: {str(e)}")
                continue
        
        db.commit()
        
        return {
            "message": f"Updated status for {updated_count} devices from agent",
            "updated": updated_count
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




@router.put("/{device_id}/toggle-service")
def toggle_device_service(
    device_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Toggle device service status."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Check permissions
    if current_user["role"] not in ["company_admin", "full_control"]:
        if current_user["role"] == "engineer":
            user = check_engineer_permissions(current_user, db)
            if not user or user.engineer_tier < 2:
                raise HTTPException(
                    status_code=403,
                    detail="Insufficient permissions to toggle device service"
                )
            
            network_access = db.query(UserNetworkAccess).filter(
                UserNetworkAccess.user_id == current_user["user_id"],
                UserNetworkAccess.network_id == device.network_id
            ).first()
            
            if not network_access:
                raise HTTPException(
                    status_code=403,
                    detail="Not authorized to modify devices in this network"
                )
        else:
            raise HTTPException(
                status_code=403,
                detail="Not authorized to toggle device service"
            )

    try:
        # Update the device status
        device.is_active = data.get('is_active', not device.is_active)
        db.commit()
        db.refresh(device)
        return device
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/all", response_model=List[DeviceSchema])
def get_all_devices(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    network_id: Optional[int] = Query(None)
):
    """Get all devices including inactive ones (for admins and tier 3 engineers only)."""
    if current_user["role"] not in ["company_admin", "superadmin"]:
        user = check_engineer_permissions(current_user, db)
        if not user or user.engineer_tier < 3:
            raise HTTPException(
                status_code=403,
                detail="Only admins and tier 3 engineers can view inactive devices"
            )

    query = db.query(Device)
    if current_user["role"] == "company_admin":
        query = query.filter(Device.company_id == current_user["company_id"])
    
    if network_id:
        query = query.filter(Device.network_id == network_id)

    return query.all()

class DiscoveryRequest(BaseModel):
    network_id: int = Field(..., description="The ID of the network to discover devices in")
    ip_range: Optional[str] = Field(None, description="CIDR notation (e.g. '192.168.1.0/24')")
    start_ip: Optional[str] = Field(None, description="Start IP address for range")
    end_ip: Optional[str] = Field(None, description="End IP address for range")
    username: str = Field(..., description="Username for device authentication")
    password: str = Field(..., description="Password for device authentication")
    device_type: str = Field("cisco_ios", description="Type of device (default: cisco_ios)")
    location: str = Field("", description="Location of the devices")
    snmp_version: Optional[str] = Field(None, description="SNMP version")
    community: Optional[str] = Field(None, description="SNMP community string")
    snmp_username: Optional[str] = Field(None, description="SNMP username")
    auth_protocol: Optional[str] = Field(None, description="SNMP authentication protocol")
    auth_password: Optional[str] = Field(None, description="SNMP authentication password")
    priv_protocol: Optional[str] = Field(None, description="SNMP privacy protocol")
    priv_password: Optional[str] = Field(None, description="SNMP privacy password")
    snmp_port: str = Field(..., description="SNMP port")

    class Config:
        json_schema_extra = {
            "example": {
                "network_id": 1,
                "username": "admin",
                "password": "password123",
                "ip_range": "192.168.1.0/24"
            }
        }

class DiscoveryStatus(BaseModel):
    total_ips: int
    scanned_ips: int
    discovered_devices: int
    status: str  # "in_progress", "completed", "failed"
    error: Optional[str] = None

# Store discovery status for each network
discovery_status: Dict[int, DiscoveryStatus] = {}

def is_valid_cidr(ip_range: str) -> bool:
    try:
        ipaddress.ip_network(ip_range)
        return True
    except ValueError:
        return False

async def check_tcp_port(ip: str, port: int = 22, timeout: float = 1) -> bool:
    """Quick check if TCP port is open without full connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

async def scan_single_device(
    ip_address: str,
    username: str,
    password: str,
    device_type: str,
    network_id: int,
    company_id: int,
    db: Session,
    owner_id: int,
    snmp_config: dict = None
) -> Dict[str, Any]:
    print(f"Scanning device at {ip_address}")

    # Initial ping check
    ping_ok = ping_device(ip_address)
    print(f"Initial ping check for {ip_address}: {ping_ok}")

    if not ping_ok:
        try:
            log = DeviceLog(
                ip_address=ip_address,
                network_id=network_id,
                company_id=company_id,
                log_type=LogType.UNREACHABLE.value,
                message=f"Device at {ip_address} is unreachable"
            )
            db.add(log)
            db.commit()
        except Exception as e:
            print(f"Error creating ping failure log: {str(e)}")
            db.rollback()
        return {"status": "failed", "message": "Device unreachable", "ip": ip_address}

    try:
        # Create SNMP config object with provided configuration
        device_snmp = DeviceSNMP(
            snmp_version=snmp_config.get('snmp_version', 'v2c'),
            community=snmp_config.get('community', 'public'),
            username=snmp_config.get('username'),
            auth_protocol=snmp_config.get('auth_protocol'),
            auth_password=snmp_config.get('auth_password'),
            priv_protocol=snmp_config.get('priv_protocol'),
            priv_password=snmp_config.get('priv_password'),
            port=snmp_config.get('port', 161)
        )
        
        # Check SNMP
        snmp_ok, snmp_info = check_snmp(ip_address, device_snmp)
        print(f"[SNMP] {ip_address} -> {'✅' if snmp_ok else '❌'}")
        
        if not snmp_ok:
            try:
                log = DeviceLog(
                    ip_address=ip_address,
                    network_id=network_id,
                    company_id=company_id,
                    log_type=LogType.UNKNOWN_DEVICE.value,
                    message=f"SNMP authentication failed for {ip_address}"
                )
                db.add(log)
                db.commit()
            except Exception as e:
                print(f"Error creating SNMP failure log: {str(e)}")
                db.rollback()
            return {"status": "failed", "message": "SNMP authentication failed", "ip": ip_address}

        # Get detailed device info via SNMP
        device_info = get_device_info_snmp(ip_address, device_snmp)
        
        if not device_info:
            try:
                log = DeviceLog(
                    ip_address=ip_address,
                    network_id=network_id,
                    company_id=company_id,
                    log_type=LogType.UNKNOWN_DEVICE.value,
                    message=f"Failed to get device info via SNMP for {ip_address}"
                )
                db.add(log)
                db.commit()
            except Exception as e:
                print(f"Error creating SNMP info failure log: {str(e)}")
                db.rollback()
            return {"status": "failed", "message": "Failed to get device info", "ip": ip_address}

        # Clean up device name by removing .test and .Test suffixes
        hostname = device_info['hostname'].replace('.test', '').replace('.Test', '')
        
        # Create or update device in database
        device_entry = db.query(Device).filter_by(ip=ip_address, network_id=network_id).first()
        if device_entry:
            print(f"Updating existing device {ip_address}")
            device_entry.name = hostname  # Use cleaned hostname
            device_entry.type = device_info['model']
            device_entry.platform = 'cisco_ios_xe' if 'IOS-XE' in device_info['description'] else device_type
            device_entry.username = username
            device_entry.password = password
            device_entry.is_active = True
            device_entry.os_version = device_info['os_version']
            device_entry.serial_number = device_info['serial_number']
            device_entry.ping_status = True
            device_entry.snmp_status = True
            device_entry.discovery_method = 'auto'  # Set discovery method for auto-discovery
            
            # Update SNMP config
            if device_entry.snmp_config:
                device_entry.snmp_config.snmp_version = device_snmp.snmp_version
                device_entry.snmp_config.community = device_snmp.community
                device_entry.snmp_config.username = device_snmp.username
                device_entry.snmp_config.auth_protocol = device_snmp.auth_protocol
                device_entry.snmp_config.auth_password = device_snmp.auth_password
                device_entry.snmp_config.priv_protocol = device_snmp.priv_protocol
                device_entry.snmp_config.priv_password = device_snmp.priv_password
                device_entry.snmp_config.port = device_snmp.port
            else:
                device_entry.snmp_config = DeviceSNMPModel(
                    snmp_version=device_snmp.snmp_version,
                    community=device_snmp.community,
                    username=device_snmp.username,
                    auth_protocol=device_snmp.auth_protocol,
                    auth_password=device_snmp.auth_password,
                    priv_protocol=device_snmp.priv_protocol,
                    priv_password=device_snmp.priv_password,
                    port=device_snmp.port
                )
            
            if not device_entry.location:
                device_entry.location = device_info['location'] or 'Default'
            db.add(device_entry)
        else:
            print(f"Creating new device {ip_address}")
            device_entry = Device(
                ip=ip_address,
                name=hostname,  # Use cleaned hostname
                type=device_info['model'],
                platform='cisco_ios_xe' if 'IOS-XE' in device_info['description'] else device_type,
                username=username,
                password=password,
                network_id=network_id,
                company_id=company_id,
                owner_id=owner_id,
                is_active=True,
                os_version=device_info['os_version'],
                serial_number=device_info['serial_number'],
                location=device_info['location'] or 'Default',
                ping_status=True,
                snmp_status=True,
                discovery_method='auto'  # Set discovery method for auto-discovery
            )
            
            # Create SNMP config
            device_entry.snmp_config = DeviceSNMPModel(
                snmp_version=device_snmp.snmp_version,
                community=device_snmp.community,
                username=device_snmp.username,
                auth_protocol=device_snmp.auth_protocol,
                auth_password=device_snmp.auth_password,
                priv_protocol=device_snmp.priv_protocol,
                priv_password=device_snmp.priv_password,
                port=device_snmp.port
            )
            
            db.add(device_entry)

        try:
            db.commit()
            print(f"Successfully saved device {ip_address} to database")
        except Exception as e:
            db.rollback()
            print(f"Error committing device changes: {str(e)}")
            raise e

        # Create success log with cleaned hostname
        try:
            log = DeviceLog(
                ip_address=ip_address,
                log_type=LogType.UNKNOWN_DEVICE.value,
                message=f"Successfully discovered device: {hostname} ({device_info['model']})",  # Use cleaned hostname
                network_id=network_id,
                company_id=company_id
            )
            db.add(log)
            db.commit()
        except Exception as e:
            print(f"Error creating success log: {str(e)}")
            db.rollback()

        return {
            "status": "success",
            "hostname": hostname,  # Use cleaned hostname
            "model": device_info['model'],
            "platform": 'cisco_ios_xe' if 'IOS-XE' in device_info['description'] else device_type,
            "os_version": device_info['os_version'],
            "serial_number": device_info['serial_number'],
            "ip": ip_address,
            "ping_status": True,
            "snmp_status": True
        }

    except Exception as e:
        print(f"Error scanning device at {ip_address}: {str(e)}")
        try:
            log = DeviceLog(
                ip_address=ip_address,
                network_id=network_id,
                company_id=company_id,
                log_type=LogType.UNKNOWN_DEVICE.value,
                message=f"Error scanning device at {ip_address}: {str(e)}"
            )
            db.add(log)
            db.commit()
        except Exception as log_e:
            print(f"Error creating error log: {str(log_e)}")
            db.rollback()
        return {"status": "failed", "message": str(e), "ip": ip_address}

@router.post("/discover")
@router.post("/discovery/start")
async def start_discovery(
    request: Request,
    discovery_data: dict,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start device discovery for a network"""
    try:
        print(f"Raw discovery request data: {discovery_data}")

        # Get the full user object from the database
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check network access
        network = check_network_access(db, user, discovery_data['network_id'])
        if not network:
            raise HTTPException(status_code=403, detail="No access to this network")

        # Check if user has permission to discover devices
        if user.role == "engineer" and user.engineer_tier < 2:
            raise HTTPException(
                status_code=403,
                detail="Only Tier 2 and above engineers can perform device discovery"
            )

        # Get and validate IP range
        ip_range = None
        if discovery_data.get('ip_range'):
            # Check if the ip_range is in the format "start_ip-end_ip"
            if '-' in discovery_data['ip_range']:
                try:
                    start_ip_str, end_ip_str = discovery_data['ip_range'].split('-')
                    start_ip = ipaddress.IPv4Address(start_ip_str.strip())
                    end_ip = ipaddress.IPv4Address(end_ip_str.strip())
                    # For a range, we'll handle it directly in run_discovery
                    ip_range = f"{start_ip}-{end_ip}"
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=f"Invalid IP range format: {str(e)}")
            else:
                ip_range = discovery_data['ip_range']
        elif discovery_data.get('start_ip') and discovery_data.get('end_ip'):
            try:
                start_ip = ipaddress.IPv4Address(discovery_data['start_ip'])
                end_ip = ipaddress.IPv4Address(discovery_data['end_ip'])
                ip_range = f"{start_ip}-{end_ip}"
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid IP range: {str(e)}")
        else:
            raise HTTPException(status_code=400, detail="IP range must be provided either in CIDR notation, start_ip-end_ip format, or as separate start_ip and end_ip fields")

        print(f"Using IP range: {ip_range}")

        # Initialize discovery status before starting
        discovery_status[discovery_data['network_id']] = DiscoveryStatus(
            total_ips=0,
            scanned_ips=0,
            discovered_devices=0,
            status="starting"
        )

        # Validate IP range format
        if '-' not in ip_range and not is_valid_cidr(ip_range):
            raise HTTPException(status_code=400, detail="Invalid IP range format")

        # Create SNMP configuration
        snmp_config = {
            'snmp_version': discovery_data.get('snmp_version', 'v2c'),
            'community': discovery_data.get('community', 'public'),
            'username': discovery_data.get('snmp_username'),
            'auth_protocol': discovery_data.get('auth_protocol'),
            'auth_password': discovery_data.get('auth_password'),
            'priv_protocol': discovery_data.get('priv_protocol'),
            'priv_password': discovery_data.get('priv_password'),
            'port': int(discovery_data.get('snmp_port', 161))
        }

        # Start discovery process
        asyncio.create_task(run_discovery(
            discovery_data['network_id'],
            discovery_data.get('start_ip'),
            discovery_data.get('end_ip'),
            discovery_data['username'],
            discovery_data['password'],
            discovery_data.get('device_type', 'cisco_ios'),
            db,
            current_user["user_id"],
            snmp_config
        ))

        return {"status": "Discovery started", "scan_id": str(discovery_data['network_id'])}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Discovery error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to start discovery: {str(e)}")

@router.get("/discovery/status/{network_id}")
@router.get("/discover/status/{network_id}")
async def get_discovery_status(
    network_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get the status of device discovery for a network"""
    try:
        print(f"Checking discovery status for network: {network_id}")
        
        # Handle invalid network_id
        if network_id == "undefined" or not network_id.isdigit():
            print(f"Invalid network_id: {network_id}")
            return {
                "total_ips": 0,
                "scanned_ips": 0,
                "discovered_devices": 0,
                "status": "not_started",
                "error": None
            }

        network_id_int = int(network_id)
        
        # Get the full user object
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check network access
        network = check_network_access(db, user, network_id_int)
        if not network:
            raise HTTPException(status_code=403, detail="No access to this network")

        # Get status from memory
        status = discovery_status.get(network_id_int)
        
        # If no status in memory, check if discovery is still running
        if not status:
            # Check if there are any devices in the network
            device_count = db.query(Device).filter(Device.network_id == network_id_int).count()
            if device_count > 0:
                # If we have devices, discovery must have completed
                return {
                    "total_ips": device_count,
                    "scanned_ips": device_count,
                    "discovered_devices": device_count,
                    "status": "completed",
                    "error": None
                }
            else:
                return {
                    "total_ips": 0,
                    "scanned_ips": 0,
                    "discovered_devices": 0,
                    "status": "not_started",
                    "error": None
                }

        print(f"Current discovery status for network {network_id_int}: {status}")
        return {
            "total_ips": status.total_ips,
            "scanned_ips": status.scanned_ips,
            "discovered_devices": status.discovered_devices,
            "status": status.status,
            "error": status.error
        }
    except ValueError:
        return {
            "total_ips": 0,
            "scanned_ips": 0,
            "discovered_devices": 0,
            "status": "not_started",
            "error": None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Status check error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get discovery status: {str(e)}")

@router.get("/logs/{network_id}", response_model=List[DeviceLogSchema])
async def get_device_logs(
    network_id: int,
    failed_only: bool = False,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
) -> List[Dict]:
    try:
        # Get the full user object
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Verify user has access to this network using check_network_access
        network = check_network_access(db, user, network_id)
        if not network:
            raise HTTPException(status_code=403, detail="Not authorized to access this network")
        
        # Query logs - by default only show failed attempts
        query = db.query(DeviceLog).filter(
            DeviceLog.network_id == network_id,
            DeviceLog.log_type.in_([
                "unknown_device",
                "invalid_credentials",
                "unreachable"
            ])
        )
        
        # Order by most recent first
        logs = query.order_by(DeviceLog.created_at.desc()).all()
        
        def get_failure_reason(log_type: str) -> str:
            if log_type == "unreachable":
                return "Device Unreachable"
            elif log_type == "invalid_credentials":
                return "Invalid Credentials"
            elif log_type == "unknown_device":
                return "Unknown Error"
            return "Unknown"
        
        # Format logs
        formatted_logs = []
        for log in logs:
            formatted_log = {
                "id": log.id,
                "ip_address": log.ip_address,
                "network_id": log.network_id,
                "company_id": log.company_id,
                "log_type": log.log_type,
                "message": log.message,
                "created_at": log.created_at.isoformat(),
                "status": "failed",
                "failure_reason": get_failure_reason(log.log_type)
            }
            formatted_logs.append(formatted_log)
        
        return formatted_logs
    except Exception as e:
        print(f"Error getting device logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get device logs: {str(e)}")

@router.post("/logs", response_model=DeviceLogSchema)
async def create_device_log(
    log: DeviceLogCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new device log entry."""
    # Get the full user object from the database
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if user has access to the network
    network = check_network_access(db, user, log.network_id)
    if not network:
        raise HTTPException(status_code=403, detail="Not authorized to access this network")

    # Create log entry
    db_log = DeviceLog(
        **log.dict(),
        company_id=current_user["company_id"]
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    
    return db_log

async def scan_device(ip: str, username: str, password: str, device_type: str, network_id: int, db: Session) -> Optional[Dict[str, str]]:
    """
    Scan a device and return its hostname, model, and platform information.
    Returns None if device is unreachable or credentials are invalid.
    """
    try:
        device = {
            'device_type': device_type,
            'ip': ip,
            'username': username,
            'password': password,
            'timeout': 5,
            'fast_cli': True
        }
        
        connection = ConnectHandler(**device)
        
        # Get hostname from prompt
        hostname = connection.find_prompt().replace('#', '').strip()
        
        # Get version info for model and platform detection
        version_output = connection.send_command('show version')
        
        # Try to get model from version output
        

        
        if 'WS-C' in version_output:
            # Extract Catalyst switch model (e.g., WS-C3750X-48P)
            model_match = re.search(r'(WS-C\d+[A-Z]?-\d+[A-Z]?)', version_output)
            if model_match:
                model = model_match.group(1)
        elif 'ISR' in version_output:
            # Extract ISR model
            model_match = re.search(r'(ISR\d+)', version_output)
            if model_match:
                model = model_match.group(1)
        elif 'ASR' in version_output:
            # Extract ASR model
            model_match = re.search(r'(ASR\d+)', version_output)
            if model_match:
                model = model_match.group(1)
        elif 'CSR' in version_output:
            # Extract CSR model
            model_match = re.search(r'(CSR\d+)', version_output)
            if model_match:
                model = model_match.group(1)
                
        if not model:
            # Fallback to basic model extraction
            model_match = re.search(r'[Cc]isco\s+(\S+)(?:\s+\([^)]+\))?\s+processor', version_output)
            if model_match:
                model = model_match.group(1)
            else:
                model = device_type
        
        # Determine platform (IOS or IOS-XE)
        platform = 'cisco_ios_xe' if 'IOS-XE' in version_output else device_type
        
        # Create or update device in database
        device_entry = db.query(Device).filter_by(ip=ip, network_id=network_id).first()
        if device_entry:
            device_entry.name = hostname
            device_entry.type = model
            device_entry.platform = platform
            device_entry.username = username
            device_entry.password = password
        else:
            network = db.query(Network).filter_by(id=network_id).first()
            if not network:
                raise ValueError(f"Network with ID {network_id} not found")
                
            device_entry = Device(
                ip=ip,
                name=hostname,
                type=model,
                platform=platform,
                username=username,
                password=password,
                network_id=network_id,
                company_id=network.company_id
            )
            db.add(device_entry)
        
        try:
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error committing device changes: {str(e)}")
            
        # Create success log
        try:
            network = db.query(Network).filter_by(id=network_id).first()
            log = DeviceLog(
                ip_address=ip,
                network_id=network_id,
                company_id=network.company_id,
                log_type=LogType.UNKNOWN_DEVICE.value,  # Use UNKNOWN_DEVICE for success
                message=f"Successfully discovered device: {hostname} ({model})"
            )
            db.add(log)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error creating success log: {str(e)}")
        
        connection.disconnect()
        return {
            "hostname": hostname,
            "model": model,
            "platform": platform
        }
        
    except AuthenticationException:
        # Handle authentication failure
        try:
            network = db.query(Network).filter_by(id=network_id).first()
            log = DeviceLog(
                ip_address=ip,
                network_id=network_id,
                company_id=network.company_id,
                log_type=LogType.INVALID_CREDENTIALS.value,  # Use exact string from enum
                message=f"Invalid credentials for device at {ip}"
            )
            db.add(log)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error creating auth failure log: {str(e)}")
        return None
        
    except NetMikoTimeoutException:
        # Handle connection timeout
        try:
            network = db.query(Network).filter_by(id=network_id).first()
            log = DeviceLog(
                ip_address=ip,
                network_id=network_id,
                company_id=network.company_id,
                log_type=LogType.UNREACHABLE.value,  # Use exact string from enum
                message=f"Device unreachable at {ip}"
            )
            db.add(log)
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"Error creating unreachable log: {str(e)}")
        return None
        
    except Exception as e:
        # Handle other exceptions
        print(f"Error scanning device at {ip}: {str(e)}")
        try:
            network = db.query(Network).filter_by(id=network_id).first()
            log = DeviceLog(
                ip_address=ip,
                network_id=network_id,
                company_id=network.company_id,
                log_type=LogType.UNREACHABLE.value,  # Use exact string from enum
                message=f"Error scanning device at {ip}: {str(e)}"
            )
            db.add(log)
            db.commit()
        except Exception as log_e:
            db.rollback()
            print(f"Error creating error log: {str(log_e)}")
        return None

@router.delete("/logs/{network_id}/clear", status_code=204)
async def clear_device_logs(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Clear all device logs for a network."""
    try:
        # Get the full user object from the database
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Full Control users can clear logs for any network
        if user.role == "full_control" or user.role == "company_admin":
            db.query(DeviceLog).filter(
                DeviceLog.network_id == network_id,
                DeviceLog.company_id == current_user["company_id"]
            ).delete()
            db.commit()
            return

        # For other roles, check network access
        network = check_network_access(db, user, network_id)
        if not network:
            raise HTTPException(status_code=403, detail="Not authorized to clear logs for this network")

        # Delete logs for the network
        db.query(DeviceLog).filter(
            DeviceLog.network_id == network_id,
            DeviceLog.company_id == current_user["company_id"]
        ).delete()
        db.commit()

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

def check_snmp(ip, snmp_config):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(snmp_config.community, mpModel=0 if snmp_config.snmp_version == 'v1' else 1),  # Use provided community string
            UdpTransportTarget((ip, snmp_config.port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
        )
        
        error_indication, error_status, error_index, var_binds = next(iterator)
        
        if error_indication:
            print(f"SNMP error indication: {error_indication}")
            return False, None
        elif error_status:
            print(f"SNMP error status: {error_status}")
            return False, None
        else:
            return True, var_binds[0][1].prettyPrint()
    except Exception as e:
        print(f"SNMP error for {ip}: {str(e)}")
        return False, None

def get_device_info_snmp(ip, snmp_config):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(snmp_config.community, mpModel=0 if snmp_config.snmp_version == 'v1' else 1),  # Use provided community string
            UdpTransportTarget((ip, snmp_config.port), timeout=2, retries=1),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0')),  # sysName
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.6.0')),  # sysLocation
            ObjectType(ObjectIdentity('1.3.6.1.2.1.47.1.1.1.1.11.1')),  # entPhysicalSerialNum
            ObjectType(ObjectIdentity('1.3.6.1.2.1.47.1.1.1.1.13.1'))   # entPhysicalModelName
        )
        
        error_indication, error_status, error_index, var_binds = next(iterator)
        
        if error_indication:
            print(f"SNMP error indication: {error_indication}")
            return None
        elif error_status:
            print(f"SNMP error status: {error_status}")
            return None
        
        info = {
            'hostname': var_binds[0][1].prettyPrint(),
            'description': var_binds[1][1].prettyPrint(),
            'location': var_binds[2][1].prettyPrint() or 'Default',
            'serial_number': var_binds[3][1].prettyPrint(),
            'model': var_binds[4][1].prettyPrint()
        }
        
        # Extract OS version from description
        version_match = re.search(r'Version\s+([\d\.]+[a-z]?)', info['description'])
        if version_match:
            info['os_version'] = version_match.group(1)
        else:
            info['os_version'] = 'Unknown'
        
        return info
    except Exception as e:
        print(f"Error getting SNMP info for {ip}: {str(e)}")
        return None

@router.post("/discover", response_model=dict)
async def discover_device(
    request: Request,
    discovery_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        print(f"Raw discovery request data: {discovery_data}")
        
        # Extract SNMP configuration
        snmp_config = {
            'version': discovery_data.get('snmp_version', 'v2c'),
            'community': discovery_data.get('community', 'public'),
            'username': discovery_data.get('snmp_username'),
            'auth_protocol': discovery_data.get('auth_protocol'),
            'auth_password': discovery_data.get('auth_password'),
            'priv_protocol': discovery_data.get('priv_protocol'),
            'priv_password': discovery_data.get('priv_password'),
            'port': int(discovery_data.get('snmp_port', 161))
        }
        
        # Extract network and IP range information
        network_id = discovery_data.get('network_id')
        if not network_id:
            raise HTTPException(status_code=400, detail="Network ID is required")
            
        # Get network and verify access
        network = check_network_access(db, current_user, network_id)
        if not network:
            raise HTTPException(status_code=403, detail="Access denied to this network")
            
        company_id = network.company_id
        
        # Parse IP range
        ip_list = []
        if discovery_data.get('ip_range'):
            if not is_valid_cidr(discovery_data['ip_range']):
                raise HTTPException(status_code=400, detail="Invalid CIDR notation")
            ip_list = list(ipaddress.IPv4Network(discovery_data['ip_range']))
        elif discovery_data.get('start_ip') and discovery_data.get('end_ip'):
            start_ip = ipaddress.IPv4Address(discovery_data['start_ip'])
            end_ip = ipaddress.IPv4Address(discovery_data['end_ip'])
            ip_list = [ipaddress.IPv4Address(ip) for ip in range(int(start_ip), int(end_ip) + 1)]
        else:
            raise HTTPException(status_code=400, detail="Either IP range or start/end IPs must be provided")
            
        print(f"Using IP range: {ip_list[0]}-{ip_list[-1]}")
        print(f"Using company_id {company_id} from owner's record")
        print(f"Scanning IP range: {ip_list[0]} to {ip_list[-1]}, total IPs: {len(ip_list)}")
        
        # For each IP in the range
        for ip in ip_list:
            try:
                print(f"Scanning device at {ip}")
                
                # Check ping
                ping_ok = check_ping(str(ip))
                print(f"[PING] {ip} -> {'✅' if ping_ok else '❌'}")
                
                if ping_ok:
                    # Create SNMP config object
                    device_snmp = DeviceSNMP(
                        snmp_version=snmp_config['version'],
                        community=snmp_config['community'],
                        username=snmp_config['username'],
                        auth_protocol=snmp_config['auth_protocol'],
                        auth_password=snmp_config['auth_password'],
                        priv_protocol=snmp_config['priv_protocol'],
                        priv_password=snmp_config['priv_password'],
                        port=snmp_config['port']
                    )
                    
                    # Check SNMP
                    snmp_ok, snmp_info = check_snmp(str(ip), device_snmp)
                    print(f"[SNMP] {ip} -> {'✅' if snmp_ok else '❌'}")
                    
                    if snmp_ok:
                        # Get detailed device info via SNMP
                        device_info = get_device_info_snmp(str(ip), device_snmp)
                        
                        if device_info:
                            # Clean up device name by removing .test and .Test suffixes
                            hostname = device_info['hostname'].replace('.test', '').replace('.Test', '')
                            
                            # Create or update device
                            device = Device(
                                ip_address=str(ip),
                                hostname=hostname,  # Use cleaned hostname
                                device_type='cisco_ios',  # Default to cisco_ios
                                location=device_info['location'],
                                os_version=device_info['os_version'],
                                serial_number=device_info['serial_number'],
                                model=device_info['model'],
                                ping_status=True,
                                snmp_status=True,
                                network_id=network_id,
                                company_id=company_id,
                                username=discovery_data.get('username'),  # Store SSH credentials for other tabs
                                password=discovery_data.get('password'),   # Store SSH credentials for other tabs
                                discovery_method='auto'  # Set discovery method for auto-discovery
                            )
                            device.snmp_config = json.dumps(device_snmp.dict())  # Convert to JSON string
                            
                            db.add(device)
                            db.commit()
                            db.refresh(device)
                            
                            # Create success log with cleaned hostname
                            log = DeviceLog(
                                ip_address=str(ip),
                                log_type=LogType.UNKNOWN_DEVICE.value,
                                message=f"Successfully discovered device: {hostname} ({device_info['model']})",  # Use cleaned hostname
                                network_id=network_id,
                                company_id=company_id
                            )
                            db.add(log)
                            db.commit()
                            
                            print(f"Successfully discovered device {ip}")
                            continue
                
                # If we get here, either ping failed or SNMP failed
                if not ping_ok:
                    log_type = LogType.UNREACHABLE.value
                    message = f"Device at {ip} is unreachable"
                else:
                    log_type = LogType.UNKNOWN_DEVICE.value
                    message = f"SNMP authentication failed for {ip}"
                
                log = DeviceLog(
                    ip_address=str(ip),
                    log_type=log_type,
                    message=message,
                    network_id=network_id,
                    company_id=company_id
                )
                db.add(log)
                db.commit()
                
            except Exception as e:
                print(f"Error processing device {ip}: {str(e)}")
                continue
        
        return {"status": "success", "message": "Discovery completed"}
        
    except Exception as e:
        print(f"Error in discover_device: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

async def run_discovery(
    network_id: int,
    start_ip: str,
    end_ip: str,
    username: str,
    password: str,
    device_type: str,
    db: Session,
    owner_id: int,
    snmp_config: dict = None
):
    try:
        # Get network details and validate access
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")
        
        # Get organization
        organization = db.query(Organization).filter(Organization.id == network.organization_id).first()
        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Get owner information and company_id
        owner = db.query(User).filter(User.id == organization.owner_id).first()
        if not owner:
            raise HTTPException(status_code=404, detail="Organization owner not found")
            
        company_id = owner.company_id
        owner_id = owner.id  # Store owner_id for later use
        if not company_id:
            raise HTTPException(status_code=400, detail="Owner's company_id not found")
        print(f"Using company_id {company_id} from owner's record")

        # Generate list of IPs to scan
        start = ipaddress.IPv4Address(start_ip)
        end = ipaddress.IPv4Address(end_ip)
        ip_list = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

        total_ips = len(ip_list)
        print(f"Scanning IP range: {start_ip} to {end_ip}, total IPs: {total_ips}")
        
        # Initialize discovery status
        discovery_status[network_id] = DiscoveryStatus(
            total_ips=total_ips,
            scanned_ips=0,
            discovered_devices=0,
            status="in_progress"
        )

        # Create tasks for all IPs with controlled concurrency
        semaphore = asyncio.Semaphore(5)  # Limit concurrent scans to 5
        
        async def scan_with_semaphore(semaphore, ip_address, username, password, device_type, network_id, company_id, db, owner_id, snmp_config):
            async with semaphore:
                result = await scan_single_device(
                    ip_address=ip_address,
                    username=username,
                    password=password,
                    device_type=device_type,
                    network_id=network_id,
                    company_id=company_id,
                    db=db,
                    owner_id=owner_id,
                    snmp_config=snmp_config
                )
                result["ip"] = ip_address
                return result
        
        # Scan devices concurrently
        tasks = [scan_with_semaphore(semaphore, ip, username, password, device_type, network_id, company_id, db, owner_id, snmp_config) for ip in ip_list]
        results = await asyncio.gather(*tasks)
        
        # Process results and update database
        discovered_count = 0
        for result in results:
            discovery_status[network_id].scanned_ips += 1
            
            if result["status"] == "success":
                discovered_count += 1
                discovery_status[network_id].discovered_devices = discovered_count
                try:
                    # Check if device already exists
                    existing_device = db.query(Device).filter(
                        Device.ip == result["ip"],
                        Device.network_id == network_id
                    ).first()
                    
                    if existing_device:
                        print(f"Updating existing device {result['ip']}")
                        existing_device.name = result["hostname"]
                        existing_device.type = result["model"] if result["model"] else device_type
                        existing_device.platform = result["platform"]
                        existing_device.username = username
                        existing_device.password = password
                        existing_device.is_active = True
                        existing_device.os_version = result.get("os_version")
                        existing_device.serial_number = result.get("serial_number")
                        existing_device.ping_status = result.get("ping_status")
                        existing_device.snmp_status = result.get("snmp_status")
                        # Don't update discovery_method if it's already set to 'auto'
                        if existing_device.discovery_method != 'auto':
                            existing_device.discovery_method = 'auto'
                        db.add(existing_device)
                    else:
                        print(f"Creating new device {result['ip']}")
                        new_device = Device(
                            name=result["hostname"],
                            ip=result["ip"],
                            type=result["model"] if result["model"] else device_type,
                            platform=result["platform"],
                            username=username,
                            password=password,
                            network_id=network_id,
                            company_id=company_id,
                            owner_id=owner_id,
                            location='Default',
                            is_active=True,
                            os_version=result.get("os_version"),
                            serial_number=result.get("serial_number"),
                            ping_status=result.get("ping_status"),
                            snmp_status=result.get("snmp_status"),
                            discovery_method='auto'  # Set discovery method for auto-discovery
                        )
                        db.add(new_device)
                    
                    try:
                        db.commit()
                        print(f"Successfully saved device {result['ip']} to database")
                    except Exception as commit_error:
                        print(f"Error committing device {result['ip']}: {str(commit_error)}")
                        db.rollback()
                    
                except Exception as db_error:
                    print(f"Error saving device {result['ip']} to database: {str(db_error)}")
                    db.rollback()
            else:
                print(f"Device {result['ip']} not reachable: {result['message']}")
        
        # Update final status
        discovery_status[network_id].status = "completed"
        discovery_status[network_id].scanned_ips = total_ips
        discovery_status[network_id].discovered_devices = discovered_count
        
        # Save final status to database
        try:
            network = db.query(Network).filter(Network.id == network_id).first()
            if network:
                network.last_discovery_status = json.dumps({
                    "total_ips": total_ips,
                    "scanned_ips": total_ips,
                    "discovered_devices": discovered_count,
                    "status": "completed",
                    "error": None
                })
                db.commit()
        except Exception as e:
            print(f"Error saving final discovery status: {str(e)}")
            db.rollback()
        
        return {"message": f"Discovery completed. Found {discovered_count} devices."}
        
    except Exception as e:
        discovery_status[network_id].status = "failed"
        discovery_status[network_id].error = str(e)
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{device_id}/snmp", response_model=DeviceSNMPSchema)
def configure_device_snmp(
    device_id: int,
    snmp_config: DeviceSNMPCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Configure SNMP for a device."""
    # Check if device exists and user has access
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Check network access
    network = check_network_access(db, current_user, device.network_id)
    if not network:
        raise HTTPException(status_code=403, detail="Not authorized to configure this device")

    # Create or update SNMP configuration
    existing_snmp = db.query(DeviceSNMPModel).filter(DeviceSNMPModel.device_id == device_id).first()
    if existing_snmp:
        for key, value in snmp_config.dict(exclude={'device_id'}).items():
            setattr(existing_snmp, key, value)
        existing_snmp.updated_at = datetime.utcnow()
        db.add(existing_snmp)
    else:
        new_snmp = DeviceSNMPModel(**snmp_config.dict())
        db.add(new_snmp)

    try:
        db.commit()
        db.refresh(existing_snmp if existing_snmp else new_snmp)
        return existing_snmp if existing_snmp else new_snmp
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/{device_id}/snmp", response_model=DeviceSNMPSchema)
def get_device_snmp(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get SNMP configuration for a device."""
    # Check if device exists and user has access
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    # Check network access
    network = check_network_access(db, current_user, device.network_id)
    if not network:
        raise HTTPException(status_code=403, detail="Not authorized to view this device")

    # Get SNMP configuration
    snmp_config = db.query(DeviceSNMPModel).filter(DeviceSNMPModel.device_id == device_id).first()
    if not snmp_config:
        raise HTTPException(status_code=404, detail="SNMP configuration not found")

    return snmp_config

@router.get("/status/refresh-status/{session_id}")
async def get_status_refresh_status(
    session_id: str,
    network_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check the status of a status refresh session"""
    try:
        print(f"[STATUS] Checking status for session: {session_id}")
        
        # Get all devices in the network
        devices = db.query(Device).filter(Device.network_id == network_id).all()
        
        # Check if any devices have been updated recently (within last 30 seconds)
        now = datetime.utcnow()
        recently_updated_devices = []
        
        for device in devices:
            if device.updated_at:
                time_diff = (now - device.updated_at).total_seconds()
                if time_diff < 30:  # Updated within last 30 seconds
                    recently_updated_devices.append({
                        "id": device.id,
                        "ip": device.ip,
                        "name": device.name,
                        "ping_status": device.ping_status,
                        "snmp_status": device.snmp_status,
                        "updated_at": device.updated_at.isoformat()
                    })
        
        # Check if we have recent updates
        if recently_updated_devices:
            print(f"[STATUS] Found {len(recently_updated_devices)} recently updated devices")
            return {
                "session_id": session_id,
                "status": "completed",
                "updated_devices": recently_updated_devices,
                "total_devices": len(devices),
                "updated_count": len(recently_updated_devices)
            }
        else:
            print(f"[STATUS] No recent updates found for session {session_id}")
            return {
                "session_id": session_id,
                "status": "in_progress",
                "updated_devices": [],
                "total_devices": len(devices),
                "updated_count": 0
            }
            
    except Exception as e:
        print(f"[STATUS] Error checking status refresh status: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/status/{device_id}/refresh-agent")
async def refresh_device_status_agent(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Force refresh the status of a device using agent"""
    try:
        device = db.query(Device).filter(Device.id == device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")

        # Get the network ID for this device
        network_id = device.network_id
        
        # Get available agents for this network
        from app.api.v1.endpoints.agents import get_available_agents_for_network
        agents_response = await get_available_agents_for_network(network_id, current_user, db)
        agents = agents_response.get("available_agents", [])
        
        if not agents:
            return {
                "message": "No agents available for status testing",
                "status": "no_agents",
                "ping": False,
                "snmp": False,
                "ip": device.ip,
                "last_checked": datetime.utcnow().isoformat()
            }
        
        # Use the first available agent
        agent = agents[0]
        agent_id = agent['id']
        
        # Create a session ID for tracking this status refresh
        import uuid
        session_id = f"single_status_{uuid.uuid4().hex[:8]}"
        
        # Prepare device data for agent
        device_data = []
        
        # Check if device has SNMP configuration
        snmp_config = None
        if hasattr(device, 'snmp_config') and device.snmp_config:
            snmp_config = {
                'snmp_version': device.snmp_config.snmp_version,
                'community': device.snmp_config.community,
                'port': device.snmp_config.port
            }
        
        device_info = {
            'ip': device.ip,
            'snmp_config': snmp_config
        }
        device_data.append(device_info)
        
        # Store status test request for agent to pick up
        try:
            from app.api.v1.endpoints.agents import pending_discovery_requests
            
            status_request = {
                "type": "status_test",
                "session_id": session_id,
                "network_id": network_id,
                "devices": device_data,
                "timestamp": datetime.utcnow().isoformat()
            }
            
            pending_discovery_requests[agent_id] = status_request
            print(f"[SINGLE STATUS] Stored status test request for device {device.ip}")
            
        except Exception as e:
            print(f"[SINGLE STATUS] Error storing agent status test request: {str(e)}")
        
        return {
            "message": f"Requested agent test for device {device.ip}",
            "status": "requested",
            "session_id": session_id,
            "agent_id": agent_id,
            "ping": device.ping_status,  # Return current status
            "snmp": device.snmp_status,  # Return current status
            "ip": device.ip,
            "last_checked": device.updated_at.isoformat() if device.updated_at else datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"[SINGLE STATUS] Error in refresh_device_status_agent: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
