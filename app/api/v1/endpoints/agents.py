import secrets
import string
import logging
from datetime import datetime, timedelta

# Configure logger
logger = logging.getLogger(__name__)
from typing import List, Optional, Dict
from fastapi import APIRouter, Depends, HTTPException, status, Header, WebSocket, WebSocketDisconnect, Body, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_
import json
import os
import re

from app.core.dependencies import get_current_user
from app.api.deps import get_db
from app.models.base import (
    User, Company, Organization, Network, Agent, AgentNetworkAccess,
    UserOrganizationAccess, UserNetworkAccess, AgentTokenAuditLog
)
from app.models.base import Device
from app.models.topology import DeviceTopology
from app.schemas.base import (
    AgentCreate, AgentUpdate, AgentResponse, AgentRegistration,
    AgentHeartbeat, DiscoveryRequest, DiscoveryResponse, AgentTokenAuditLogResponse
)
from app.schemas.base import AgentDiscoveryRequest

router = APIRouter()

# Global storage for discovery sessions and pending requests
discovery_sessions = {}
pending_discovery_requests = {}


def generate_agent_token(length: int = 32) -> str:
    """Generate a secure random token for agent authentication."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def validate_user_organization_access(user: User, organization_id: int, db: Session) -> bool:
    """Validate that user has access to the organization."""
    if user.role == "superadmin":
        return True
    
    # Check if user owns the organization
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if org and org.owner_id == user.id:
        return True
    
    # Check if user has explicit access to the organization
    access = db.query(UserOrganizationAccess).filter(
        and_(
            UserOrganizationAccess.user_id == user.id,
            UserOrganizationAccess.organization_id == organization_id
        )
    ).first()
    
    return access is not None


def validate_user_network_access(user: User, network_id: int, db: Session) -> bool:
    """Validate that user has access to the network."""
    if user.role == "superadmin":
        return True
    
    # Check if user has explicit access to the network
    access = db.query(UserNetworkAccess).filter(
        and_(
            UserNetworkAccess.user_id == user.id,
            UserNetworkAccess.network_id == network_id
        )
    ).first()
    
    if access:
        return True
    
    # Check if user owns the organization that contains this network
    network = db.query(Network).filter(Network.id == network_id).first()
    if network:
        return validate_user_organization_access(user, network.organization_id, db)
    
    return False


# Utility: log agent token event
def log_agent_token_event(db, agent_id, event, user_id=None, ip_address=None, details=None):
    from app.models.base import AgentTokenAuditLog
    audit = AgentTokenAuditLog(
        agent_id=agent_id,
        event_type=event,
        timestamp=datetime.utcnow(),
        user_id=user_id,
        ip_address=ip_address,
        details=details or {}
    )
    db.add(audit)
    db.commit()


@router.post("/register", response_model=AgentResponse)
async def register_agent(
    agent_data: AgentRegistration,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Register a new agent for an organization."""
    try:
        # Get user from database
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can register agents
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company_admin and full_control users can register agents."
            )
        
        company_id = user.company_id
        
        # Validate organization belongs to the company
        org = db.query(Organization).filter(Organization.id == agent_data.organization_id).first()
        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")
        
        # Check if organization belongs to the company
        org_owner = db.query(User).filter(User.id == org.owner_id).first()
        if not org_owner or org_owner.company_id != company_id:
            raise HTTPException(
                status_code=403,
                detail="Organization does not belong to your company"
            )
        
        # Validate networks belong to the organization
        networks = db.query(Network).filter(
            and_(
                Network.id.in_(agent_data.networks),
                Network.organization_id == agent_data.organization_id
            )
        ).all()
        
        if len(networks) != len(agent_data.networks):
            raise HTTPException(
                status_code=400,
                detail="Some networks do not belong to the specified organization"
            )
        
        # Generate secure agent token
        agent_token = generate_agent_token()
        now = datetime.utcnow()
        
        # Create agent - use company_id from token
        agent = Agent(
            name=agent_data.name,
            company_id=company_id,
            organization_id=agent_data.organization_id,
            agent_token=agent_token,
            capabilities=agent_data.capabilities,
            version=agent_data.version,
            status="offline",
            token_status="active",
            scopes=["monitoring", "heartbeat"],
            issued_at=now,
            created_by=user.id
        )
        
        db.add(agent)
        db.flush()  # Get the agent ID
        
        # Create network access records
        for network_id in agent_data.networks:
            network_access = AgentNetworkAccess(
                agent_id=agent.id,
                network_id=network_id,
                company_id=company_id,
                organization_id=agent_data.organization_id
            )
            db.add(network_access)
        
        db.commit()
        db.refresh(agent)
        
        # Log issuance
        log_agent_token_event(db, agent.id, event="issued", user_id=user.id)
        return agent
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error registering agent: {str(e)}")


# Removed duplicate user-authenticated heartbeat endpoint - keeping only agent-authenticated version below


# Agent-specific routes (must come before generic routes to avoid conflicts)

@router.get("/agent/organizations", response_model=List[dict])
async def get_agent_organizations(
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Get organizations accessible to the agent."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        if agent.token_status != "active":
            raise HTTPException(status_code=401, detail="Agent token is not active")
        
        # Get organizations the agent has access to
        # Since Organization doesn't have company_id, we need to get organizations
        # that belong to users in the same company as the agent
        organizations = db.query(Organization).join(User).filter(
            User.company_id == agent.company_id
        ).all()
        
        # Log the access
        log_agent_token_event(db, agent.id, "organizations_accessed")
        
        return [
            {
                "id": org.id,
                "name": org.name
            }
            for org in organizations
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/agent/networks", response_model=List[dict])
async def get_agent_networks(
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Get networks accessible to the agent."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        if agent.token_status != "active":
            raise HTTPException(status_code=401, detail="Agent token is not active")
        
        # Get networks the agent has access to
        networks = db.query(Network).filter(
            Network.organization_id == agent.organization_id
        ).all()
        
        # Log the access
        log_agent_token_event(db, agent.id, "networks_accessed")
        
        return [
            {
                "id": network.id,
                "name": network.name,
                "organization_id": network.organization_id
            }
            for network in networks
        ]
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/status")
async def update_agent_status(
    status_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Update agent status via HTTP (Cloud Run compatible)"""
    try:
        
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        if agent.token_status != "active":
            raise HTTPException(status_code=401, detail="Agent token is not active")
        
        # Update agent status
        agent.status = status_data.get("status", "unknown")
        agent.last_heartbeat = datetime.utcnow()
        agent.last_used_at = datetime.utcnow()
        
        # Update additional fields if provided
        if "agent_name" in status_data:
            agent.agent_name = status_data["agent_name"]
        if "discovered_devices_count" in status_data:
            agent.discovered_devices_count = status_data["discovered_devices_count"]
        if "system_info" in status_data:
            agent.system_info = status_data["system_info"]
        
        db.commit()
        
        # Log the status update
        log_agent_token_event(db, agent.id, "status_updated", details={"status": status_data.get("status")})
        
        return {"message": "Status updated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/heartbeat")
async def agent_heartbeat(
    heartbeat_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Handle agent heartbeat via HTTP (Cloud Run compatible)"""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        if agent.token_status != "active":
            raise HTTPException(status_code=401, detail="Agent token is not active")
        
        # Update agent heartbeat
        agent.last_heartbeat = datetime.utcnow()
        agent.last_used_at = datetime.utcnow()
        agent.status = "online"
        
        # Update additional fields if provided
        if "agent_name" in heartbeat_data:
            agent.agent_name = heartbeat_data["agent_name"]
        if "discovered_devices_count" in heartbeat_data:
            agent.discovered_devices_count = heartbeat_data["discovered_devices_count"]
        if "system_info" in heartbeat_data:
            agent.system_info = heartbeat_data["system_info"]
        
        db.commit()
        
        # Log the heartbeat
        log_agent_token_event(db, agent.id, "heartbeat_received")
        
        return {"message": "Heartbeat received", "timestamp": datetime.utcnow().isoformat()}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/pong")
async def agent_pong(
    pong_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Handle agent pong response via HTTP (Cloud Run compatible)"""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        if agent.token_status != "active":
            raise HTTPException(status_code=401, detail="Agent token is not active")
        
        # Update agent last activity
        agent.last_heartbeat = datetime.utcnow()
        agent.last_used_at = datetime.utcnow()
        
        db.commit()
        
        # Log the pong
        log_agent_token_event(db, agent.id, "pong_received")
        
        return {"message": "Pong received", "timestamp": datetime.utcnow().isoformat()}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


# User-specific routes (must come after agent-specific routes)

@router.post("/test-auth", response_model=dict)
async def test_agents_post(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Temporary POST endpoint to test dependency injection and logging."""
    return {"status": "success", "user": current_user}


@router.post("/auth-debug", response_model=dict)
async def test_agents_auth_debug(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Temporary POST endpoint to test dependency injection and logging (unique path)."""
    return {"status": "success", "user": current_user}


@router.get("/auth-debug", response_model=dict)
async def test_agents_auth_debug_get(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Temporary GET endpoint to test dependency injection and logging (unique path)."""
    return {"status": "success", "user": current_user}


@router.get("/all", response_model=List[AgentResponse])
async def get_agents(
    organization_id: Optional[int] = None,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get agents for the user's accessible organizations."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        query = db.query(Agent)
        
        if user.role != "superadmin":
            if user.company_id:
                query = query.filter(Agent.company_id == user.company_id)
            
            if organization_id:
                # Validate access to specific organization
                if not validate_user_organization_access(user, organization_id, db):
                    raise HTTPException(
                        status_code=403,
                        detail="No access to this organization"
                    )
                query = query.filter(Agent.organization_id == organization_id)
            else:
                # Get all organizations user has access to
                accessible_orgs = []
                
                # Organizations user owns
                owned_orgs = db.query(Organization).filter(Organization.owner_id == user.id).all()
                accessible_orgs.extend([org.id for org in owned_orgs])
                
                # Organizations user has access to
                org_access = db.query(UserOrganizationAccess).filter(
                    UserOrganizationAccess.user_id == user.id
                ).all()
                accessible_orgs.extend([access.organization_id for access in org_access])
                
                if accessible_orgs:
                    query = query.filter(Agent.organization_id.in_(accessible_orgs))
                else:
                    return []
        
        agents = query.all()
        
        # Calculate real-time status for each agent
        current_time = datetime.utcnow()
        for agent in agents:
            # Consider agent offline if no heartbeat in last 1 minute (for testing)
            if agent.last_heartbeat:
                time_diff = current_time - agent.last_heartbeat
                if time_diff.total_seconds() > 60:  # 1 minute (for testing)
                    agent.status = "offline"
                else:
                    agent.status = "online"
            else:
                agent.status = "offline"
        
        return agents
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agents: {str(e)}")


@router.get("/test-download/{agent_id}")
async def test_download_agent(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Test download endpoint."""
    return {"message": f"Test download endpoint working for agent {agent_id}", "user": current_user}

@router.get("/simple-test")
async def simple_test():
    """Simple test endpoint without authentication."""
    return {"message": "Simple test endpoint working"}


@router.get("/download-agent/{agent_id}")
async def download_agent_files(
    request: Request,
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Get the agent
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Check user access
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    if not validate_user_organization_access(user, agent.organization_id, db):
        raise HTTPException(status_code=403, detail="Not authorized to access this agent")
    
    # Create a deployment package
    import os
    import zipfile
    import tempfile
    import json
    import shutil
    import logging
    from fastapi.responses import FileResponse
    
    logger = logging.getLogger(__name__)
    
    # Get the base directory - try multiple possible paths
    possible_paths = [
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),  # Original path
        "/app",  # Cloud Run working directory
        os.getcwd(),  # Current working directory
        os.path.dirname(os.path.abspath(__file__)),  # Current file directory
    ]
    
    # Create temporary directory for the package
    temp_dir = tempfile.mkdtemp()
    package_dir = os.path.join(temp_dir, f"cisco_ai_agent_{agent.name.replace(' ', '_')}")
    os.makedirs(package_dir, exist_ok=True)
    
    # Try to find the agent file in multiple locations
    agent_py_content = None
    agent_file_path = None
    
    for base_dir in possible_paths:
        try:
            test_path = os.path.join(base_dir, "cisco_ai_agent.py")
            logger.info(f"Trying path: {test_path}")
            logger.info(f"File exists: {os.path.exists(test_path)}")
            
            if os.path.exists(test_path):
                with open(test_path, 'r', encoding='utf-8') as f:
                    agent_py_content = f.read()
                agent_file_path = test_path
                logger.info(f"Successfully read agent file from: {agent_file_path}")
                logger.info(f"File size: {len(agent_py_content)} characters")
                break
        except Exception as e:
            logger.error(f"Failed to read from {test_path}: {e}")
            continue
    
    if agent_py_content is None:
        logger.error("Failed to find agent file in any location, using fallback")
        # Fallback to inline content if file not found
        agent_py_content = '''#!/usr/bin/env python3
"""
Cisco AI Agent Service
Enhanced multi-vendor device discovery and monitoring
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
import websocket
from pysnmp.hlapi import *
import paramiko
import psutil

# Configure logging with UTF-8 encoding
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cisco_ai_agent.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class CiscoAIAgent:
    """Enhanced multi-vendor agent class for device discovery and monitoring"""
    
    def __init__(self, config_path: str = "agent_config.json"):
        self.config = self.load_config(config_path)
        self.backend_url = self.config['backend_url']
        self.agent_token = self.config['agent_token']
        self.agent_name = self.config['agent_name']
        self.heartbeat_interval = self.config.get('heartbeat_interval', 30)
        
        # WebSocket connection for real-time communication
        self.ws = None
        self.ws_connected = False
        
        # Discovery state
        self.discovered_devices = {}
        self.discovery_running = False
        
        # Service state
        self.running = False
        
        logger.info(f"Initialized Enhanced Cisco AI Agent: {self.agent_name}")
    
    def load_config(self, config_path: str) -> Dict:
        """Load agent configuration"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            # Try alternative config file names
            alternative_paths = ["agent_config.json", "config.json"]
            for alt_path in alternative_paths:
                if alt_path != config_path:
                    try:
                        with open(alt_path, 'r', encoding='utf-8') as f:
                            config = json.load(f)
                        logger.info(f"Configuration loaded successfully from {alt_path}")
                        return config
                    except Exception as alt_e:
                        logger.error(f"Failed to load configuration from {alt_path}: {alt_e}")
                        continue
            
            # If all config files fail, exit
            logger.error("No valid configuration file found. Please ensure agent_config.json exists.")
            sys.exit(1)
    
    def start(self):
        """Start the agent service"""
        logger.info("Starting Cisco AI Agent service")
        
        # Test agent token validity first
        logger.info(f"Testing agent token: {self.agent_token[:10]}...")
        test_response = self.safe_request(
            'GET',
            f"{self.backend_url}/api/v1/agents/agent/organizations",
            headers={'X-Agent-Token': self.agent_token}
        )
        
        if not test_response or test_response.status_code != 200:
            logger.error(f"Agent token validation failed. Status: {test_response.status_code if test_response else 'No response'}")
            if test_response:
                try:
                    error_detail = test_response.json().get('detail', 'Unknown error')
                    logger.error(f"Error detail: {error_detail}")
                except:
                    logger.error(f"Response text: {test_response.text}")
            logger.error("Please check your agent token in the frontend and ensure it's active.")
            return
        
        logger.info("Agent token validation successful")
        self.running = True
        
        # Start WebSocket connection
        self.start_websocket()
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Main service loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            self.stop()
    
    def stop(self):
        """Stop the agent service"""
        logger.info("Stopping Cisco AI Agent service")
        self.running = False
        
        if self.ws:
            self.ws.close()
        
        # Update status to offline
        self.update_status("offline")
    
    def start_websocket(self):
        """Start HTTP polling instead of WebSocket (Cloud Run doesn't support WebSocket)"""
        try:
            logger.info("Starting HTTP polling mode (Cloud Run compatible)")
            self.ws_connected = True  # Simulate connection for compatibility
            self.update_status("online")
            
            # Start polling thread
            polling_thread = threading.Thread(target=self.polling_loop, daemon=True)
            polling_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start HTTP polling: {e}")
    
    def polling_loop(self):
        """HTTP polling loop to check for commands from backend"""
        while self.running:
            try:
                # Check for any pending commands from backend
                self.check_for_commands()
                time.sleep(30)  # Poll every 30 seconds
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                time.sleep(60)  # Wait longer on error
    
    def check_for_commands(self):
        """Check for any commands from the backend"""
        try:
            # Check for discovery requests from backend
            self.check_for_discovery_requests()
            
            # Send heartbeat
            self.send_heartbeat_http()
        except Exception as e:
            logger.error(f"Error checking for commands: {e}")
    
    def check_for_discovery_requests(self):
        """Check for discovery requests from backend"""
        try:
            # Get pending discovery requests for this agent
            response = self.safe_request(
                'GET',
                f"{self.backend_url}/api/v1/agents/{self.config['agent_id']}/pending-discovery",
                headers={'X-Agent-Token': self.agent_token}
            )
            
            if response and response.status_code == 200:
                discovery_requests = response.json()
                for request in discovery_requests:
                    self.handle_enhanced_discovery_request(request)
                    
        except Exception as e:
            logger.error(f"Error checking for discovery requests: {e}")
    
    def handle_enhanced_discovery_request(self, request_data: Dict):
        """Handle enhanced discovery request with SNMP configuration"""
        try:
            session_id = request_data.get('session_id')
            network_id = request_data.get('network_id')
            discovery_method = request_data.get('discovery_method', {})
            credentials = request_data.get('credentials', {})
            ip_range = request_data.get('ip_range')
            start_ip = request_data.get('start_ip')
            end_ip = request_data.get('end_ip')
            
            logger.info(f"Received enhanced discovery request: session_id={session_id}, network_id={network_id}")
            
            # Start discovery in background thread
            discovery_thread = threading.Thread(
                target=self.start_enhanced_discovery,
                args=(session_id, network_id, discovery_method, credentials, ip_range, start_ip, end_ip),
                daemon=True
            )
            discovery_thread.start()
            
        except Exception as e:
            logger.error(f"Error handling enhanced discovery request: {e}")
    
    def start_enhanced_discovery(self, session_id: str, network_id: int, discovery_method: Dict, 
                                credentials: Dict, ip_range: str = None, start_ip: str = None, end_ip: str = None):
        """Start enhanced device discovery with SNMP configuration"""
        try:
            self.discovery_running = True
            logger.info(f"Starting enhanced discovery for session: {session_id}")
            
            # Notify backend that discovery started
            self.notify_enhanced_discovery_status(session_id, 'started')
            
            # Parse IP range
            ip_list = self.parse_ip_range(ip_range, start_ip, end_ip)
            total_ips = len(ip_list)
            discovered_devices = []
            errors = []
            
            # Perform discovery based on method
            method = discovery_method.get('method', 'auto')
            
            for i, ip_address in enumerate(ip_list):
                try:
                    # Update progress
                    progress = int((i / total_ips) * 100)
                    self.notify_enhanced_discovery_progress(session_id, progress, i, len(discovered_devices))
                    
                    device_info = None
                    
                    if method == 'snmp_only' or method == 'auto':
                        device_info = self.enhanced_snmp_discovery(ip_address, discovery_method, credentials)
                    
                    if not device_info and (method == 'ssh_only' or method == 'auto'):
                        device_info = self.enhanced_ssh_discovery(ip_address, credentials)
                    
                    if not device_info and method == 'ping_only':
                        device_info = self.ping_discovery(ip_address)
                    
                    if device_info:
                        device_info['discovered_by_agent'] = self.config['agent_id']
                        device_info['discovered_at'] = datetime.now().isoformat()
                        device_info['session_id'] = session_id
                        discovered_devices.append(device_info)
                        
                except Exception as e:
                    error_msg = f"Error discovering {ip_address}: {str(e)}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            
            # Send results to backend
            self.send_enhanced_discovery_results(session_id, discovered_devices, errors)
            
            # Notify completion
            self.notify_enhanced_discovery_status(session_id, 'completed', len(discovered_devices))
            
        except Exception as e:
            logger.error(f"Error during enhanced discovery: {e}")
            self.notify_enhanced_discovery_status(session_id, 'failed', error=str(e))
        finally:
            self.discovery_running = False
    
    def parse_ip_range(self, ip_range: str = None, start_ip: str = None, end_ip: str = None) -> List[str]:
        """Parse IP range into list of IP addresses"""
        ip_list = []
        
        if ip_range:
            # Handle CIDR notation (e.g., 192.168.1.0/24)
            if '/' in ip_range:
                ip_list = self.cidr_to_ip_list(ip_range)
            # Handle range notation (e.g., 192.168.1.1-192.168.1.10)
            elif '-' in ip_range:
                start, end = ip_range.split('-')
                ip_list = self.ip_range_to_list(start.strip(), end.strip())
            # Single IP
            else:
                ip_list = [ip_range.strip()]
        elif start_ip and end_ip:
            ip_list = self.ip_range_to_list(start_ip, end_ip)
        
        return ip_list
    
    def cidr_to_ip_list(self, cidr: str) -> List[str]:
        """Convert CIDR notation to list of IP addresses"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(cidr, strict=False)
            return [str(ip) for ip in network.hosts()]
        except Exception as e:
            logger.error(f"Error parsing CIDR {cidr}: {e}")
            return []
    
    def ip_range_to_list(self, start_ip: str, end_ip: str) -> List[str]:
        """Convert IP range to list of IP addresses"""
        try:
            import ipaddress
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            
            ip_list = []
            current = start
            while current <= end:
                ip_list.append(str(current))
                current += 1
            
            return ip_list
        except Exception as e:
            logger.error(f"Error parsing IP range {start_ip}-{end_ip}: {e}")
            return []
    
    def enhanced_snmp_discovery(self, ip_address: str, discovery_method: Dict, credentials: Dict) -> Optional[Dict]:
        """Enhanced SNMP discovery with full SNMPv3 support"""
        try:
            snmp_config = discovery_method.get('snmp_config', {})
            snmp_version = discovery_method.get('snmp_version', 'v2c')
            snmp_community = discovery_method.get('snmp_community', 'public')
            snmp_port = discovery_method.get('snmp_port', 161)
            
            if snmp_version == 'v3':
                return self.snmpv3_get_device_info(ip_address, snmp_config, snmp_port)
            else:
                return self.snmpv1v2c_get_device_info(ip_address, snmp_community, snmp_port, snmp_version)
                
        except Exception as e:
            logger.debug(f"Enhanced SNMP discovery failed for {ip_address}: {e}")
            return None
    
    def snmpv3_get_device_info(self, ip_address: str, snmp_config: Dict, port: int = 161) -> Optional[Dict]:
        """Get device information via SNMPv3"""
        try:
            security_level = snmp_config.get('security_level', 'noAuthNoPriv')
            username = snmp_config.get('username', '')
            auth_protocol = snmp_config.get('auth_protocol')
            auth_password = snmp_config.get('auth_password')
            priv_protocol = snmp_config.get('priv_protocol')
            priv_password = snmp_config.get('priv_password')
            
            # Create SNMPv3 user
            if security_level == 'noAuthNoPriv':
                user_data = UsmUserData(username)
            elif security_level == 'authNoPriv':
                user_data = UsmUserData(username, authProtocol=self.get_auth_protocol(auth_protocol), authKey=auth_password)
            else:  # authPriv
                user_data = UsmUserData(
                    username, 
                    authProtocol=self.get_auth_protocol(auth_protocol), 
                    authKey=auth_password,
                    privProtocol=self.get_priv_protocol(priv_protocol),
                    privKey=priv_password
                )
            
            # SNMP OIDs to query
            oids = [
                '1.3.6.1.2.1.1.1.0',  # sysDescr
                '1.3.6.1.2.1.1.5.0',  # sysName
                '1.3.6.1.2.1.1.6.0',  # sysLocation
                '1.3.6.1.2.1.1.4.0',  # sysContact
                '1.3.6.1.2.1.1.2.0',  # sysObjectID
                '1.3.6.1.2.1.1.3.0',  # sysUpTime
            ]
            
            # Query device
            for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
                SnmpEngine(),
                user_data,
                UdpTransportTarget((ip_address, port), timeout=3, retries=1),
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
                lexicographicMode=False,
                maxRows=0
            ):
                if errorIndication:
                    error_msg = str(errorIndication).lower()
                    if 'timeout' in error_msg:
                        logger.debug(f"SNMPv3 timeout for {ip_address}: {errorIndication}")
                    elif 'no response' in error_msg:
                        logger.debug(f"SNMPv3 no response from {ip_address}: {errorIndication}")
                    elif 'authentication' in error_msg or 'username' in error_msg:
                        logger.debug(f"SNMPv3 authentication failed for {ip_address}: {errorIndication}")
                    else:
                        logger.debug(f"SNMPv3 error indication for {ip_address}: {errorIndication}")
                    return None
                if errorStatus:
                    logger.debug(f"SNMPv3 error status for {ip_address}: {errorStatus.prettyPrint()}")
                    return None
                
                # Extract device information
                description = str(varBinds[0][1]) if varBinds and varBinds[0][1] else ''
                hostname = str(varBinds[1][1]) if len(varBinds) > 1 and varBinds[1][1] else ip_address
                location = str(varBinds[2][1]) if len(varBinds) > 2 and varBinds[2][1] else 'Unknown'
                contact = str(varBinds[3][1]) if len(varBinds) > 3 and varBinds[3][1] else 'Unknown'
                uptime = str(varBinds[5][1]) if len(varBinds) > 5 and varBinds[5][1] else 'Unknown'
                
                device_info = {
                    'ip_address': ip_address,
                    'hostname': hostname,
                    'description': description,
                    'location': self.extract_device_location(description, location),
                    'contact': self.extract_device_contact(description, contact),
                    'object_id': str(varBinds[4][1]) if len(varBinds) > 4 and varBinds[4][1] else 'Unknown',
                    'uptime': self.extract_device_uptime(uptime),
                    'device_type': self.detect_device_type(description),
                    'os_version': self.extract_os_version(description),
                    'serial_number': self.extract_serial_number(description),
                    'discovery_method': 'snmp',
                    'snmp_version': 'v3',
                    'capabilities': ['snmp']
                }
                
                return device_info
                
        except Exception as e:
            logger.debug(f"SNMPv3 query failed for {ip_address}: {e}")
            return None
    
    def snmpv1v2c_get_device_info(self, ip_address: str, community: str, port: int = 161, snmp_version: str = 'v2c') -> Optional[Dict]:
        """Get device information via SNMPv1/v2c"""
        try:
            # SNMP OIDs to query
            oids = [
                '1.3.6.1.2.1.1.1.0',  # sysDescr
                '1.3.6.1.2.1.1.5.0',  # sysName
                '1.3.6.1.2.1.1.6.0',  # sysLocation
                '1.3.6.1.2.1.1.4.0',  # sysContact
                '1.3.6.1.2.1.1.2.0',  # sysObjectID
                '1.3.6.1.2.1.1.3.0',  # sysUpTime
            ]
            
            # Set mpModel based on SNMP version (0 for v1, 1 for v2c)
            mp_model = 0 if snmp_version == 'v1' else 1
            
            # Query device
            for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=mp_model),
                UdpTransportTarget((ip_address, port), timeout=3, retries=1),
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
                lexicographicMode=False,
                maxRows=0
            ):
                if errorIndication:
                    error_msg = str(errorIndication).lower()
                    if 'timeout' in error_msg:
                        logger.debug(f"SNMP timeout for {ip_address}: {errorIndication}")
                    elif 'no response' in error_msg:
                        logger.debug(f"SNMP no response from {ip_address}: {errorIndication}")
                    elif 'authentication' in error_msg or 'community' in error_msg:
                        logger.debug(f"SNMP authentication failed for {ip_address}: {errorIndication}")
                    else:
                        logger.debug(f"SNMP error indication for {ip_address}: {errorIndication}")
                    return None
                if errorStatus:
                    logger.debug(f"SNMP error status for {ip_address}: {errorStatus.prettyPrint()}")
                    return None
                
                # Extract device information
                description = str(varBinds[0][1]) if varBinds and varBinds[0][1] else ''
                hostname = str(varBinds[1][1]) if len(varBinds) > 1 and varBinds[1][1] else ip_address
                location = str(varBinds[2][1]) if len(varBinds) > 2 and varBinds[2][1] else 'Unknown'
                contact = str(varBinds[3][1]) if len(varBinds) > 3 and varBinds[3][1] else 'Unknown'
                uptime = str(varBinds[5][1]) if len(varBinds) > 5 and varBinds[5][1] else 'Unknown'
                
                device_info = {
                    'ip_address': ip_address,
                    'hostname': hostname,
                    'description': description,
                    'location': self.extract_device_location(description, location),
                    'contact': self.extract_device_contact(description, contact),
                    'object_id': str(varBinds[4][1]) if len(varBinds) > 4 and varBinds[4][1] else 'Unknown',
                    'uptime': self.extract_device_uptime(uptime),
                    'device_type': self.detect_device_type(description),
                    'os_version': self.extract_os_version(description),
                    'serial_number': self.extract_serial_number(description),
                    'discovery_method': 'snmp',
                    'snmp_version': snmp_version,
                    'community_string': community,
                    'capabilities': ['snmp'],
                    'snmp_config': {
                        'snmp_version': snmp_version,
                        'community': community,
                        'port': port
                    }
                }
                
                return device_info
                
        except Exception as e:
            logger.debug(f"SNMPv1/v2c query failed for {ip_address}: {e}")
            return None
    
    def get_auth_protocol(self, protocol: str):
        """Get SNMPv3 authentication protocol"""
        protocols = {
            'MD5': usmHMACMD5AuthProtocol,
            'SHA': usmHMACSHA1AuthProtocol,
            'SHA224': usmHMAC128SHA224AuthProtocol,
            'SHA256': usmHMAC192SHA256AuthProtocol,
            'SHA384': usmHMAC256SHA384AuthProtocol,
            'SHA512': usmHMAC384SHA512AuthProtocol,
        }
        return protocols.get(protocol, usmHMACMD5AuthProtocol)
    
    def get_priv_protocol(self, protocol: str):
        """Get SNMPv3 privacy protocol"""
        protocols = {
            'DES': usmDESPrivProtocol,
            'AES': usmAESPrivProtocol,
            'AES192': usmAES192PrivProtocol,
            'AES256': usmAES256PrivProtocol,
            'AES192CISCO': usmAES192PrivProtocol,
            'AES256CISCO': usmAES256PrivProtocol,
        }
        return protocols.get(protocol, usmDESPrivProtocol)
    
    def enhanced_ssh_discovery(self, ip_address: str, credentials: Dict) -> Optional[Dict]:
        """Enhanced SSH discovery with better device information extraction"""
        try:
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not username or not password:
                return None
            
            # Try to connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            try:
                ssh.connect(ip_address, username=username, password=password, timeout=5)
                
                # Get device information via SSH commands
                device_info = {
                    'ip_address': ip_address,
                    'discovery_method': 'ssh',
                    'capabilities': ['ssh']
                }
                
                # Get hostname
                try:
                    stdin, stdout, stderr = ssh.exec_command('hostname')
                    hostname = stdout.read().decode().strip()
                    device_info['hostname'] = hostname if hostname else ip_address
                except:
                    device_info['hostname'] = ip_address
                
                # Get system information
                try:
                    stdin, stdout, stderr = ssh.exec_command('uname -a')
                    system_info = stdout.read().decode().strip()
                    device_info['description'] = system_info
                    device_info['device_type'] = self.detect_device_type(system_info)
                    device_info['os_version'] = self.extract_os_version(system_info)
                except:
                    device_info['description'] = 'Unknown'
                    device_info['device_type'] = 'Unknown'
                    device_info['os_version'] = 'Unknown'
                
                # Get location (if available)
                try:
                    stdin, stdout, stderr = ssh.exec_command('cat /etc/location 2>/dev/null || echo "Unknown"')
                    location = stdout.read().decode().strip()
                    device_info['location'] = location if location != 'Unknown' else 'Unknown'
                except:
                    device_info['location'] = 'Unknown'
                
                ssh.close()
                return device_info
                
            except Exception as e:
                logger.debug(f"SSH connection failed for {ip_address}: {e}")
                return None
                
        except Exception as e:
            logger.debug(f"Enhanced SSH discovery failed for {ip_address}: {e}")
            return None
    
    def ping_discovery(self, ip_address: str) -> Optional[Dict]:
        """Simple ping discovery"""
        try:
            # Use ping to check if device is reachable
            result = subprocess.run(['ping', '-c', '1', '-W', '2', ip_address], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                return {
                    'ip_address': ip_address,
                    'hostname': ip_address,
                    'description': 'Pingable device',
                    'location': 'Unknown',
                    'device_type': 'Unknown',
                    'os_version': 'Unknown',
                    'discovery_method': 'ping',
                    'capabilities': ['ping']
                }
            return None
            
        except Exception as e:
            logger.debug(f"Ping discovery failed for {ip_address}: {e}")
            return None
    
    def extract_os_version(self, description: str) -> str:
        """Enhanced OS version extraction from device description"""
        try:
            description_lower = description.lower()
            
            # Cisco IOS
            if 'cisco ios' in description_lower:
                import re
                # Look for IOS version patterns
                patterns = [
                    r'ios.*?version\s+([^\s,]+)',
                    r'ios.*?([0-9]+\.[0-9]+[a-z]*)',
                    r'version\s+([0-9]+\.[0-9]+[a-z]*)'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, description_lower)
                    if match:
                        return f"Cisco IOS {match.group(1)}"
                return "Cisco IOS"
            
            # Cisco IOS-XE
            elif 'ios-xe' in description_lower or 'ios xe' in description_lower:
                import re
                patterns = [
                    r'ios-xe.*?version\s+([^\s,]+)',
                    r'ios-xe.*?([0-9]+\.[0-9]+[a-z]*)',
                    r'xe.*?version\s+([^\s,]+)'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, description_lower)
                    if match:
                        return f"Cisco IOS-XE {match.group(1)}"
                return "Cisco IOS-XE"
            
            # Cisco NX-OS
            elif 'nx-os' in description_lower:
                import re
                patterns = [
                    r'nx-os.*?version\s+([^\s,]+)',
                    r'nx-os.*?([0-9]+\.[0-9]+[a-z]*)'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, description_lower)
                    if match:
                        return f"Cisco NX-OS {match.group(1)}"
                return "Cisco NX-OS"
            
            # Juniper JunOS
            elif 'junos' in description_lower:
                import re
                patterns = [
                    r'junos.*?version\s+([^\s,]+)',
                    r'junos.*?([0-9]+\.[0-9]+[a-z]*)'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, description_lower)
                    if match:
                        return f"Juniper JunOS {match.group(1)}"
                return "Juniper JunOS"
            
            # Linux distributions
            elif any(distro in description_lower for distro in ['ubuntu', 'centos', 'debian', 'redhat', 'fedora']):
                import re
                if 'ubuntu' in description_lower:
                    match = re.search(r'ubuntu.*?([0-9]+\.[0-9]+)', description_lower)
                    if match:
                        return f"Ubuntu {match.group(1)}"
                    return "Ubuntu"
                elif 'centos' in description_lower:
                    match = re.search(r'centos.*?([0-9]+)', description_lower)
                    if match:
                        return f"CentOS {match.group(1)}"
                    return "CentOS"
                elif 'debian' in description_lower:
                    match = re.search(r'debian.*?([0-9]+)', description_lower)
                    if match:
                        return f"Debian {match.group(1)}"
                    return "Debian"
                elif 'redhat' in description_lower:
                    match = re.search(r'redhat.*?([0-9]+)', description_lower)
                    if match:
                        return f"Red Hat {match.group(1)}"
                    return "Red Hat"
                else:
                    return "Linux"
            
            # Windows
            elif 'windows' in description_lower:
                import re
                patterns = [
                    r'windows.*?server.*?([0-9]+)',
                    r'windows.*?([0-9]+\.[0-9]+)',
                    r'win.*?([0-9]+)'
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, description_lower)
                    if match:
                        return f"Windows Server {match.group(1)}"
                return "Windows"
            
            # Generic Linux
            elif 'linux' in description_lower:
                import re
                match = re.search(r'linux.*?([0-9]+\.[0-9]+)', description_lower)
                if match:
                    return f"Linux {match.group(1)}"
                return "Linux"
            
            return "Unknown"
            
        except Exception as e:
            logger.debug(f"Error extracting OS version: {e}")
            return "Unknown"
    
    def extract_serial_number(self, description: str) -> str:
        """Enhanced serial number extraction from device description"""
        try:
            import re
            
            # Look for common serial number patterns
            patterns = [
                # Cisco format: ABC1234DEF5
                r'[A-Z]{3}[0-9]{4}[A-Z0-9]{4}',
                # Generic format: AB12345678
                r'[A-Z]{2}[A-Z0-9]{8}',
                # Numeric format: 123456789012
                r'[0-9]{12}',
                # Short numeric: 12345678
                r'[0-9]{8}',
                # Alphanumeric with dashes: ABC-123-DEF
                r'[A-Z0-9]{3}-[0-9]{3}-[A-Z0-9]{3}',
                # Serial with letters and numbers
                r'[A-Z0-9]{10,}'
            ]
            
            # Search in the entire description
            for pattern in patterns:
                matches = re.findall(pattern, description.upper())
                if matches:
                    # Return the first match that looks like a serial number
                    for match in matches:
                        if len(match) >= 8:  # Minimum length for a serial number
                            return match
            
            # If no pattern found, look for "serial" or "sn" keywords
            serial_keywords = ['serial', 'sn:', 'serial number', 'serial#']
            for keyword in serial_keywords:
                if keyword in description.lower():
                    # Extract text after the keyword
                    import re
                    match = re.search(f'{keyword}[:\s]*([A-Z0-9-]+)', description, re.IGNORECASE)
                    if match:
                        return match.group(1).strip()
            
            return "Unknown"
            
        except Exception as e:
            logger.debug(f"Error extracting serial number: {e}")
            return "Unknown"
    
    def extract_device_location(self, description: str, snmp_location: str = None) -> str:
        """Extract device location from description or SNMP location"""
        try:
            # First try SNMP location if available
            if snmp_location and snmp_location != 'Unknown' and snmp_location.strip():
                return snmp_location.strip()
            
            # Look for location patterns in description
            import re
            location_patterns = [
                r'location[:\s]*([^,\\n]+)',
                r'loc[:\s]*([^,\\n]+)',
                r'building[:\s]*([^,\\n]+)',
                r'floor[:\s]*([^,\\n]+)',
                r'room[:\s]*([^,\\n]+)'
            ]
            
            for pattern in location_patterns:
                match = re.search(pattern, description, re.IGNORECASE)
                if match:
                    location = match.group(1).strip()
                    if location and location != 'Unknown':
                        return location
            
            return "Unknown"
            
        except Exception as e:
            logger.debug(f"Error extracting device location: {e}")
            return "Unknown"
    
    def extract_device_contact(self, description: str, snmp_contact: str = None) -> str:
        """Extract device contact information"""
        try:
            # First try SNMP contact if available
            if snmp_contact and snmp_contact != 'Unknown' and snmp_contact.strip():
                return snmp_contact.strip()
            
            # Look for contact patterns in description
            import re
            contact_patterns = [
                r'contact[:\s]*([^,\\n]+)',
                r'admin[:\s]*([^,\\n]+)',
                r'email[:\s]*([^,\\n]+)',
                r'phone[:\s]*([^,\\n]+)'
            ]
            
            for pattern in contact_patterns:
                match = re.search(pattern, description, re.IGNORECASE)
                if match:
                    contact = match.group(1).strip()
                    if contact and contact != 'Unknown':
                        return contact
            
            return "Unknown"
            
        except Exception as e:
            logger.debug(f"Error extracting device contact: {e}")
            return "Unknown"
    
    def extract_device_uptime(self, snmp_uptime: str = None) -> str:
        """Extract and format device uptime"""
        try:
            if not snmp_uptime or snmp_uptime == 'Unknown':
                return "Unknown"
            
            # Parse SNMP uptime (timeticks)
            import re
            match = re.search(r'(\d+)', snmp_uptime)
            if match:
                timeticks = int(match.group(1))
                # Convert timeticks to days (1 timetick = 1/100 second)
                seconds = timeticks // 100
                days = seconds // 86400
                hours = (seconds % 86400) // 3600
                minutes = (seconds % 3600) // 60
                
                if days > 0:
                    return f"{days}d {hours}h {minutes}m"
                elif hours > 0:
                    return f"{hours}h {minutes}m"
                else:
                    return f"{minutes}m"
            
            return "Unknown"
            
        except Exception as e:
            logger.debug(f"Error extracting device uptime: {e}")
            return "Unknown"
    
    def notify_enhanced_discovery_status(self, session_id: str, status: str, count: int = 0, error: str = None):
        """Notify backend of enhanced discovery status"""
        try:
            status_data = {
                'session_id': session_id,
                'status': status,
                'discovered_count': count,
                'error': error,
                'timestamp': datetime.now().isoformat()
            }
            
            response = self.safe_request(
                'POST',
                f"{self.backend_url}/api/v1/agents/{self.config['agent_id']}/discovery-status",
                headers={'X-Agent-Token': self.agent_token},
                json=status_data
            )
            
            if response and response.status_code == 200:
                logger.info(f"Discovery status notification sent: {status}")
            else:
                logger.warning(f"Failed to send discovery status: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error sending discovery status: {e}")
    
    def notify_enhanced_discovery_progress(self, session_id: str, progress: int, processed_ips: int, discovered_count: int):
        """Notify backend of enhanced discovery progress"""
        try:
            progress_data = {
                'session_id': session_id,
                'progress': progress,
                'processed_ips': processed_ips,
                'discovered_count': discovered_count,
                'timestamp': datetime.now().isoformat()
            }
            
            response = self.safe_request(
                'POST',
                f"{self.backend_url}/api/v1/agents/{self.config['agent_id']}/discovery-progress",
                headers={'X-Agent-Token': self.agent_token},
                json=progress_data
            )
            
            if response and response.status_code == 200:
                logger.debug(f"Discovery progress sent: {progress}%")
            else:
                logger.warning(f"Failed to send discovery progress: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error sending discovery progress: {e}")
    
    def send_enhanced_discovery_results(self, session_id: str, discovered_devices: List[Dict], errors: List[str]):
        """Send enhanced discovery results to backend"""
        try:
            results_data = {
                'session_id': session_id,
                'discovered_devices': discovered_devices,
                'errors': errors,
                'timestamp': datetime.now().isoformat()
            }
            
            response = self.safe_request(
                'POST',
                f"{self.backend_url}/api/v1/agents/{self.config['agent_id']}/discovery-results",
                headers={'X-Agent-Token': self.agent_token},
                json=results_data
            )
            
            if response and response.status_code == 200:
                logger.info(f"Discovery results sent: {len(discovered_devices)} devices, {len(errors)} errors")
            else:
                logger.warning(f"Failed to send discovery results: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error sending discovery results: {e}")
    
    def send_heartbeat_http(self):
        """Send heartbeat via HTTP instead of WebSocket"""
        try:
            heartbeat_data = {
                'type': 'heartbeat',
                'agent_name': self.agent_name,
                'timestamp': datetime.now().isoformat(),
                'status': 'online',
                'discovered_devices_count': len(self.discovered_devices),
                'system_info': self.get_system_info()
            }
            
            # Send heartbeat via HTTP POST
            response = self.safe_request(
                'POST',
                f"{self.backend_url}/api/v1/agents/heartbeat",
                headers={'X-Agent-Token': self.agent_token},
                json=heartbeat_data
            )
            
            if response and response.status_code == 200:
                logger.debug("Heartbeat sent successfully")
            else:
                logger.warning(f"Heartbeat failed: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error sending HTTP heartbeat: {e}")
    
    def on_websocket_open(self, ws):
        """Handle WebSocket connection open (deprecated - using HTTP polling)"""
        logger.info("HTTP polling mode active")
        self.ws_connected = True
        self.update_status("online")
    
    def on_websocket_message(self, ws, message):
        """Handle WebSocket messages from backend (deprecated - using HTTP polling)"""
        try:
            data = json.loads(message)
            message_type = data.get('type')
            
            if message_type == 'error' and ('token' in data.get('detail', '').lower() or 'revoked' in data.get('detail', '').lower()):
                self.handle_token_error(data.get('detail', 'Agent token error'))
                return
            if message_type == 'discovery_request':
                self.handle_discovery_request(data)
            elif message_type == 'ping':
                self.send_pong()
            else:
                logger.warning(f"Unknown message type: {message_type}")
                
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
    
    def on_websocket_error(self, ws, error):
        """Handle WebSocket errors (deprecated - using HTTP polling)"""
        logger.error(f"HTTP polling error: {error}")
        self.ws_connected = False
    
    def on_websocket_close(self, ws, close_status_code, close_msg):
        """Handle WebSocket connection close (deprecated - using HTTP polling)"""
        logger.info("HTTP polling stopped")
        self.ws_connected = False
        self.update_status("offline")
    
    def heartbeat_loop(self):
        """Send periodic heartbeats to backend (now using HTTP)"""
        while self.running:
            try:
                if self.ws_connected:
                    self.send_heartbeat_http()
                time.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
    
    def send_heartbeat(self):
        """Send heartbeat to backend (now using HTTP)"""
        self.send_heartbeat_http()
    
    def send_pong(self):
        """Send pong response to ping (now using HTTP)"""
        try:
            pong_data = {
                'type': 'pong',
                'agent_name': self.agent_name,
                'timestamp': datetime.now().isoformat()
            }
            
            # Send pong via HTTP POST
            response = self.safe_request(
                'POST',
                f"{self.backend_url}/api/v1/agents/pong",
                headers={'X-Agent-Token': self.agent_token},
                json=pong_data
            )
            
            if response and response.status_code == 200:
                logger.debug("Pong sent successfully")
            else:
                logger.warning(f"Pong failed: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error sending HTTP pong: {e}")
    
    def update_status(self, status: str):
        """Update agent status in backend"""
        try:
            status_data = {
                'type': 'status_update',
                'agent_name': self.agent_name,
                'timestamp': datetime.now().isoformat(),
                'status': status,
                'discovered_devices_count': len(self.discovered_devices),
                'system_info': self.get_system_info()
            }
            
            response = self.safe_request(
                'PUT',
                f"{self.backend_url}/api/v1/agents/status",
                headers={'X-Agent-Token': self.agent_token},
                json=status_data
            )
            
            if response and response.status_code == 200:
                logger.info(f"Status updated to: {status}")
            else:
                logger.warning(f"Failed to update status: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def get_system_info(self) -> Dict:
        """Get system information"""
        try:
            return {
                'platform': sys.platform,
                'python_version': sys.version,
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': psutil.disk_usage('/').percent,
                'uptime': time.time() - psutil.boot_time()
            }
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            return {}

    def safe_request(self, method, url, **kwargs):
        """Wrapper for requests to handle token errors and rotation"""
        try:
            headers = kwargs.pop('headers', {})
            headers['X-Agent-Token'] = self.agent_token
            logger.debug(f"Making {method} request to {url} with token: {self.agent_token[:10]}...")
            resp = requests.request(method, url, headers=headers, **kwargs)
            logger.debug(f"Response status: {resp.status_code}")
            if resp.status_code in (401, 403):
                try:
                    detail = resp.json().get('detail', '')
                    logger.error(f"Token validation failed: {detail}")
                except Exception:
                    detail = resp.text
                    logger.error(f"Token validation failed: {detail}")
                new_token = resp.json().get('new_agent_token') if resp.headers.get('Content-Type', '').startswith('application/json') else None
                if 'revoked' in detail or 'inactive' in detail or 'not active' in detail:
                    self.handle_token_error(detail, new_token)
                else:
                    logger.error(f"Agent token error: {detail}")
            return resp
        except Exception as e:
            logger.error(f"Request error: {e}")
            return None


def main():
    """Main entry point"""
    try:
        # Create agent instance
        agent = CiscoAIAgent()
        
        # Start agent service
        agent.start()
        
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error(f"Agent failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
'''
    
    # Create requirements.txt
    requirements_content = '''requests>=2.25.1
urllib3>=1.26.0
websocket-client>=1.0.0
pysnmp>=4.4.12
paramiko>=3.5.1
psutil>=5.8.0
'''
    
    # Create agent_requirements.txt
    agent_requirements_content = '''requests>=2.25.1
urllib3>=1.26.0
websocket-client>=1.0.0
pysnmp>=4.4.12
paramiko>=3.5.1
psutil>=5.8.0
'''
    
    # Create installer
    installer_content = '''import os
import sys
import subprocess

print("Installing Cisco AI Agent dependencies...")
subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
print("Installation complete!")
'''
    
    # Create deployment guide
    guide_content = '''# Cisco AI Agent Deployment Guide

## Quick Start
1. Run `deploy.bat` (Windows) or `deploy.sh` (Linux/Mac)
2. Or manually: `pip install -r requirements.txt && python cisco_ai_agent.py`

## Configuration
The agent is pre-configured with your settings in `agent_config.json`

## Support
Check the web interface for agent status and logs.
'''
    
    # Write all files
    files_to_create = [
        ("cisco_ai_agent.py", agent_py_content),
        ("requirements.txt", requirements_content),
        ("agent_requirements.txt", agent_requirements_content),
        ("cisco_ai_agent_installer.py", installer_content),
        ("AGENT_DEPLOYMENT_GUIDE.md", guide_content),
        ("AGENT_DEPLOYMENT.md", guide_content)
    ]
    
    for file_name, content in files_to_create:
        file_path = os.path.join(package_dir, file_name)
        with open(file_path, 'w') as f:
            f.write(content)
    
    # Create agent configuration
    # Determine backend public URL dynamically
    from fastapi import Request
    def _detect_backend_url(req: Request):
        # Prefer explicit env var if provided
        env_url = os.getenv("BACKEND_PUBLIC_URL")
        if env_url:
            return env_url.rstrip('/')
        # Use forwarded proto/host if present (behind proxies)
        proto = req.headers.get("x-forwarded-proto") or req.url.scheme
        host = req.headers.get("x-forwarded-host") or req.headers.get("host")
        if host:
            return f"{proto}://{host}".rstrip('/')
        return str(req.base_url).rstrip('/')

    # Build agent_config with current backend URL
    agent_config = {
        "agent_id": agent.id,
        "agent_name": agent.name,
        "agent_token": agent.agent_token,
        "backend_url": _detect_backend_url(request),
        "organization_id": agent.organization_id,
        "capabilities": agent.capabilities or [],
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "status": agent.status
    }
    
    config_path = os.path.join(package_dir, "agent_config.json")
    with open(config_path, 'w') as f:
        json.dump(agent_config, f, indent=2, default=str)
    
    # Create improved deployment scripts
    deploy_bat_content = f"""@echo off
echo Installing Cisco AI Agent...
echo Agent: {agent.name}
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://python.org
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

REM Check if pip is available
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not available
    echo Please install pip or upgrade Python
    pause
    exit /b 1
)

echo Python found: 
python --version
echo.

REM Install Python dependencies
echo Installing dependencies...
python -m pip install -r requirements.txt

if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)

echo.
echo Dependencies installed successfully!
echo Starting agent...
echo.

REM Start the agent
python cisco_ai_agent.py

pause
"""
    
    deploy_sh_content = f"""#!/bin/bash
echo "Installing Cisco AI Agent..."
echo "Agent: {agent.name}"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3 from https://python.org"
    exit 1
fi

# Check if pip is available
if ! python3 -m pip --version &> /dev/null; then
    echo "ERROR: pip is not available"
    echo "Please install pip or upgrade Python"
    exit 1
fi

echo "Python found:"
python3 --version
echo

# Install Python dependencies
echo "Installing dependencies..."
python3 -m pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "ERROR: Failed to install dependencies"
    exit 1
fi

echo
echo "Dependencies installed successfully!"
echo "Starting agent..."
echo

# Start the agent
python3 cisco_ai_agent.py
"""
    
    # Write deployment scripts
    with open(os.path.join(package_dir, "deploy.bat"), 'w') as f:
        f.write(deploy_bat_content)
    
    with open(os.path.join(package_dir, "deploy.sh"), 'w') as f:
        f.write(deploy_sh_content)
    
    # Make deploy.sh executable (for Unix systems)
    os.chmod(os.path.join(package_dir, "deploy.sh"), 0o755)
    
    # Create improved README
    readme_content = f"""# Cisco AI Agent - {agent.name}

## Quick Start

### Windows
1. Make sure Python is installed (https://python.org)
2. Run `deploy.bat` to install dependencies and start the agent

### Linux/Mac
1. Make sure Python 3 is installed
2. Run `./deploy.sh` to install dependencies and start the agent

### Manual Installation
1. Install Python dependencies: `python -m pip install -r requirements.txt`
2. Start the agent: `python cisco_ai_agent.py`

## Configuration
The agent is pre-configured with your settings in `agent_config.json`

## Troubleshooting
- If you get "python not found", install Python from https://python.org
- Make sure to check "Add Python to PATH" during installation
- If you get "pip not found", try: `python -m pip install --upgrade pip`

## Support
Check the web interface for agent status and logs.
"""
    
    readme_path = os.path.join(package_dir, "README.md")
    with open(readme_path, 'w') as f:
        f.write(readme_content)
    
    # Create ZIP file
    zip_path = os.path.join(temp_dir, f"cisco_ai_agent_{agent.name.replace(' ', '_')}.zip")
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(package_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, package_dir)
                zipf.write(file_path, arcname)
    
    # Return the ZIP file
    return FileResponse(
        zip_path,
        media_type='application/zip',
        filename=f"cisco_ai_agent_{agent.name.replace(' ', '_')}.zip"
    )


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific agent details."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Calculate real-time status
        current_time = datetime.utcnow()
        if agent.last_heartbeat:
            time_diff = current_time - agent.last_heartbeat
            if time_diff.total_seconds() > 300:  # 5 minutes
                agent.status = "offline"
            else:
                agent.status = "online"
        else:
            agent.status = "offline"
        
        return agent
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agent: {str(e)}")


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: int,
    agent_data: AgentUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update agent details."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Update fields
        if agent_data.name is not None:
            agent.name = agent_data.name
        if agent_data.status is not None:
            agent.status = agent_data.status
        if agent_data.capabilities is not None:
            agent.capabilities = agent_data.capabilities
        if agent_data.version is not None:
            agent.version = agent_data.version
        
        agent.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(agent)
        
        return agent
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating agent: {str(e)}")


@router.delete("/{agent_id}", status_code=204)
async def delete_agent(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Delete an agent."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        db.delete(agent)
        db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error deleting agent: {str(e)}")


@router.post("/discovery", response_model=DiscoveryResponse)
async def agent_discovery(
    discovery_data: DiscoveryRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Route discovery request to appropriate agent."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate user has access to the network
        if not validate_user_network_access(user, discovery_data.network_id, db):
            raise HTTPException(
                status_code=403,
                detail="No access to this network"
            )
        
        # Find agent that has access to this network and is online
        agent = db.query(Agent).join(AgentNetworkAccess).filter(
            and_(
                AgentNetworkAccess.network_id == discovery_data.network_id,
                Agent.status == "online",
                Agent.last_heartbeat >= datetime.utcnow() - timedelta(minutes=5)  # Agent was active in last 5 minutes
            )
        ).first()
        
        if not agent:
            raise HTTPException(
                status_code=404,
                detail="No online agent available for this network"
            )
        
        # FUTURE ENHANCEMENT: Implement agent communication for discovery
        # This endpoint should send discovery requests to agents via WebSocket or HTTP
        # Currently returning placeholder response - agent communication not yet implemented
        logger.info(f"Discovery request would be routed to agent {agent.name} (placeholder response)")
        
        return DiscoveryResponse(
            status="pending_implementation",
            message=f"Agent discovery routing not yet implemented - would route to agent {agent.name}",
            discovered_devices=[],
            errors=["Agent communication not yet implemented"]
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error routing discovery: {str(e)}")


@router.get("/network/{network_id}/available-agents")
async def get_available_agents_for_network(
    network_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all available agents for a specific network."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Validate user has access to the network
        if not validate_user_network_access(user, network_id, db):
            raise HTTPException(
                status_code=403,
                detail="No access to this network"
            )
        
        # Find all agents that have access to this network
        agents = db.query(Agent).join(AgentNetworkAccess).filter(
            and_(
                AgentNetworkAccess.network_id == network_id,
                Agent.status == "online",
                Agent.last_heartbeat >= datetime.utcnow() - timedelta(minutes=5)
            )
        ).all()
        
        # Calculate real-time status for each agent
        current_time = datetime.utcnow()
        agent_list = []
        for agent in agents:
            if agent.last_heartbeat:
                time_diff = current_time - agent.last_heartbeat
                if time_diff.total_seconds() > 60:  # 1 minute timeout
                    agent.status = "offline"
                else:
                    agent.status = "online"
            else:
                agent.status = "offline"
            
            agent_list.append({
                "id": agent.id,
                "name": agent.name,
                "status": agent.status,
                "capabilities": agent.capabilities,
                "last_heartbeat": agent.last_heartbeat,
                "organization_id": agent.organization_id
            })
        
        return {
            "network_id": network_id,
            "available_agents": agent_list,
            "total_agents": len(agent_list)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching available agents: {str(e)}")


@router.post("/{agent_id}/start-discovery")
async def start_agent_discovery(
    agent_id: int,
    discovery_data: AgentDiscoveryRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Start device discovery using multiple agents with load balancing."""
    print(f"🔍 DEBUG: Received discovery request for agent {agent_id}")
    print(f"🔍 DEBUG: Discovery data: {discovery_data}")
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get the primary agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Check if agent is online
        if agent.status != "online" or not agent.last_heartbeat or \
           (datetime.utcnow() - agent.last_heartbeat).total_seconds() > 60:
            raise HTTPException(
                status_code=400,
                detail="Agent is offline or not responding"
            )
        
        # Validate network access for this agent
        print(f"🔍 DEBUG: Checking network access for agent {agent_id} to network {discovery_data.network_id}")
        network_access = db.query(AgentNetworkAccess).filter(
            and_(
                AgentNetworkAccess.agent_id == agent_id,
                AgentNetworkAccess.network_id == discovery_data.network_id
            )
        ).first()
        
        print(f"🔍 DEBUG: Network access result: {network_access}")
        
        if not network_access:
            print(f"🔍 DEBUG: No network access found for agent {agent_id} to network {discovery_data.network_id}")
            raise HTTPException(
                status_code=403,
                detail="Agent does not have access to this network"
            )
        
        # Validate all selected agents
        print(f"🔍 DEBUG: Starting validation of {len(discovery_data.agent_ids)} agents")
        all_agents = []
        for selected_agent_id in discovery_data.agent_ids:
            selected_agent = db.query(Agent).filter(Agent.id == selected_agent_id).first()
            if not selected_agent:
                raise HTTPException(
                    status_code=404,
                    detail=f"Agent {selected_agent_id} not found"
                )
            
            # Check if agent is online
            if selected_agent.status != "online" or not selected_agent.last_heartbeat or \
               (datetime.utcnow() - selected_agent.last_heartbeat).total_seconds() > 60:
                raise HTTPException(
                    status_code=400,
                    detail=f"Agent {selected_agent.name} is offline or not responding"
                )
            
            # Validate network access
            agent_network_access = db.query(AgentNetworkAccess).filter(
                and_(
                    AgentNetworkAccess.agent_id == selected_agent_id,
                    AgentNetworkAccess.network_id == discovery_data.network_id
                )
            ).first()
            
            if not agent_network_access:
                raise HTTPException(
                    status_code=403,
                    detail=f"Agent {selected_agent.name} does not have access to this network"
                )
            
            all_agents.append(selected_agent)
        
        print(f"🔍 DEBUG: All agents validated successfully, creating discovery session")
        # Create discovery session
        session_id = f"discovery_{int(datetime.utcnow().timestamp())}_{agent_id}"
        
        # Parse IP range for distribution
        print(f"🔍 DEBUG: Parsing IP range for distribution")
        ip_list = parse_ip_range_for_distribution(
            discovery_data.ip_range, 
            discovery_data.start_ip, 
            discovery_data.end_ip
        )
        
        # Distribute IPs across agents
        print(f"🔍 DEBUG: Distributing {len(ip_list)} IPs across {len(all_agents)} agents")
        agent_ip_assignments = distribute_ips_across_agents(ip_list, all_agents)
        
        # Start discovery on each agent
        print(f"🔍 DEBUG: Starting discovery tasks for {len(agent_ip_assignments)} agents")
        discovery_tasks = []
        for agent, assigned_ips in agent_ip_assignments.items():
            if assigned_ips:  # Only start if agent has IPs to scan
                task = await start_discovery_on_agent(
                    agent, 
                    session_id, 
                    discovery_data, 
                    assigned_ips
                )
                discovery_tasks.append(task)
        
        return {
            "session_id": session_id,
            "status": "started",
            "message": f"Discovery started on {len(discovery_tasks)} agents",
            "agent_count": len(discovery_tasks),
            "total_ips": len(ip_list),
            "agent_assignments": {
                agent.name: len(ips) for agent, ips in agent_ip_assignments.items() if ips
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting discovery: {str(e)}")


def parse_ip_range_for_distribution(ip_range: str = None, start_ip: str = None, end_ip: str = None) -> List[str]:
    """Parse IP range into list of IP addresses for distribution"""
    ip_list = []
    
    if ip_range:
        # Handle CIDR notation (e.g., 192.168.1.0/24)
        if '/' in ip_range:
            import ipaddress
            network = ipaddress.IPv4Network(ip_range, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
        # Handle range notation (e.g., 192.168.1.1-192.168.1.10)
        elif '-' in ip_range:
            start, end = ip_range.split('-')
            import ipaddress
            start_addr = ipaddress.IPv4Address(start.strip())
            end_addr = ipaddress.IPv4Address(end.strip())
            
            current = start_addr
            while current <= end_addr:
                ip_list.append(str(current))
                current += 1
        # Single IP
        else:
            ip_list = [ip_range.strip()]
    elif start_ip and end_ip:
        import ipaddress
        start_addr = ipaddress.IPv4Address(start_ip)
        end_addr = ipaddress.IPv4Address(end_ip)
        
        current = start_addr
        while current <= end_addr:
            ip_list.append(str(current))
            current += 1
    
    return ip_list


def distribute_ips_across_agents(ip_list: List[str], agents: List[Agent]) -> Dict[Agent, List[str]]:
    """Distribute IP addresses across multiple agents for load balancing"""
    if not agents:
        return {}
    
    # Simple round-robin distribution
    agent_ip_assignments = {agent: [] for agent in agents}
    
    for i, ip in enumerate(ip_list):
        agent_index = i % len(agents)
        agent_ip_assignments[agents[agent_index]].append(ip)
    
    return agent_ip_assignments


async def start_discovery_on_agent(agent: Agent, session_id: str, discovery_data: AgentDiscoveryRequest, assigned_ips: List[str]):
    """Start discovery on a specific agent"""
    logger = logging.getLogger(__name__)
    try:
        # Create agent-specific discovery request
        agent_discovery_request = {
            "type": "discovery",
            "session_id": session_id,
            "network_id": discovery_data.network_id,
            "discovery_method": discovery_data.discovery_method.dict(),
            "credentials": discovery_data.credentials,
            "ip_range": discovery_data.ip_range,
            "start_ip": discovery_data.start_ip,
            "end_ip": discovery_data.end_ip,
            "assigned_ips": assigned_ips,
            "total_agents": len(discovery_data.agent_ids),
            "agent_index": discovery_data.agent_ids.index(agent.id)
        }
        
        # Store the discovery request for the agent to pick up
        global pending_discovery_requests
        pending_discovery_requests[agent.id] = agent_discovery_request
        
        # Also store the network_id in the discovery session immediately
        global discovery_sessions
        if session_id not in discovery_sessions:
            discovery_sessions[session_id] = {
                "started_at": datetime.utcnow(),
                "discovered_devices": [],
                "errors": []
            }
        discovery_sessions[session_id]["network_id"] = discovery_data.network_id
        logger.info(f"🔍 DEBUG: Stored network_id {discovery_data.network_id} in discovery session {session_id}")
        
        logger.info(f"🔍 DEBUG: Stored discovery request for agent {agent.name} (ID: {agent.id}) for session {session_id}")
        logger.info(f"🔍 DEBUG: Assigned IPs: {assigned_ips}")
        logger.info(f"🔍 DEBUG: Total pending requests: {len(pending_discovery_requests)}")
        logger.info(f"🔍 DEBUG: Pending requests keys: {list(pending_discovery_requests.keys())}")
        
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": "started",
            "assigned_ips": len(assigned_ips)
        }
        
    except Exception as e:
        logger.error(f"Error starting discovery on agent {agent.name}: {e}")
        return {
            "agent_id": agent.id,
            "agent_name": agent.name,
            "status": "failed",
            "error": str(e)
        }


@router.get("/discovery/{session_id}/status")
async def get_discovery_status(
    session_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get the status of a discovery session."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Check for discovery session in memory storage
        global discovery_sessions
        if session_id in discovery_sessions:
            session_data = discovery_sessions[session_id]
            return {
                "session_id": session_id,
                "status": session_data.get("status", "in_progress"),
                "progress": session_data.get("progress", 0),
                "discovered_devices": session_data.get("discovered_devices", []),
                "errors": session_data.get("errors", []),
                "started_at": session_data.get("started_at", datetime.utcnow()),
                "estimated_completion": session_data.get("estimated_completion")
            }
        
        # Return default response if session not found
        return {
            "session_id": session_id,
            "status": "in_progress",
            "progress": 0,
            "discovered_devices": [],
            "errors": [],
            "started_at": datetime.utcnow(),
            "estimated_completion": None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching discovery status: {str(e)}")


@router.post("/{agent_id}/discovery-results")
async def submit_discovery_results(
    agent_id: int,
    results: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Receive discovery results from an agent."""
    logger = logging.getLogger(__name__)
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Process discovered devices
        discovered_devices = results.get("discovered_devices", [])
        errors = results.get("errors", [])
        session_id = results.get("session_id")
        
        # Store discovered devices in memory storage
        global discovery_sessions
        if session_id not in discovery_sessions:
            discovery_sessions[session_id] = {
                "started_at": datetime.utcnow(),
                "discovered_devices": [],
                "errors": []
            }
        
        discovery_sessions[session_id]["discovered_devices"].extend(discovered_devices)
        discovery_sessions[session_id]["errors"].extend(errors)
        
        # Get network_id from pending discovery request
        network_id = None
        global pending_discovery_requests
        if agent_id in pending_discovery_requests:
            pending_request = pending_discovery_requests[agent_id]
            if pending_request.get("session_id") == session_id:
                network_id = pending_request.get("network_id")
                logger.info(f"Found network_id {network_id} from pending discovery request for session {session_id}")
        
        if not network_id and session_id in discovery_sessions:
            # Try to get network_id from the discovery session
            session_data = discovery_sessions[session_id]
            if "network_id" in session_data:
                network_id = session_data["network_id"]
                logger.info(f"Found network_id {network_id} from discovery session for session {session_id}")
        
        if not network_id:
            logger.warning(f"No network_id found for session {session_id}, devices will not be saved to database")
            return {
                "status": "received",
                "message": f"Received {len(discovered_devices)} devices and {len(errors)} errors (no network_id found)",
                "session_id": session_id
            }
        
        # Save discovered devices to database
        saved_devices = []
        for device_data in discovered_devices:
            try:
                # Extract device information
                device_name = device_data.get("hostname", device_data.get("name", f"Device-{device_data.get('ip', device_data.get('ip_address', 'unknown'))}"))
                device_ip = device_data.get("ip") or device_data.get("ip_address")  # Try both 'ip' and 'ip_address' fields
                device_type = device_data.get("device_type", "unknown")
                location = device_data.get("location", "")
                platform = device_data.get("vendor", "cisco_ios")  # Use vendor as platform
                os_version = device_data.get("os_version", "")
                serial_number = device_data.get("serial_number", "")
                
                # Extract vendor and model from description
                description = device_data.get("description", "")
                vendor = "Unknown"
                model = "Unknown"
                
                if description:
                    # Try to extract vendor and model from description
                    if "Cisco" in description:
                        vendor = "Cisco"
                        # Extract model from Cisco description
                        if "Catalyst" in description:
                            model = "Catalyst L3 Switch Software"
                        elif "IOS" in description:
                            model = "Cisco IOS"
                        elif "NX-OS" in description:
                            model = "Cisco NX-OS"
                        else:
                            model = "Cisco Device"
                    elif "Juniper" in description:
                        vendor = "Juniper"
                        model = "Juniper Device"
                    elif "HP" in description or "HPE" in description:
                        vendor = "HP"
                        model = "HP Device"
                    elif "Dell" in description:
                        vendor = "Dell"
                        model = "Dell Device"
                    else:
                        vendor = "Unknown"
                        model = "Unknown Device"
                
                # Convert uptime to seconds if it's a string
                uptime_value = device_data.get("uptime", 0)
                if isinstance(uptime_value, str):
                    uptime_seconds = parse_uptime_string(uptime_value)
                else:
                    uptime_seconds = uptime_value
                
                # Validate required fields
                if not device_ip:
                    logger.error(f"Device IP is missing for device: {device_data}")
                    errors.append(f"Device IP is missing for device: {device_name}")
                    continue
                
                if not device_name:
                    logger.error(f"Device name is missing for device: {device_data}")
                    errors.append(f"Device name is missing for device with IP: {device_ip}")
                    continue
                
                logger.info(f"Processing device: {device_name} ({device_ip}) with type: {device_type}, platform: {platform}")
                
                # Create or update device in database
                existing_device = db.query(Device).filter(
                    and_(
                        Device.ip == device_ip,
                        Device.network_id == network_id
                    )
                ).first()
                
                # Set status based on discovery method (don't test from cloud for local devices)
                # If device was discovered, it means it's reachable
                ping_ok = True  # Device was discovered, so it's reachable
                
                # Set SNMP status based on discovery method
                snmp_ok = False
                if device_data.get("discovery_method") == "snmp" or device_data.get("capabilities", []):
                    snmp_ok = True  # If device was discovered via SNMP, it's working
                    logger.info(f"[STATUS] {device_ip} -> Ping: OK, SNMP: OK (discovered via SNMP)")
                else:
                    logger.info(f"[STATUS] {device_ip} -> Ping: OK, SNMP: Unknown")
                
                # Determine discovery method based on device data
                discovery_method = device_data.get("discovery_method", "enhanced")
                capabilities = device_data.get("capabilities", [])
                
                # Debug logging to see what the agent is sending
                logger.info(f"[DEBUG] Device {device_ip} capabilities: {capabilities}")
                logger.info(f"[DEBUG] Device {device_ip} discovery_method from agent: {device_data.get('discovery_method')}")
                
                # If both SNMP and SSH capabilities exist, it's enhanced discovery
                if capabilities and "snmp" in capabilities and "ssh" in capabilities:
                    discovery_method = "enhanced"
                    logger.info(f"[DEBUG] Device {device_ip} -> Enhanced discovery (both SNMP and SSH)")
                elif capabilities and "snmp" in capabilities:
                    discovery_method = "snmp"
                    logger.info(f"[DEBUG] Device {device_ip} -> SNMP discovery")
                elif capabilities and "ssh" in capabilities:
                    discovery_method = "ssh"
                    logger.info(f"[DEBUG] Device {device_ip} -> SSH discovery")
                else:
                    logger.info(f"[DEBUG] Device {device_ip} -> Default enhanced discovery")
                
                if existing_device:
                    # Update existing device
                    existing_device.name = device_name
                    existing_device.type = device_type
                    existing_device.platform = platform
                    existing_device.location = location
                    existing_device.os_version = os_version
                    existing_device.serial_number = serial_number
                    existing_device.ping_status = ping_ok
                    existing_device.snmp_status = snmp_ok
                    existing_device.discovery_method = discovery_method
                    existing_device.updated_at = datetime.utcnow()
                    
                    # Update or create DeviceTopology record with detailed MIB-2 information
                    existing_topology = db.query(DeviceTopology).filter(DeviceTopology.device_id == existing_device.id).first()
                    
                    if existing_topology:
                        # Update existing topology
                        existing_topology.hostname = device_data.get("hostname", device_name)
                        existing_topology.vendor = vendor
                        existing_topology.model = model
                        existing_topology.uptime = uptime_seconds
                        existing_topology.last_polled = datetime.utcnow()
                        existing_topology.health_data = {
                            "location": device_data.get("location", ""),
                            "contact": device_data.get("contact", ""),
                            "capabilities": device_data.get("capabilities", [])
                        }
                    else:
                        # Create new topology record
                        new_topology = DeviceTopology(
                            device_id=existing_device.id,
                            network_id=network_id,
                            hostname=device_data.get("hostname", device_name),
                            vendor=vendor,
                            model=model,
                            uptime=uptime_seconds,
                            last_polled=datetime.utcnow(),
                            health_data={
                                "location": device_data.get("location", ""),
                                "contact": device_data.get("contact", ""),
                                "capabilities": device_data.get("capabilities", [])
                            }
                        )
                        db.add(new_topology)
                    
                    # Update SNMP configuration if provided
                    if device_data.get('snmp_config'):
                        snmp_config_data = device_data['snmp_config']
                        if existing_device.snmp_config:
                            # Update existing SNMP config
                            existing_device.snmp_config.snmp_version = snmp_config_data.get('snmp_version', 'v2c')
                            existing_device.snmp_config.community = snmp_config_data.get('community')
                            existing_device.snmp_config.username = snmp_config_data.get('username')
                            existing_device.snmp_config.auth_protocol = snmp_config_data.get('auth_protocol')
                            existing_device.snmp_config.auth_password = snmp_config_data.get('auth_password')
                            existing_device.snmp_config.priv_protocol = snmp_config_data.get('priv_protocol')
                            existing_device.snmp_config.priv_password = snmp_config_data.get('priv_password')
                            existing_device.snmp_config.port = snmp_config_data.get('port', 161)
                        else:
                            # Create new SNMP config
                            from app.models.base import DeviceSNMP
                            new_snmp_config = DeviceSNMP(
                                device_id=existing_device.id,
                                snmp_version=snmp_config_data.get('snmp_version', 'v2c'),
                                community=snmp_config_data.get('community'),
                                username=snmp_config_data.get('username'),
                                auth_protocol=snmp_config_data.get('auth_protocol'),
                                auth_password=snmp_config_data.get('auth_password'),
                                priv_protocol=snmp_config_data.get('priv_protocol'),
                                priv_password=snmp_config_data.get('priv_password'),
                                port=snmp_config_data.get('port', 161)
                            )
                            db.add(new_snmp_config)
                    
                    saved_devices.append(existing_device)
                    logger.info(f"Updated existing device: {device_name} ({device_ip}) - Ping: {ping_ok}, SNMP: {snmp_ok}, Method: {discovery_method}")
                else:
                    # Create new device
                    new_device = Device(
                        name=device_name,
                        ip=device_ip,
                        type=device_type,
                        platform=platform,
                        location=location,
                        os_version=os_version,
                        serial_number=serial_number,
                        network_id=network_id,
                        owner_id=agent.company_id,  # Use agent's company as owner
                        company_id=agent.company_id,
                        username="",  # Required field
                        password="",  # Required field
                        ping_status=ping_ok,
                        snmp_status=snmp_ok,
                        discovery_method=discovery_method,
                        created_at=datetime.utcnow(),
                        updated_at=datetime.utcnow()
                    )
                    db.add(new_device)
                    db.flush()  # Flush to get the device ID
                    
                    # Create SNMP configuration if provided
                    if device_data.get('snmp_config'):
                        snmp_config_data = device_data['snmp_config']
                        from app.models.base import DeviceSNMP
                        new_snmp_config = DeviceSNMP(
                            device_id=new_device.id,
                            snmp_version=snmp_config_data.get('snmp_version', 'v2c'),
                            community=snmp_config_data.get('community'),
                            username=snmp_config_data.get('username'),
                            auth_protocol=snmp_config_data.get('auth_protocol'),
                            auth_password=snmp_config_data.get('auth_password'),
                            priv_protocol=snmp_config_data.get('priv_protocol'),
                            priv_password=snmp_config_data.get('priv_password'),
                            port=snmp_config_data.get('port', 161)
                        )
                        db.add(new_snmp_config)
                        logger.info(f"Created SNMP config for device {device_ip}: version={snmp_config_data.get('snmp_version')}, community={snmp_config_data.get('community')}")
                    
                    # Create DeviceTopology record with detailed MIB-2 information
                    new_topology = DeviceTopology(
                        device_id=new_device.id,
                        network_id=network_id,
                        hostname=device_data.get("hostname", device_name),
                        vendor=vendor,
                        model=model,
                        uptime=uptime_seconds,
                        last_polled=datetime.utcnow(),
                        health_data={
                            "location": device_data.get("location", ""),
                            "contact": device_data.get("contact", ""),
                            "capabilities": device_data.get("capabilities", [])
                        }
                    )
                    db.add(new_topology)
                    logger.info(f"Created DeviceTopology record for device {device_ip} with hostname: {device_data.get('hostname', device_name)}")
                    
                    saved_devices.append(new_device)
                    logger.info(f"Created new device: {device_name} ({device_ip}) - Ping: {ping_ok}, SNMP: {snmp_ok}, Method: {discovery_method}")
                
            except Exception as e:
                logger.error(f"Error saving device {device_data.get('ip', 'unknown')}: {str(e)}")
                errors.append(f"Failed to save device {device_data.get('ip', 'unknown')}: {str(e)}")
        
        # Commit all changes to database
        try:
            db.commit()
            logger.info(f"Successfully saved {len(saved_devices)} devices to database")
        except Exception as e:
            db.rollback()
            logger.error(f"Error committing devices to database: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Error saving devices to database: {str(e)}")
        
        # Create DeviceLog entries for failed discoveries
        if errors:
            try:
                from app.models.base import DeviceLog
                
                for error_msg in errors:
                    # Try to extract IP address from error message
                    ip_address = None
                    log_type = "invalid_credentials"  # Default to a valid enum value
                    message = error_msg
                    
                    # Check if error contains IP address
                    import re
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', error_msg)
                    if ip_match:
                        ip_address = ip_match.group()
                        
                        # Determine log type based on error message
                        if 'unreachable' in error_msg.lower() or 'ping' in error_msg.lower():
                            log_type = "unreachable"
                        elif 'credentials' in error_msg.lower() or 'authentication' in error_msg.lower():
                            log_type = "invalid_credentials"
                        else:
                            log_type = "invalid_credentials"  # Use valid enum value
                        
                        # Create DeviceLog entry
                        device_log = DeviceLog(
                            ip_address=ip_address,
                            network_id=network_id,
                            company_id=agent.company_id,
                            log_type=log_type,
                            message=error_msg
                        )
                        db.add(device_log)
                
                # Commit the logs
                db.commit()
                logger.info(f"Created {len(errors)} DeviceLog entries for failed discoveries")
                
            except Exception as e:
                logger.error(f"Error creating DeviceLog entries for failed discoveries: {str(e)}")
                # Don't fail the entire request if logging fails
        
        logger.info(f"Received discovery results for session {session_id}: {len(discovered_devices)} devices, {len(errors)} errors")
        
        return {
            "status": "received",
            "message": f"Received {len(discovered_devices)} devices and {len(errors)} errors",
            "session_id": session_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing discovery results: {str(e)}")


@router.get("/status/{agent_id}")
async def get_agent_status(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get agent status and health information."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Calculate health status
        is_healthy = (
            agent.status == "online" and 
            agent.last_heartbeat and 
            agent.last_heartbeat >= datetime.utcnow() - timedelta(minutes=5)
        )
        
        return {
            "agent_id": agent.id,
            "name": agent.name,
            "status": agent.status,
            "is_healthy": is_healthy,
            "last_heartbeat": agent.last_heartbeat,
            "capabilities": agent.capabilities,
            "version": agent.version,
            "uptime": (datetime.utcnow() - agent.created_at).total_seconds() if agent.created_at else 0
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching agent status: {str(e)}") 


@router.post("/{agent_id}/rotate_token", response_model=AgentResponse)
async def rotate_agent_token(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if user.role not in ["superadmin", "company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    old_token = agent.agent_token
    agent.agent_token = generate_agent_token()
    agent.token_status = "active"
    agent.rotated_at = datetime.utcnow()
    agent.revoked_at = None
    db.commit()
    log_agent_token_event(db, agent.id, event="rotated", user_id=user.id, details={"old_token": old_token})
    return agent

@router.post("/{agent_id}/revoke_token", response_model=AgentResponse)
async def revoke_agent_token(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if user.role not in ["superadmin", "company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    agent.token_status = "revoked"
    agent.revoked_at = datetime.utcnow()
    db.commit()
    log_agent_token_event(db, agent.id, event="revoked", user_id=user.id)
    return agent

@router.get("/{agent_id}/audit_logs", response_model=List[AgentTokenAuditLogResponse])
async def get_agent_audit_logs(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == current_user["user_id"]).first()
    agent = db.query(Agent).filter(Agent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if user.role not in ["superadmin", "company_admin", "full_control"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    logs = db.query(AgentTokenAuditLog).filter(AgentTokenAuditLog.agent_id == agent_id).order_by(AgentTokenAuditLog.timestamp.desc()).all()
    return logs 


@router.get("/fix-db-schema", response_model=dict)
async def fix_database_schema(
    current_user: dict = Depends(get_current_user)
):
    """Temporary endpoint to fix database schema issues."""
    try:
        from sqlalchemy import create_engine, text, inspect
        from app.core.config import settings
        
        # Create a direct database connection
        engine = create_engine(settings.DATABASE_URL)
        
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            
            # Fix agents table
            if 'agents' in tables:
                agent_columns = [col['name'] for col in inspector.get_columns('agents')]
                
                # New agent token management fields that need to be added
                agent_new_columns = [
                    ('token_status', 'VARCHAR NOT NULL DEFAULT \'active\''),
                    ('scopes', 'JSONB'),
                    ('issued_at', 'TIMESTAMP DEFAULT NOW()'),
                    ('expires_at', 'TIMESTAMP'),
                    ('rotated_at', 'TIMESTAMP'),
                    ('revoked_at', 'TIMESTAMP'),
                    ('last_used_at', 'TIMESTAMP'),
                    ('last_used_ip', 'VARCHAR'),
                    ('created_by', 'INTEGER REFERENCES users(id)')
                ]
                
                added_columns = []
                for col_name, col_def in agent_new_columns:
                    if col_name not in agent_columns:
                        try:
                            conn.execute(text(f"ALTER TABLE agents ADD COLUMN {col_name} {col_def};"))
                            added_columns.append(col_name)
                        except Exception as e:
                            print(f"Error adding column {col_name}: {e}")
                
                conn.commit()
            
            # Fix agent_token_audit_logs table
            if 'agent_token_audit_logs' not in tables:
                # Create the table
                create_table_sql = """
                CREATE TABLE agent_token_audit_logs (
                    id SERIAL PRIMARY KEY,
                    agent_id INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
                    event VARCHAR NOT NULL,
                    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
                    ip_address VARCHAR,
                    user_id INTEGER REFERENCES users(id),
                    details JSONB
                );
                """
                conn.execute(text(create_table_sql))
                conn.commit()
                table_created = True
            else:
                # Check columns in agent_token_audit_logs table
                audit_columns = [col['name'] for col in inspector.get_columns('agent_token_audit_logs')]
                
                audit_required_columns = [
                    ('agent_id', 'INTEGER NOT NULL REFERENCES agents(id) ON DELETE CASCADE'),
                    ('event', 'VARCHAR NOT NULL'),
                    ('timestamp', 'TIMESTAMP NOT NULL DEFAULT NOW()'),
                    ('ip_address', 'VARCHAR'),
                    ('user_id', 'INTEGER REFERENCES users(id)'),
                    ('details', 'JSONB')
                ]
                
                audit_added_columns = []
                for col_name, col_def in audit_required_columns:
                    if col_name not in audit_columns:
                        try:
                            conn.execute(text(f"ALTER TABLE agent_token_audit_logs ADD COLUMN {col_name} {col_def};"))
                            audit_added_columns.append(col_name)
                        except Exception as e:
                            print(f"Error adding column {col_name}: {e}")
                
                conn.commit()
                table_created = False
        
        return {
            "status": "success",
            "message": "Database schema fixed",
            "added_agent_columns": added_columns,
            "audit_table_created": table_created,
            "added_audit_columns": audit_added_columns if 'audit_added_columns' in locals() else []
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error fixing schema: {str(e)}",
            "error_type": type(e).__name__
        } 

@router.get("/check-db-schema", response_model=dict)
async def check_database_schema(
    current_user: dict = Depends(get_current_user)
):
    """Temporary endpoint to check the actual database schema."""
    try:
        from sqlalchemy import create_engine, text, inspect
        from app.core.config import settings
        
        # Create a direct database connection
        engine = create_engine(settings.DATABASE_URL)
        
        with engine.connect() as conn:
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            
            result = {
                "tables": tables,
                "agents_columns": [],
                "audit_logs_columns": []
            }
            
            # Check agents table columns
            if 'agents' in tables:
                agent_columns = inspector.get_columns('agents')
                result["agents_columns"] = [
                    {
                        "name": col['name'],
                        "type": str(col['type']),
                        "nullable": col['nullable'],
                        "default": col['default']
                    }
                    for col in agent_columns
                ]
            
            # Check agent_token_audit_logs table columns
            if 'agent_token_audit_logs' in tables:
                audit_columns = inspector.get_columns('agent_token_audit_logs')
                result["audit_logs_columns"] = [
                    {
                        "name": col['name'],
                        "type": str(col['type']),
                        "nullable": col['nullable'],
                        "default": col['default']
                    }
                    for col in audit_columns
                ]
            
            return result
        
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error checking schema: {str(e)}",
            "error_type": type(e).__name__
        } 


@router.websocket("/ws/agent/{agent_token}")
async def agent_websocket(websocket: WebSocket, agent_token: str, db: Session = Depends(get_db)):
    """WebSocket endpoint for agent connections."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent:
            await websocket.close(code=4001, reason="Invalid agent token")
            return
        
        if agent.token_status != "active":
            await websocket.close(code=4003, reason="Agent token is not active")
            return
        
        await websocket.accept()
        
        # Update agent status to online
        agent.status = "online"
        agent.last_heartbeat = datetime.utcnow()
        agent.last_used_at = datetime.utcnow()
        db.commit()
        
        # Log the connection
        log_agent_token_event(db, agent.id, event="websocket_connected")
        
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    payload = json.loads(data)
                    message_type = payload.get("type", "")
                    
                    if message_type == "heartbeat":
                        # Update heartbeat
                        agent.last_heartbeat = datetime.utcnow()
                        agent.last_used_at = datetime.utcnow()
                        db.commit()
                        
                        # Send pong response
                        await websocket.send_text(json.dumps({
                            "type": "pong",
                            "timestamp": datetime.utcnow().isoformat()
                        }))
                    
                    elif message_type == "discovery_result":
                        # Handle discovery results
                        devices = payload.get("devices", [])
                        subnet = payload.get("subnet", "")
                        
                        # Process discovered devices
                        for device_data in devices:
                            # You can add device processing logic here
                            pass
                        
                        await websocket.send_text(json.dumps({
                            "type": "discovery_ack",
                            "message": f"Received {len(devices)} devices from {subnet}"
                        }))
                    
                    else:
                        # Echo back unknown message types
                        await websocket.send_text(json.dumps({
                            "type": "echo",
                            "data": payload
                        }))
                        
                except json.JSONDecodeError:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid JSON format"
                    }))
                    
        except WebSocketDisconnect:
            # Update agent status to offline
            agent.status = "offline"
            db.commit()
            log_agent_token_event(db, agent.id, event="websocket_disconnected")
            
    except Exception as e:
        if websocket.client_state.value < 3:  # Not closed yet
            await websocket.close(code=4000, reason=f"Internal error: {str(e)}")
        log_agent_token_event(db, None, event="websocket_error", details={"error": str(e)})

 
@router.post("/{agent_id}/test-device-status")
async def request_device_status_test(
    agent_id: int,
    status_request: dict = Body(...),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Request agent to test device status for specific devices"""
    try:
        # Validate agent exists and user has access
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if user has access to the network
        network_id = status_request.get("network_id")
        if not validate_user_network_access(current_user, network_id, db):
            raise HTTPException(status_code=403, detail="Access denied to network")
        
        # Store the status test request for the agent to pick up
        request_id = f"status_test_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{agent_id}"
        
        # Add to pending requests
        if agent_id not in pending_discovery_requests:
            pending_discovery_requests[agent_id] = []
        
        pending_discovery_requests[agent_id].append({
            "type": "status_test",
            "request_id": request_id,
            "network_id": network_id,
            "devices": status_request.get("devices", []),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        return {
            "message": "Status test request queued for agent",
            "request_id": request_id,
            "agent_id": agent_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{agent_id}/pending-discovery")
async def get_pending_discovery_requests(
    agent_id: int,
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Get pending discovery requests for an agent."""
    logger = logging.getLogger(__name__)
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Check for pending discovery requests
        global pending_discovery_requests
        logger.info(f"🔍 DEBUG: Agent {agent_id} checking for pending discovery requests")
        logger.info(f"🔍 DEBUG: Available pending requests: {list(pending_discovery_requests.keys())}")
        
        if agent_id in pending_discovery_requests:
            request = pending_discovery_requests[agent_id]
            # Remove the request so it's only processed once
            del pending_discovery_requests[agent_id]
            
            # Log the request type and details safely
            request_type = request.get('type', 'unknown')
            session_id = request.get('session_id', 'no-session-id')
            logger.info(f"🔍 DEBUG: Returning pending {request_type} request for agent {agent_id}: {session_id}")
            return [request]
        
        logger.info(f"🔍 DEBUG: No pending discovery requests found for agent {agent_id}")
        return []
        
        return []
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"🔍 DEBUG: Error in get_pending_discovery_requests: {str(e)}")
        logger.error(f"🔍 DEBUG: Error type: {type(e)}")
        import traceback
        logger.error(f"🔍 DEBUG: Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error fetching pending discovery: {str(e)}")


@router.post("/{agent_id}/discovery-status")
async def update_discovery_status(
    agent_id: int,
    status_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Update discovery session status."""
    logger = logging.getLogger(__name__)
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        session_id = status_data.get("session_id")
        status = status_data.get("status")
        discovered_count = status_data.get("discovered_count", 0)
        error = status_data.get("error")
        
        logger.info(f"Agent {agent_id} discovery status update: session={session_id}, status={status}, count={discovered_count}")
        
        # Update discovery session in memory storage
        global discovery_sessions
        if session_id not in discovery_sessions:
            discovery_sessions[session_id] = {
                "started_at": datetime.utcnow(),
                "discovered_devices": [],
                "errors": []
            }
        
        # Try to get network_id from pending discovery request if not already stored
        if "network_id" not in discovery_sessions[session_id]:
            global pending_discovery_requests
            if agent_id in pending_discovery_requests:
                pending_request = pending_discovery_requests[agent_id]
                if pending_request.get("session_id") == session_id:
                    discovery_sessions[session_id]["network_id"] = pending_request.get("network_id")
                    logger.info(f"Stored network_id {pending_request.get('network_id')} in discovery session {session_id}")
        
        discovery_sessions[session_id]["status"] = status
        discovery_sessions[session_id]["discovered_count"] = discovered_count
        if error:
            discovery_sessions[session_id]["errors"].append(error)
        
        return {"status": "updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating discovery status: {str(e)}")


@router.post("/{agent_id}/discovery-progress")
async def update_discovery_progress(
    agent_id: int,
    progress_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Update discovery session progress."""
    logger = logging.getLogger(__name__)
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        session_id = progress_data.get("session_id")
        progress = progress_data.get("progress", 0)
        processed_ips = progress_data.get("processed_ips", 0)
        discovered_count = progress_data.get("discovered_count", 0)
        
        logger.debug(f"Agent {agent_id} discovery progress: session={session_id}, progress={progress}%, processed={processed_ips}, discovered={discovered_count}")
        
        # Update discovery session progress in memory storage
        global discovery_sessions
        if session_id not in discovery_sessions:
            discovery_sessions[session_id] = {
                "started_at": datetime.utcnow(),
                "discovered_devices": [],
                "errors": []
            }
        
        discovery_sessions[session_id]["progress"] = progress
        discovery_sessions[session_id]["processed_ips"] = processed_ips
        discovery_sessions[session_id]["discovered_count"] = discovered_count
        
        return {"status": "updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating discovery progress: {str(e)}") 


@router.post("/{agent_id}/network-access")
async def assign_network_access(
    agent_id: int,
    network_access_data: dict = Body(...),
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Assign network access to an agent."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get the agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        network_id = network_access_data.get("network_id")
        if not network_id:
            raise HTTPException(status_code=400, detail="network_id is required")
        
        # Check if network exists and belongs to the same organization
        network = db.query(Network).filter(Network.id == network_id).first()
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")
        
        if network.organization_id != agent.organization_id:
            raise HTTPException(
                status_code=403,
                detail="Network does not belong to the same organization as the agent"
            )
        
        # Check if assignment already exists
        existing_access = db.query(AgentNetworkAccess).filter(
            and_(
                AgentNetworkAccess.agent_id == agent_id,
                AgentNetworkAccess.network_id == network_id
            )
        ).first()
        
        if existing_access:
            raise HTTPException(
                status_code=400,
                detail="Agent already has access to this network"
            )
        
        # Create the network access assignment
        network_access = AgentNetworkAccess(
            agent_id=agent_id,
            network_id=network_id,
            company_id=agent.company_id,
            organization_id=agent.organization_id
        )
        
        db.add(network_access)
        db.commit()
        
        return {
            "message": f"Agent {agent.name} now has access to network {network.name}",
            "agent_id": agent_id,
            "network_id": network_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error assigning network access: {str(e)}")


@router.delete("/{agent_id}/network-access/{network_id}")
async def remove_network_access(
    agent_id: int,
    network_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove network access from an agent."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get the agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Find and remove the network access
        network_access = db.query(AgentNetworkAccess).filter(
            and_(
                AgentNetworkAccess.agent_id == agent_id,
                AgentNetworkAccess.network_id == network_id
            )
        ).first()
        
        if not network_access:
            raise HTTPException(
                status_code=404,
                detail="Agent does not have access to this network"
            )
        
        db.delete(network_access)
        db.commit()
        
        return {
            "message": f"Removed network access from agent {agent.name}",
            "agent_id": agent_id,
            "network_id": network_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error removing network access: {str(e)}")


@router.get("/{agent_id}/network-access")
async def get_agent_network_access(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all networks that an agent has access to."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get the agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Validate access
        if user.role != "superadmin":
            if not validate_user_organization_access(user, agent.organization_id, db):
                raise HTTPException(
                    status_code=403,
                    detail="No access to this agent"
                )
        
        # Get all network access for this agent
        network_access_list = db.query(AgentNetworkAccess).filter(
            AgentNetworkAccess.agent_id == agent_id
        ).all()
        
        # Get network details
        networks = []
        for access in network_access_list:
            network = db.query(Network).filter(Network.id == access.network_id).first()
            if network:
                networks.append({
                    "id": network.id,
                    "name": network.name,
                    "organization_id": network.organization_id,
                    "assigned_at": access.created_at
                })
        
        return {
            "agent_id": agent_id,
            "agent_name": agent.name,
            "networks": networks
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting agent network access: {str(e)}")


@router.post("/{agent_id}/device-status-report")
async def report_device_status_agent(
    agent_id: int,
    status_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Report device status from agent (agent authentication)"""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Extract data from request body
        network_id = status_data.get("network_id")
        device_statuses = status_data.get("device_statuses", [])
        
        if not network_id:
            raise HTTPException(status_code=400, detail="network_id is required")
        
        updated_count = 0
        
        for device_status in device_statuses:
            try:
                device_ip = device_status.get("ip")
                ping_status = device_status.get("ping_status", False)
                snmp_status = device_status.get("snmp_status", False)
                timestamp = device_status.get("timestamp")
                
                if not device_ip:
                    continue
                
                # Find device by IP in the network
                from app.models.base import Device
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
                            from datetime import datetime
                            device.updated_at = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                        except:
                            from datetime import datetime
                            device.updated_at = datetime.utcnow()
                    else:
                        from datetime import datetime
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


# ============================================================================
# TOPOLOGY DISCOVERY ENDPOINTS
# ============================================================================

@router.post("/{agent_id}/topology/discover")
async def start_agent_topology_discovery(
    agent_id: int,
    discovery_request: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Start topology discovery on an agent."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Extract discovery parameters
        network_id = discovery_request.get("network_id")
        discovery_type = discovery_request.get("discovery_type", "full")
        force_refresh = discovery_request.get("force_refresh", False)
        
        if not network_id:
            raise HTTPException(status_code=400, detail="network_id is required")
        
        # Check if agent has access to the network
        network_access = db.query(AgentNetworkAccess).filter(
            AgentNetworkAccess.agent_id == agent_id,
            AgentNetworkAccess.network_id == network_id
        ).first()
        
        if not network_access:
            raise HTTPException(status_code=403, detail="Agent does not have access to this network")
        
        # Import and use the topology discovery service
        from app.services.agent_topology_discovery import AgentTopologyDiscoveryService
        discovery_service = AgentTopologyDiscoveryService(db)
        
        # Start discovery
        success = discovery_service.start_discovery(agent_id, network_id, discovery_type)
        
        if success:
            return {
                "success": True,
                "message": f"Topology discovery started for network {network_id}",
                "agent_id": agent_id,
                "network_id": network_id,
                "discovery_type": discovery_type,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to start topology discovery")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error starting topology discovery: {str(e)}")


@router.post("/{agent_id}/topology/update")
async def update_agent_topology(
    agent_id: int,
    topology_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Update topology data from an agent."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Extract topology data
        network_id = topology_data.get("network_id")
        devices = topology_data.get("devices", [])
        interfaces = topology_data.get("interfaces", [])
        neighbors = topology_data.get("neighbors", [])
        
        if not network_id:
            raise HTTPException(status_code=400, detail="network_id is required")
        
        # Check if agent has access to the network
        network_access = db.query(AgentNetworkAccess).filter(
            AgentNetworkAccess.agent_id == agent_id,
            AgentNetworkAccess.network_id == network_id
        ).first()
        
        if not network_access:
            raise HTTPException(status_code=403, detail="Agent does not have access to this network")
        
        # Import and use the topology discovery service
        from app.services.agent_topology_discovery import AgentTopologyDiscoveryService
        discovery_service = AgentTopologyDiscoveryService(db)
        
        # Create topology update object
        from app.schemas.agent_topology import AgentTopologyUpdate, AgentDeviceDiscovery, AgentInterfaceDiscovery, AgentNeighborDiscovery
        
        # Convert raw data to schema objects
        device_discoveries = []
        for device_data in devices:
            device_discoveries.append(AgentDeviceDiscovery(
                ip_address=device_data.get("ip_address"),
                hostname=device_data.get("hostname"),
                device_type=device_data.get("device_type"),
                platform=device_data.get("platform"),
                vendor=device_data.get("vendor"),
                os_version=device_data.get("os_version"),
                serial_number=device_data.get("serial_number"),
                uptime=device_data.get("uptime"),
                ping_status=device_data.get("ping_status", False),
                snmp_status=device_data.get("snmp_status", False),
                ssh_status=device_data.get("ssh_status", False)
            ))
        
        interface_discoveries = []
        for interface_data in interfaces:
            interface_discoveries.append(AgentInterfaceDiscovery(
                interface_name=interface_data.get("interface_name"),
                interface_description=interface_data.get("interface_description"),
                interface_type=interface_data.get("interface_type"),
                operational_status=interface_data.get("operational_status"),
                administrative_status=interface_data.get("administrative_status"),
                speed=interface_data.get("speed"),
                mac_address=interface_data.get("mac_address"),
                ip_address=interface_data.get("ip_address"),
                vlan=interface_data.get("vlan")
            ))
        
        neighbor_discoveries = []
        for neighbor_data in neighbors:
            neighbor_discoveries.append(AgentNeighborDiscovery(
                local_device_ip=neighbor_data.get("local_device_ip"),
                local_interface=neighbor_data.get("local_interface"),
                neighbor_device_ip=neighbor_data.get("neighbor_device_ip"),
                neighbor_hostname=neighbor_data.get("neighbor_hostname"),
                neighbor_interface=neighbor_data.get("neighbor_interface"),
                neighbor_platform=neighbor_data.get("neighbor_platform"),
                discovery_protocol=neighbor_data.get("discovery_protocol")
            ))
        
        topology_update = AgentTopologyUpdate(
            agent_id=agent_id,
            network_id=network_id,
            devices=device_discoveries,
            interfaces=interface_discoveries,
            neighbors=neighbor_discoveries,
            summary={
                "total_devices": len(device_discoveries),
                "total_interfaces": len(interface_discoveries),
                "total_neighbors": len(neighbor_discoveries),
                "discovery_timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Complete the discovery
        success = discovery_service.complete_discovery(agent_id, topology_update)
        
        if success:
            return {
                "success": True,
                "message": f"Topology updated successfully for network {network_id}",
                "agent_id": agent_id,
                "network_id": network_id,
                "devices_discovered": len(device_discoveries),
                "interfaces_discovered": len(interface_discoveries),
                "neighbors_discovered": len(neighbor_discoveries),
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update topology")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating topology: {str(e)}")


@router.post("/{agent_id}/topology/progress")
async def update_discovery_progress(
    agent_id: int,
    progress_data: dict = Body(...),
    agent_token: str = Header(..., alias="X-Agent-Token"),
    db: Session = Depends(get_db)
):
    """Update discovery progress for an agent."""
    try:
        # Validate agent token
        agent = db.query(Agent).filter(Agent.agent_token == agent_token).first()
        if not agent or agent.id != agent_id:
            raise HTTPException(status_code=401, detail="Invalid agent token")
        
        # Extract progress data
        progress = progress_data.get("progress", 0)
        discovered_devices = progress_data.get("discovered_devices", 0)
        
        # Import and use the topology discovery service
        from app.services.agent_topology_discovery import AgentTopologyDiscoveryService
        discovery_service = AgentTopologyDiscoveryService(db)
        
        # Update progress
        success = discovery_service.update_discovery_progress(agent_id, progress, discovered_devices)
        
        if success:
            return {
                "success": True,
                "message": "Discovery progress updated",
                "agent_id": agent_id,
                "progress": progress,
                "discovered_devices": discovered_devices,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to update discovery progress")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating discovery progress: {str(e)}")


@router.get("/{agent_id}/topology/status")
async def get_agent_topology_status(
    agent_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get topology discovery status for an agent."""
    try:
        # Validate user access to the agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if user has access to the agent's company/organization
        if current_user.get("role") != "superadmin":
            user = db.query(User).filter(User.id == current_user.get("user_id")).first()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            
            if user.company_id != agent.company_id:
                raise HTTPException(status_code=403, detail="Access denied to this agent")
        
        # Import and use the topology discovery service
        from app.services.agent_topology_discovery import AgentTopologyDiscoveryService
        discovery_service = AgentTopologyDiscoveryService(db)
        
        # Get status
        status = discovery_service.get_discovery_status(agent_id)
        
        if status:
            return {
                "success": True,
                "data": status.dict(),
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=404, detail="Discovery status not found")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting discovery status: {str(e)}")


@router.get("/{agent_id}/topology/data")
async def get_agent_topology_data(
    agent_id: int,
    network_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get topology data discovered by an agent."""
    try:
        # Validate user access to the agent
        agent = db.query(Agent).filter(Agent.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        # Check if user has access to the agent's company/organization
        if current_user.get("role") != "superadmin":
            user = db.query(User).filter(User.id == current_user.get("user_id")).first()
            if not user:
                raise HTTPException(status_code=401, detail="User not found")
            
            if user.company_id != agent.company_id:
                raise HTTPException(status_code=403, detail="Access denied to this agent")
        
        # Import and use the topology discovery service
        from app.services.agent_topology_discovery import AgentTopologyDiscoveryService
        discovery_service = AgentTopologyDiscoveryService(db)
        
        # Get topology data
        topology_data = discovery_service.get_agent_topology_data(agent_id, network_id)
        
        if topology_data:
            return {
                "success": True,
                "data": topology_data,
                "timestamp": datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=404, detail="Topology data not found")
            
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error getting topology data: {str(e)}")


def parse_uptime_string(uptime_str: str) -> int:
    """Convert uptime string to seconds"""
    try:
        if not uptime_str or uptime_str == "Unknown":
            return 0
        
        # Handle formats like "6h 32m", "24 days, 23 hours, 1 minute, 53 seconds"
        total_seconds = 0
        
        # Parse days
        if "day" in uptime_str:
            days_match = re.search(r'(\d+)\s*days?', uptime_str)
            if days_match:
                total_seconds += int(days_match.group(1)) * 24 * 3600
        
        # Parse hours
        if "hour" in uptime_str:
            hours_match = re.search(r'(\d+)\s*hours?', uptime_str)
            if hours_match:
                total_seconds += int(hours_match.group(1)) * 3600
        
        # Parse minutes
        if "minute" in uptime_str:
            minutes_match = re.search(r'(\d+)\s*minutes?', uptime_str)
            if minutes_match:
                total_seconds += int(minutes_match.group(1)) * 60
        
        # Parse seconds
        if "second" in uptime_str:
            seconds_match = re.search(r'(\d+)\s*seconds?', uptime_str)
            if seconds_match:
                total_seconds += int(seconds_match.group(1))
        
        # Handle short format like "6h 32m"
        if "h" in uptime_str and "m" in uptime_str:
            hours_match = re.search(r'(\d+)h', uptime_str)
            minutes_match = re.search(r'(\d+)m', uptime_str)
            if hours_match:
                total_seconds += int(hours_match.group(1)) * 3600
            if minutes_match:
                total_seconds += int(minutes_match.group(1)) * 60
        
        # If it's already a number, return it
        if uptime_str.isdigit():
            return int(uptime_str)
        
        return total_seconds if total_seconds > 0 else 0
        
    except Exception as e:
        logger.warning(f"Error parsing uptime string '{uptime_str}': {e}")
        return 0

