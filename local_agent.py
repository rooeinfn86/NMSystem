#!/usr/bin/env python3
"""
Local Agent Service for Cisco AI Backend
Handles device discovery and management for local networks
"""

import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Dict, List, Optional
import aiohttp
import websockets
from websockets.exceptions import ConnectionClosed

# Add the app directory to the path so we can import our modules
sys.path.append(os.path.join(os.path.dirname(__file__), 'app'))

from app.core.snmp_poller import SNMPPoller, SmartSNMPDiscovery
from app.services.ssh_engine.ssh_connector import (
    run_show_command, is_ssh_reachable, ping_device, check_device_status
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('local_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class LocalAgent:
    """Local agent that handles device discovery and management."""
    
    def __init__(self, config_path: str = "agent_config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.agent_token = self.config.get("agent_token")
        self.cloud_url = self.config.get("cloud_url")
        self.company_id = self.config.get("company_id")
        self.organization_id = self.config.get("organization_id")
        self.networks = self.config.get("networks", [])
        self.capabilities = self.config.get("capabilities", [])
        self.version = self.config.get("version", "1.0.0")
        
        # Initialize SNMP poller
        self.snmp_poller = None
        self.smart_discovery = None
        
        # WebSocket connection
        self.websocket = None
        self.connected = False
        
        # Heartbeat interval (seconds)
        self.heartbeat_interval = 30
        
    def load_config(self) -> Dict:
        """Load agent configuration from file."""
        try:
            if not os.path.exists(self.config_path):
                logger.error(f"Configuration file {self.config_path} not found")
                logger.info("Please create agent_config.json with your agent details")
                sys.exit(1)
            
            with open(self.config_path, 'r') as f:
                config = json.load(f)
            
            required_fields = ["agent_token", "cloud_url", "company_id", "organization_id"]
            for field in required_fields:
                if field not in config:
                    logger.error(f"Missing required field: {field}")
                    sys.exit(1)
            
            return config
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            sys.exit(1)
    
    async def send_heartbeat(self, session: aiohttp.ClientSession):
        """Send heartbeat to cloud backend."""
        try:
            heartbeat_data = {
                "agent_token": self.agent_token,
                "status": "online",
                "capabilities": self.capabilities,
                "version": self.version
            }
            
            async with session.post(
                f"{self.cloud_url}/api/v1/agents/heartbeat",
                json=heartbeat_data
            ) as response:
                if response.status == 200:
                    logger.debug("Heartbeat sent successfully")
                else:
                    logger.warning(f"Heartbeat failed: {response.status}")
                    
        except Exception as e:
            logger.error(f"Error sending heartbeat: {e}")
    
    async def handle_discovery_request(self, discovery_data: Dict) -> Dict:
        """Handle device discovery request."""
        try:
            network_id = discovery_data.get("network_id")
            
            # Validate network access
            if network_id not in self.networks:
                return {
                    "status": "error",
                    "message": f"No access to network {network_id}",
                    "discovered_devices": [],
                    "errors": [f"Network {network_id} not accessible by this agent"]
                }
            
            # Extract discovery parameters
            ip_range = discovery_data.get("ip_range")
            start_ip = discovery_data.get("start_ip")
            end_ip = discovery_data.get("end_ip")
            username = discovery_data.get("username")
            password = discovery_data.get("password")
            device_type = discovery_data.get("device_type", "cisco_ios")
            location = discovery_data.get("location", "")
            
            # SNMP configuration
            snmp_config = {
                "snmp_version": discovery_data.get("snmp_version", "v2c"),
                "community": discovery_data.get("community", "public"),
                "username": discovery_data.get("snmp_username"),
                "auth_protocol": discovery_data.get("auth_protocol"),
                "auth_password": discovery_data.get("auth_password"),
                "priv_protocol": discovery_data.get("priv_protocol"),
                "priv_password": discovery_data.get("priv_password"),
                "port": int(discovery_data.get("snmp_port", "161"))
            }
            
            # Initialize SNMP poller
            self.snmp_poller = SNMPPoller(
                community=snmp_config["community"],
                version=snmp_config["snmp_version"],
                username=snmp_config["username"],
                auth_protocol=snmp_config["auth_protocol"],
                auth_password=snmp_config["auth_password"],
                priv_protocol=snmp_config["priv_protocol"],
                priv_password=snmp_config["priv_password"]
            )
            
            self.smart_discovery = SmartSNMPDiscovery(
                snmp_community=snmp_config["community"]
            )
            
            # Generate IP list
            ip_list = self.generate_ip_list(ip_range, start_ip, end_ip)
            
            if not ip_list:
                return {
                    "status": "error",
                    "message": "No valid IP addresses to scan",
                    "discovered_devices": [],
                    "errors": ["Invalid IP range or no IPs to scan"]
                }
            
            logger.info(f"Starting discovery for {len(ip_list)} IPs")
            
            # Discover devices
            discovered_devices = []
            errors = []
            
            for ip in ip_list:
                try:
                    device_info = await self.scan_single_device(
                        ip, username, password, device_type, location, snmp_config
                    )
                    
                    if device_info["status"] == "success":
                        discovered_devices.append(device_info)
                        logger.info(f"Discovered device: {device_info.get('hostname', ip)}")
                    else:
                        errors.append(f"Failed to scan {ip}: {device_info.get('message', 'Unknown error')}")
                        
                except Exception as e:
                    errors.append(f"Error scanning {ip}: {str(e)}")
                    logger.error(f"Error scanning {ip}: {e}")
            
            return {
                "status": "success",
                "message": f"Discovery completed. Found {len(discovered_devices)} devices",
                "discovered_devices": discovered_devices,
                "errors": errors
            }
            
        except Exception as e:
            logger.error(f"Error in discovery request: {e}")
            return {
                "status": "error",
                "message": f"Discovery failed: {str(e)}",
                "discovered_devices": [],
                "errors": [str(e)]
            }
    
    def generate_ip_list(self, ip_range: Optional[str], start_ip: Optional[str], end_ip: Optional[str]) -> List[str]:
        """Generate list of IP addresses to scan."""
        import ipaddress
        
        ip_list = []
        
        try:
            if ip_range:
                # Handle CIDR notation (e.g., "192.168.1.0/24")
                if '/' in ip_range:
                    network = ipaddress.IPv4Network(ip_range, strict=False)
                    ip_list = [str(ip) for ip in network.hosts()]
                # Handle range notation (e.g., "192.168.1.1-192.168.1.254")
                elif '-' in ip_range:
                    start, end = ip_range.split('-')
                    start_ip = ipaddress.IPv4Address(start.strip())
                    end_ip = ipaddress.IPv4Address(end.strip())
                    
                    current_ip = start_ip
                    while current_ip <= end_ip:
                        ip_list.append(str(current_ip))
                        current_ip += 1
                else:
                    # Single IP
                    ip_list = [ip_range]
            
            elif start_ip and end_ip:
                start = ipaddress.IPv4Address(start_ip)
                end = ipaddress.IPv4Address(end_ip)
                
                current_ip = start
                while current_ip <= end:
                    ip_list.append(str(current_ip))
                    current_ip += 1
            
            return ip_list
            
        except Exception as e:
            logger.error(f"Error generating IP list: {e}")
            return []
    
    async def scan_single_device(self, ip: str, username: str, password: str, 
                                device_type: str, location: str, snmp_config: Dict) -> Dict:
        """Scan a single device for discovery."""
        try:
            # Check if device is reachable
            if not ping_device(ip):
                return {
                    "status": "failed",
                    "message": f"Device {ip} is not reachable",
                    "ip": ip
                }
            
            # Check SNMP connectivity
            if not self.snmp_poller.test_connection(ip):
                return {
                    "status": "failed",
                    "message": f"SNMP connection failed for {ip}",
                    "ip": ip
                }
            
            # Get basic device info via SNMP
            device_info = self.snmp_poller.get_basic_device_info(ip)
            
            if not device_info:
                return {
                    "status": "failed",
                    "message": f"Could not retrieve device info for {ip}",
                    "ip": ip
                }
            
            # Check SSH connectivity
            ssh_reachable = is_ssh_reachable(ip, username, password)
            
            # Get hostname
            hostname = device_info.get('sysName', ip)
            if not hostname or hostname == 'ip':
                hostname = ip
            
            # Get model and description
            model = device_info.get('sysObjectID', 'Unknown')
            description = device_info.get('sysDescr', 'Unknown')
            
            # Try to get more specific model info
            if 'cisco' in description.lower():
                if 'ios-xe' in description.lower():
                    platform = 'cisco_ios_xe'
                else:
                    platform = 'cisco_ios'
            else:
                platform = device_type
            
            # Get OS version if available
            os_version = "Unknown"
            if 'Version' in description:
                # Extract version from description
                import re
                version_match = re.search(r'Version\s+([^\s,]+)', description)
                if version_match:
                    os_version = version_match.group(1)
            
            # Get serial number if available
            serial_number = device_info.get('sysObjectID', 'Unknown')
            
            return {
                "status": "success",
                "hostname": hostname,
                "model": model,
                "platform": platform,
                "os_version": os_version,
                "serial_number": serial_number,
                "ip": ip,
                "ping_status": True,
                "snmp_status": True,
                "ssh_status": ssh_reachable,
                "location": location or "Default"
            }
            
        except Exception as e:
            logger.error(f"Error scanning device {ip}: {e}")
            return {
                "status": "failed",
                "message": str(e),
                "ip": ip
            }
    
    async def handle_websocket_message(self, message: str) -> Dict:
        """Handle incoming WebSocket message."""
        try:
            data = json.loads(message)
            message_type = data.get("type")
            
            if message_type == "discovery_request":
                return await self.handle_discovery_request(data.get("data", {}))
            elif message_type == "ping":
                return {"type": "pong", "timestamp": datetime.utcnow().isoformat()}
            else:
                return {"type": "error", "message": f"Unknown message type: {message_type}"}
                
        except json.JSONDecodeError:
            return {"type": "error", "message": "Invalid JSON"}
        except Exception as e:
            logger.error(f"Error handling WebSocket message: {e}")
            return {"type": "error", "message": str(e)}
    
    async def connect_websocket(self):
        """Connect to cloud backend via WebSocket."""
        try:
            ws_url = f"{self.cloud_url.replace('http', 'ws')}/ws/agent/{self.agent_token}"
            self.websocket = await websockets.connect(ws_url)
            self.connected = True
            logger.info("Connected to cloud backend via WebSocket")
            
            # Send initial connection message
            await self.websocket.send(json.dumps({
                "type": "agent_connect",
                "agent_token": self.agent_token,
                "capabilities": self.capabilities,
                "version": self.version
            }))
            
        except Exception as e:
            logger.error(f"Failed to connect to WebSocket: {e}")
            self.connected = False
    
    async def run_websocket_loop(self):
        """Run the WebSocket message loop."""
        while True:
            try:
                if not self.connected:
                    await self.connect_websocket()
                    await asyncio.sleep(5)  # Wait before retry
                    continue
                
                # Wait for messages
                message = await self.websocket.recv()
                logger.debug(f"Received message: {message}")
                
                # Handle message
                response = await self.handle_websocket_message(message)
                
                # Send response
                await self.websocket.send(json.dumps(response))
                
            except ConnectionClosed:
                logger.warning("WebSocket connection closed")
                self.connected = False
                await asyncio.sleep(5)  # Wait before reconnecting
            except Exception as e:
                logger.error(f"Error in WebSocket loop: {e}")
                self.connected = False
                await asyncio.sleep(5)
    
    async def run_heartbeat_loop(self):
        """Run the heartbeat loop."""
        async with aiohttp.ClientSession() as session:
            while True:
                try:
                    await self.send_heartbeat(session)
                    await asyncio.sleep(self.heartbeat_interval)
                except Exception as e:
                    logger.error(f"Error in heartbeat loop: {e}")
                    await asyncio.sleep(self.heartbeat_interval)
    
    async def run(self):
        """Run the agent."""
        logger.info("Starting Local Agent Service")
        logger.info(f"Company ID: {self.company_id}")
        logger.info(f"Organization ID: {self.organization_id}")
        logger.info(f"Networks: {self.networks}")
        logger.info(f"Capabilities: {self.capabilities}")
        
        # Start both loops concurrently
        await asyncio.gather(
            self.run_websocket_loop(),
            self.run_heartbeat_loop()
        )


def create_sample_config():
    """Create a sample configuration file."""
    sample_config = {
                    "agent_token": "YOUR_AGENT_TOKEN_HERE",
        "cloud_url": "https://your-cloud-backend.com",
        "company_id": 1,
        "organization_id": 1,
        "networks": [1, 2, 3],
        "capabilities": ["snmp_discovery", "ssh_config", "health_monitoring"],
        "version": "1.0.0"
    }
    
    with open("agent_config_sample.json", "w") as f:
        json.dump(sample_config, f, indent=2)
    
    logging.info("Sample configuration created: agent_config_sample.json")
    logging.info("Please copy it to agent_config.json and update with your values")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--create-config":
        create_sample_config()
        sys.exit(0)
    
    try:
        agent = LocalAgent()
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error(f"Agent error: {e}")
        sys.exit(1) 