#!/usr/bin/env python3
"""
Cisco AI Agent Service
Local agent for device discovery and monitoring
"""

import os
import sys
import json
import time
import logging
import threading
import subprocess
import platform
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import requests
import websocket
import paramiko
import psutil
import tkinter as tk
from tkinter import ttk, messagebox

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cisco_ai_agent.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Try to import SNMP libraries, but make them optional
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UsmUserData,
        UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
    )
    SNMP_AVAILABLE = True
    logger.info("SNMP libraries loaded successfully")
except ImportError as e:
    logger.warning(f"pysnmp library not available: {e}. SNMP discovery will be disabled.")
    SNMP_AVAILABLE = False
except Exception as e:
    logger.warning(f"SNMP library error: {e}. SNMP discovery will be disabled.")
    SNMP_AVAILABLE = False

class CiscoAIAgent:
    """Main agent class for device discovery and monitoring"""
    
    def __init__(self, config_path: str = "agent_config.json"):
        self.config = self.load_config(config_path)
        self.backend_url = self.config['backend_url']
        self.agent_token = self.config['agent_token']
        self.agent_name = self.config['agent_name']
        self.agent_id = self.config.get('agent_id')  # Add agent_id from config
        self.heartbeat_interval = self.config.get('heartbeat_interval', 30)
        
        # WebSocket connection for real-time communication
        self.ws = None
        self.ws_connected = False
        
        # Discovery state
        self.discovered_devices = {}
        self.discovery_running = False
        
        # Service state
        self.running = False
        
        logger.info(f"Initialized Cisco AI Agent: {self.agent_name}")
    
    def load_config(self, config_path: str) -> Dict:
        """Load agent configuration"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
            logger.info("Configuration loaded successfully")
            return config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
    
    def start(self):
        """Start the agent service"""
        logger.info("Starting Cisco AI Agent service")
        
        # Test agent token validity first and get agent_id
        logger.info(f"Testing agent token: {self.agent_token[:10]}...")
        test_response = self.safe_request(
            'GET',
            f"{self.backend_url.rstrip('/')}/api/v1/agents/agent/organizations",
            headers={'X-Agent-Token': self.agent_token},
            timeout=15
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
        
        # Try to get agent_id from the response
        try:
            if test_response and test_response.status_code == 200:
                response_data = test_response.json()
                if isinstance(response_data, list) and len(response_data) > 0:
                    # The response might contain agent info
                    for org in response_data:
                        if 'agent_id' in org:
                            self.agent_id = org['agent_id']
                            logger.info(f"Found agent_id: {self.agent_id}")
                            break
        except Exception as e:
            logger.warning(f"Could not extract agent_id from response: {e}")
        
        # If we still don't have agent_id, try to get it from the agent info endpoint
        if not self.agent_id:
            try:
                agent_info_response = self.safe_request(
                    'GET',
                    f"{self.backend_url}/api/v1/agents/agent/networks",
                    headers={'X-Agent-Token': self.agent_token}
                )
                if agent_info_response and agent_info_response.status_code == 200:
                    # Try to extract agent_id from the response headers or body
                    # For now, we'll use a fallback approach
                    pass
            except Exception as e:
                logger.warning(f"Could not get agent info: {e}")
        
        logger.info("Agent token validation successful")
        self.running = True
        
        # Start WebSocket connection
        self.start_websocket()
        
        # Start heartbeat thread
        heartbeat_thread = threading.Thread(target=self.heartbeat_loop, daemon=True)
        heartbeat_thread.start()
        
        # Start discovery thread
        discovery_thread = threading.Thread(target=self.discovery_loop, daemon=True)
        discovery_thread.start()
        
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
                time.sleep(10)  # Poll every 10 seconds for faster response
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                time.sleep(30)  # Wait longer on error
    
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
                f"{self.backend_url.rstrip('/')}/api/v1/agents/{self.config['agent_id']}/pending-discovery",
                headers={'X-Agent-Token': self.agent_token},
                timeout=15
            )
            
            if response and response.status_code == 200:
                discovery_requests = response.json()
                for request in discovery_requests:
                    if request.get('type') == 'discovery':
                        self.handle_enhanced_discovery_request(request)
                    elif request.get('type') == 'status_test':
                        self.handle_status_test_request(request)
                    
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
    
    def handle_status_test_request(self, request_data: Dict):
        """Handle status test request for devices"""
        try:
            network_id = request_data.get('network_id')
            devices = request_data.get('devices', [])
            session_id = request_data.get('session_id', 'unknown')
            
            logger.info(f"Received status test request: session_id={session_id}, network_id={network_id}, devices={len(devices)}")
            
            # Start status testing in background thread
            status_thread = threading.Thread(
                target=self.perform_status_test,
                args=(session_id, network_id, devices),
                daemon=True
            )
            status_thread.start()
            
        except Exception as e:
            logger.error(f"Error handling status test request: {e}")
    
    def perform_status_test(self, session_id: str, network_id: int, devices: List[Dict]):
        """Perform status testing for devices"""
        try:
            logger.info(f"Starting status test for session {session_id}: {len(devices)} devices")
            
            device_statuses = []
            
            for i, device in enumerate(devices):
                try:
                    device_ip = device.get('ip')
                    snmp_config = device.get('snmp_config')
                    
                    logger.info(f"[{session_id}] Testing status for device {i+1}/{len(devices)}: {device_ip}")
                    logger.info(f"[{session_id}] Device {device_ip} SNMP config received: {snmp_config}")
                    
                    # Test device status
                    status_result = self.test_device_status(device_ip, snmp_config)
                    device_statuses.append(status_result)
                    
                    logger.info(f"[{session_id}] Status test result for {device_ip}: ping={status_result['ping_status']}, snmp={status_result['snmp_status']}")
                    
                except Exception as e:
                    logger.error(f"[{session_id}] Error testing status for device {device.get('ip', 'unknown')}: {e}")
                    continue
            
            # Report results to backend
            if device_statuses:
                success = self.report_device_status(network_id, device_statuses)
                if success:
                    logger.info(f"[{session_id}] Successfully reported status for {len(device_statuses)} devices")
                else:
                    logger.error(f"[{session_id}] Failed to report device status to backend")
            else:
                logger.warning(f"[{session_id}] No device statuses to report")
            
        except Exception as e:
            logger.error(f"[{session_id}] Error performing status test: {e}")
    
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
                    capabilities = []
                    
                    if method == 'snmp_only' or method == 'auto':
                        logger.info(f"Trying SNMP discovery for {ip_address}")
                        device_info = self.enhanced_snmp_discovery(ip_address, discovery_method, credentials)
                        if device_info:
                            logger.info(f"SNMP discovery successful for {ip_address}")
                            logger.info(f"SNMP serial number: {device_info.get('serial_number', 'Not set')}")
                            capabilities.append('snmp')
                            
                            # If SNMP didn't provide serial number, try SSH to get it
                            if device_info.get('serial_number') == 'Unknown' and method == 'auto':
                                logger.info(f"SNMP didn't provide serial number, trying SSH for {ip_address}")
                                ssh_device_info = self.enhanced_ssh_discovery(ip_address, credentials)
                                if ssh_device_info and ssh_device_info.get('serial_number') != 'Unknown':
                                    device_info['serial_number'] = ssh_device_info['serial_number']
                                    logger.info(f"Updated serial number from SSH: {ssh_device_info['serial_number']}")
                                    capabilities.append('ssh')
                                else:
                                    logger.warning("SSH also didn't provide serial number")
                                    # Log SSH failure for auto method
                                    if method == 'auto':
                                        error_msg = f"Device at {ip_address} SSH authentication failed - could not retrieve serial number"
                                        errors.append(error_msg)
                                        logger.warning(error_msg)
                            else:
                                logger.info(f"SNMP provided serial number: {device_info.get('serial_number')}")
                        else:
                            logger.info(f"SNMP discovery failed for {ip_address}, trying SSH")
                            # Add SNMP-specific error for better logging
                            if method == 'snmp_only':
                                error_msg = f"Device at {ip_address} SNMP discovery failed - device may be unreachable, SNMP not configured, or wrong community string"
                                errors.append(error_msg)
                                logger.warning(error_msg)
                            elif method == 'auto':
                                # Log SNMP failure for auto method even when we'll try SSH
                                error_msg = f"Device at {ip_address} SNMP discovery failed - will try SSH as fallback"
                                errors.append(error_msg)
                                logger.warning(error_msg)
                    
                    if not device_info and (method == 'ssh_only' or method == 'auto'):
                        logger.info(f"Trying SSH discovery for {ip_address}")
                        device_info = self.enhanced_ssh_discovery(ip_address, credentials)
                        if device_info:
                            logger.info(f"SSH discovery successful for {ip_address}")
                            capabilities.append('ssh')
                        else:
                            logger.info(f"SSH discovery failed for {ip_address}")
                            # Add SSH-specific error for better logging
                            if method == 'ssh_only':
                                error_msg = f"Device at {ip_address} SSH discovery failed - authentication failed or SSH not enabled"
                                errors.append(error_msg)
                                logger.warning(error_msg)
                    
                    if not device_info and method == 'ping_only':
                        device_info = self.ping_discovery(ip_address)
                        if device_info:
                            capabilities.append('ping')
                    
                    if device_info:
                        device_info['discovered_by_agent'] = self.config['agent_id']
                        device_info['discovered_at'] = datetime.now().isoformat()
                        device_info['session_id'] = session_id
                        
                        # Set capabilities based on what methods were successful
                        device_info['capabilities'] = capabilities
                        discovered_devices.append(device_info)
                    else:
                        # Device was not discovered - create specific error message
                        if method == 'ping_only':
                            error_msg = f"Device at {ip_address} is unreachable (ping failed)"
                        elif method == 'snmp_only':
                            error_msg = f"Device at {ip_address} SNMP discovery failed - device may be unreachable or SNMP not configured"
                        elif method == 'ssh_only':
                            # SSH error already added above
                            pass
                        else:  # auto method
                            error_msg = f"Device at {ip_address} discovery failed - device unreachable via all methods (ping, SNMP, SSH)"
                            errors.append(error_msg)
                            logger.warning(error_msg)
                        
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
        if not SNMP_AVAILABLE:
            logger.warning("SNMP discovery disabled - pysnmp library not available")
            return None
            
        try:
            snmp_config = discovery_method.get('snmp_config', {})
            snmp_version = discovery_method.get('snmp_version', 'v2c')
            snmp_community = discovery_method.get('snmp_community', 'cisco')  # Default to cisco community
            snmp_port = discovery_method.get('snmp_port', 161)
            
            logger.info(f"SNMP discovery config: version={snmp_version}, community={snmp_community}, port={snmp_port}")
            
            if snmp_version == 'v3':
                return self.snmpv3_get_device_info(ip_address, snmp_config, snmp_port)
            else:
                return self.snmpv1v2c_get_device_info(ip_address, snmp_community, snmp_port, snmp_version)
                
        except Exception as e:
            logger.error(f"Enhanced SNMP discovery failed for {ip_address}: {e}")
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
                        logger.error(f"SNMPv3 timeout for {ip_address}: {errorIndication}")
                    elif 'no response' in error_msg:
                        logger.error(f"SNMPv3 no response from {ip_address}: {errorIndication}")
                    elif 'authentication' in error_msg or 'username' in error_msg:
                        logger.error(f"SNMPv3 authentication failed for {ip_address}: {errorIndication}")
                    else:
                        logger.error(f"SNMPv3 error indication for {ip_address}: {errorIndication}")
                    return None
                if errorStatus:
                    logger.error(f"SNMPv3 error status for {ip_address}: {errorStatus.prettyPrint()}")
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
                    'capabilities': ['snmp'],
                    'snmp_config': {
                        'snmp_version': 'v3',
                        'username': snmp_config.get('username', ''),
                        'auth_protocol': snmp_config.get('auth_protocol'),
                        'auth_password': snmp_config.get('auth_password'),
                        'priv_protocol': snmp_config.get('priv_protocol'),
                        'priv_password': snmp_config.get('priv_password'),
                        'port': port
                    }
                }
                
                return device_info
                
        except Exception as e:
            logger.error(f"SNMPv3 query failed for {ip_address}: {e}")
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
                        logger.error(f"SNMP timeout for {ip_address}: {errorIndication}")
                    elif 'no response' in error_msg:
                        logger.error(f"SNMP no response from {ip_address}: {errorIndication}")
                    elif 'authentication' in error_msg or 'community' in error_msg:
                        logger.error(f"SNMP authentication failed for {ip_address}: {errorIndication}")
                    else:
                        logger.error(f"SNMP error indication for {ip_address}: {errorIndication}")
                    return None
                if errorStatus:
                    logger.error(f"SNMP error status for {ip_address}: {errorStatus}")
                    return None
                
                # Extract device information
                description = str(varBinds[0][1]) if varBinds and varBinds[0][1] else ''
                hostname = str(varBinds[1][1]) if len(varBinds) > 1 and varBinds[1][1] else ip_address
                location = str(varBinds[2][1]) if len(varBinds) > 2 and varBinds[2][1] else 'Unknown'
                contact = str(varBinds[3][1]) if len(varBinds) > 3 and varBinds[3][1] else 'Unknown'
                uptime = str(varBinds[5][1]) if len(varBinds) > 5 and varBinds[5][1] else 'Unknown'
                
                logger.info(f"SNMP device info - Description: {description[:100]}...")
                logger.info(f"SNMP device info - Hostname: {hostname}")
                logger.info(f"SNMP device info - Location: {location}")
                logger.info(f"SNMP device info - Contact: {contact}")
                logger.info(f"SNMP device info - Uptime: {uptime}")
                
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
            logger.error(f"SNMPv1/v2c query failed for {ip_address}: {e}")
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
        """Enhanced SSH discovery with multi-vendor device detection"""
        ssh = None
        try:
            username = credentials.get('username', '')
            password = credentials.get('password', '')
            
            if not username or not password:
                return None
            
            # Try to connect via SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip_address, username=username, password=password, timeout=5)
            
            # Get device information via SSH commands
            device_info = {
                'ip_address': ip_address,
                'discovery_method': 'ssh',
                'capabilities': ['ssh']
            }
            
            # Get all device information in a single session
            try:
                # Check if SSH connection is active
                if not ssh.get_transport() or not ssh.get_transport().is_active():
                    logger.error("SSH connection is not active")
                    raise Exception("SSH session not active")
                
                # Get version information first (this is more reliable)
                stdin, stdout, stderr = ssh.exec_command('show version', timeout=10)
                version_output = stdout.read().decode().strip()
                device_info['description'] = version_output[:200] + '...' if len(version_output) > 200 else version_output
                
                # Extract hostname from version output or use IP as fallback
                hostname = self.extract_hostname_from_version(version_output)
                if not hostname:
                    # Try to get hostname via a different method
                    try:
                        stdin, stdout, stderr = ssh.exec_command('show running-config | include hostname', timeout=5)
                        hostname_output = stdout.read().decode().strip()
                        hostname = self.extract_hostname_from_config(hostname_output)
                    except:
                        hostname = ip_address  # Use IP as fallback
                
                device_info['hostname'] = hostname if hostname else ip_address
                logger.info(f"SSH hostname: {hostname}")
                
                # Detect device type from version output
                device_type = 'cisco'  # Default to Cisco
                if 'cisco' in version_output.lower():
                    device_type = 'cisco'
                    logger.info("Detected Cisco device")
                elif 'juniper' in version_output.lower() or 'junos' in version_output.lower():
                    device_type = 'juniper'
                    logger.info("Detected Juniper device")
                elif 'arista' in version_output.lower() or 'eos' in version_output.lower():
                    device_type = 'arista'
                    logger.info("Detected Arista device")
                elif 'linux' in version_output.lower() or 'unix' in version_output.lower():
                    device_type = 'linux'
                    logger.info("Detected Linux device")
                
                device_info['device_type'] = device_type
                
                # Extract OS version and serial number based on device type
                if device_type in ['cisco', 'cisco_ios', 'cisco_nxos', 'cisco_ios_xe']:
                    device_info['os_version'] = self.extract_cisco_os_version(version_output)
                    device_info['serial_number'] = self.extract_cisco_serial(version_output)
                    logger.info(f"Cisco OS version: {device_info['os_version']}")
                    logger.info(f"Cisco serial: {device_info['serial_number']}")
                    
                    # Get location - but don't fail if SSH session is lost
                    try:
                        if ssh.get_transport() and ssh.get_transport().is_active():
                            stdin, stdout, stderr = ssh.exec_command('show running-config | include snmp-server location', timeout=5)
                            location_output = stdout.read().decode().strip()
                            device_info['location'] = self.extract_cisco_location(location_output)
                            logger.info(f"Cisco location: {device_info['location']}")
                        else:
                            logger.warning("SSH session lost, using default location")
                            device_info['location'] = 'Unknown'
                    except Exception as e:
                        logger.warning(f"Could not get location via SSH: {e}")
                        device_info['location'] = 'Unknown'
                    
                elif device_type in ['juniper', 'juniper_junos']:
                    device_info['os_version'] = self.extract_juniper_os_version(version_output)
                    device_info['serial_number'] = 'Unknown'  # Juniper serial extraction would go here
                    device_info['location'] = 'Unknown'
                    
                elif device_type in ['arista', 'arista_eos']:
                    device_info['os_version'] = self.extract_arista_os_version(version_output)
                    device_info['serial_number'] = 'Unknown'  # Arista serial extraction would go here
                    device_info['location'] = 'Unknown'
                    
                else:
                    device_info['os_version'] = 'Unknown'
                    device_info['serial_number'] = 'Unknown'
                    device_info['location'] = 'Unknown'
                
            except Exception as e:
                logger.error(f"Error extracting device info: {e}")
                # If we already extracted some info, keep it
                if 'serial_number' not in device_info or device_info['serial_number'] == 'Unknown':
                    device_info['serial_number'] = 'Unknown'
                if 'os_version' not in device_info or device_info['os_version'] == 'Unknown':
                    device_info['os_version'] = 'Unknown'
                if 'location' not in device_info or device_info['location'] == 'Unknown':
                    device_info['location'] = 'Unknown'
                if 'hostname' not in device_info or device_info['hostname'] == 'Unknown':
                    device_info['hostname'] = ip_address
            
            return device_info
                
        except Exception as e:
            error_msg = str(e).lower()
            if 'authentication' in error_msg or 'password' in error_msg or 'permission denied' in error_msg:
                logger.error(f"SSH authentication failed for {ip_address}: {e}")
            elif 'timeout' in error_msg or 'timed out' in error_msg:
                logger.error(f"SSH connection timeout for {ip_address}: {e}")
            elif 'connection refused' in error_msg or 'no route to host' in error_msg:
                logger.error(f"SSH connection refused for {ip_address}: {e}")
            else:
                logger.error(f"Enhanced SSH discovery failed for {ip_address}: {e}")
            return None
        finally:
            # Always close SSH connection
            if ssh:
                try:
                    ssh.close()
                except:
                    pass
    
    def detect_device_vendor(self, ssh) -> str:
        """Detect device vendor based on SSH prompt and commands"""
        try:
            # Try different commands to detect vendor
            commands_to_try = [
                ('show version', ['cisco', 'juniper', 'arista']),
                ('show system', ['juniper']),
                ('show version | include Software', ['cisco']),
                ('uname -a', ['linux', 'unix']),
                ('cat /etc/os-release', ['linux']),
            ]
            
            for command, vendors in commands_to_try:
                try:
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=5)
                    output = stdout.read().decode().strip()
                    logger.info(f"Command '{command}' output: {output[:200]}...")
                    
                    if 'cisco' in output.lower():
                        logger.info("Detected Cisco device")
                        return 'cisco'
                    elif 'juniper' in output.lower() or 'junos' in output.lower():
                        logger.info("Detected Juniper device")
                        return 'juniper'
                    elif 'arista' in output.lower() or 'eos' in output.lower():
                        logger.info("Detected Arista device")
                        return 'arista'
                    elif 'linux' in output.lower() or 'unix' in output.lower():
                        logger.info("Detected Linux device")
                        return 'linux'
                except Exception as e:
                    logger.debug(f"Command '{command}' failed: {e}")
                    continue
            
            # Default to generic if we can't detect
            logger.info("Could not detect vendor, using generic")
            return 'generic'
            
        except Exception as e:
            logger.error(f"Vendor detection failed: {e}")
            return 'generic'
    
    def get_cisco_device_info(self, ssh) -> Dict:
        """Get device information for Cisco devices"""
        device_info = {}
        
        try:
            # Check if SSH connection is still active
            if not ssh.get_transport() or not ssh.get_transport().is_active():
                logger.error("SSH connection is not active")
                raise Exception("SSH session not active")
            
            # Get hostname
            stdin, stdout, stderr = ssh.exec_command('show hostname', timeout=5)
            hostname = stdout.read().decode().strip()
            device_info['hostname'] = hostname if hostname else 'Unknown'
            logger.info(f"Cisco hostname: {hostname}")
            
            # Get version information
            stdin, stdout, stderr = ssh.exec_command('show version', timeout=10)
            version_output = stdout.read().decode().strip()
            device_info['description'] = version_output[:200] + '...' if len(version_output) > 200 else version_output
            device_info['os_version'] = self.extract_cisco_os_version(version_output)
            device_info['serial_number'] = self.extract_cisco_serial(version_output)
            logger.info(f"Cisco OS version: {device_info['os_version']}")
            logger.info(f"Cisco serial: {device_info['serial_number']}")
            
            # Get location
            stdin, stdout, stderr = ssh.exec_command('show running-config | include snmp-server location', timeout=5)
            location_output = stdout.read().decode().strip()
            device_info['location'] = self.extract_cisco_location(location_output)
            logger.info(f"Cisco location: {device_info['location']}")
            
        except Exception as e:
            logger.error(f"Cisco device info extraction failed: {e}")
            device_info.update({
                'hostname': 'Unknown',
                'description': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown',
                'location': 'Unknown'
            })
        
        return device_info
    
    def get_juniper_device_info(self, ssh) -> Dict:
        """Get device information for Juniper devices"""
        device_info = {}
        
        try:
            # Get hostname
            stdin, stdout, stderr = ssh.exec_command('show system host-name', timeout=5)
            hostname = stdout.read().decode().strip()
            device_info['hostname'] = hostname if hostname else 'Unknown'
            
            # Get version information
            stdin, stdout, stderr = ssh.exec_command('show version', timeout=10)
            version_output = stdout.read().decode().strip()
            device_info['description'] = version_output[:200] + '...' if len(version_output) > 200 else version_output
            device_info['os_version'] = self.extract_juniper_os_version(version_output)
            
        except Exception as e:
            logger.debug(f"Juniper device info extraction failed: {e}")
            device_info.update({
                'hostname': 'Unknown',
                'description': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown',
                'location': 'Unknown'
            })
        
        return device_info
    
    def get_arista_device_info(self, ssh) -> Dict:
        """Get device information for Arista devices"""
        device_info = {}
        
        try:
            # Get hostname
            stdin, stdout, stderr = ssh.exec_command('show hostname', timeout=5)
            hostname = stdout.read().decode().strip()
            device_info['hostname'] = hostname if hostname else 'Unknown'
            
            # Get version information
            stdin, stdout, stderr = ssh.exec_command('show version', timeout=10)
            version_output = stdout.read().decode().strip()
            device_info['description'] = version_output[:200] + '...' if len(version_output) > 200 else version_output
            device_info['os_version'] = self.extract_arista_os_version(version_output)
            
        except Exception as e:
            logger.debug(f"Arista device info extraction failed: {e}")
            device_info.update({
                'hostname': 'Unknown',
                'description': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown',
                'location': 'Unknown'
            })
        
        return device_info
    
    def get_linux_device_info(self, ssh) -> Dict:
        """Get device information for Linux/Unix devices"""
        device_info = {}
        
        try:
            # Get hostname
            stdin, stdout, stderr = ssh.exec_command('hostname', timeout=5)
            hostname = stdout.read().decode().strip()
            device_info['hostname'] = hostname if hostname else 'Unknown'
            
            # Get system information
            stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=5)
            system_info = stdout.read().decode().strip()
            device_info['description'] = system_info
            device_info['os_version'] = self.extract_linux_os_version(system_info)
            
            # Get location (if available)
            stdin, stdout, stderr = ssh.exec_command('cat /etc/location 2>/dev/null || echo "Unknown"', timeout=5)
            location = stdout.read().decode().strip()
            device_info['location'] = location if location != 'Unknown' else 'Unknown'
            
        except Exception as e:
            logger.debug(f"Linux device info extraction failed: {e}")
            device_info.update({
                'hostname': 'Unknown',
                'description': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown',
                'location': 'Unknown'
            })
        
        return device_info
    
    def get_generic_device_info(self, ssh) -> Dict:
        """Get device information using generic commands"""
        device_info = {}
        
        try:
            # Try common commands
            commands = [
                ('hostname', 'hostname'),
                ('uname -a', 'description'),
                ('cat /proc/version', 'description'),
                ('show version', 'description'),
                ('show system', 'description')
            ]
            
            for command, field in commands:
                try:
                    stdin, stdout, stderr = ssh.exec_command(command, timeout=5)
                    output = stdout.read().decode().strip()
                    if output:
                        device_info[field] = output
                        break
                except:
                    continue
            
            # Set defaults for missing fields
            device_info.setdefault('hostname', 'Unknown')
            device_info.setdefault('description', 'Unknown')
            device_info.setdefault('os_version', 'Unknown')
            device_info.setdefault('serial_number', 'Unknown')
            device_info.setdefault('location', 'Unknown')
            
        except Exception as e:
            logger.debug(f"Generic device info extraction failed: {e}")
            device_info.update({
                'hostname': 'Unknown',
                'description': 'Unknown',
                'os_version': 'Unknown',
                'serial_number': 'Unknown',
                'location': 'Unknown'
            })
        
        return device_info
    
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
            else:
                # Ping failed - log the specific error
                error_output = result.stderr.strip() if result.stderr else result.stdout.strip()
                logger.warning(f"Ping failed for {ip_address}: return code {result.returncode}, output: {error_output}")
                return None
            
        except subprocess.TimeoutExpired:
            logger.warning(f"Ping timeout for {ip_address} - device may be unreachable")
            return None
        except Exception as e:
            logger.debug(f"Ping discovery failed for {ip_address}: {e}")
            return None

    def test_device_status(self, device_ip: str, snmp_config: Dict = None) -> Dict:
        """Test device connectivity and SNMP status"""
        try:
            # Test ping
            ping_ok = self.ping_device(device_ip)
            logger.info(f"[STATUS TEST] {device_ip} ping: {'SUCCESS' if ping_ok else 'FAILED'}")
            
            # Test SNMP if configuration provided
            snmp_ok = False
            if snmp_config and SNMP_AVAILABLE:
                try:
                    snmp_ok = self.test_snmp_connectivity(device_ip, snmp_config)
                    logger.info(f"[STATUS TEST] {device_ip} SNMP: {'SUCCESS' if snmp_ok else 'FAILED'}")
                except Exception as e:
                    logger.error(f"SNMP test error for {device_ip}: {e}")
                    snmp_ok = False
            else:
                logger.info(f"[STATUS TEST] {device_ip} SNMP: SKIPPED (no config provided)")
            
            return {
                "ip": device_ip,
                "ping_status": ping_ok,
                "snmp_status": snmp_ok,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"Status test error for {device_ip}: {e}")
            return {
                "ip": device_ip,
                "ping_status": False,
                "snmp_status": False,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e)
            }

    def test_snmp_connectivity(self, ip: str, snmp_config: Dict) -> bool:
        """Test SNMP connectivity to a device"""
        try:
            if not SNMP_AVAILABLE:
                logger.error(f"SNMP library not available for {ip}")
                return False
                
            community = snmp_config.get('community', 'public')
            port = snmp_config.get('port', 161)
            
            logger.info(f"[SNMP TEST] Testing {ip} with community='{community}', port={port}")
            
            # Simple SNMP get for system description
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=2, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication:
                logger.error(f"[SNMP TEST] {ip} errorIndication: {errorIndication}")
                return False
                
            if errorStatus:
                logger.error(f"[SNMP TEST] {ip} errorStatus: {errorStatus.prettyPrint()}")
                return False
            
            logger.info(f"[SNMP TEST] {ip} SNMP test SUCCESS")
            return True
        except Exception as e:
            logger.error(f"[SNMP TEST] {ip} SNMP connectivity test failed: {e}")
            return False

    def report_device_status(self, network_id: int, device_statuses: List[Dict]):
        """Report device statuses to the backend"""
        try:
            # Extract agent_id from the agent token or use a fallback
            # For now, let's use the agent_id from the config or extract from token
            agent_id = self.agent_id
            if not agent_id:
                # Try to extract from token or use a default
                # The agent_id is usually in the token or we can get it from the backend
                agent_id = 94  # Fallback for now
            
            # Use agent-specific endpoint
            url = f"{self.backend_url}/api/v1/agents/{agent_id}/device-status-report"
            payload = {
                "network_id": network_id,
                "device_statuses": device_statuses
            }
            
            response = self.safe_request(
                'POST',
                url,
                json=payload,
                headers={'X-Agent-Token': self.agent_token},
                timeout=15
            )
            
            if response and response.status_code == 200:
                logger.info(f"Successfully reported status for {len(device_statuses)} devices")
                return True
            else:
                logger.error(f"Failed to report device status: {response.status_code if response else 'No response'}")
                return False
        except Exception as e:
            logger.error(f"Error reporting device status: {e}")
            return False

    def ping_device(self, ip: str) -> bool:
        """Test ping connectivity to a device"""
        try:
            system = platform.system().lower()
            if system == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]

            output = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return output.returncode == 0
        except Exception as e:
            logger.error(f"Ping test failed for {ip}: {e}")
            return False
    
    def extract_cisco_os_version(self, version_output: str) -> str:
        """Extract Cisco OS version from show version output"""
        try:
            import re
            version_output_lower = version_output.lower()
            
            # Look for IOS version patterns
            patterns = [
                r'ios.*?version\s+([^\s,]+)',
                r'ios.*?([0-9]+\.[0-9]+[a-z]*)',
                r'version\s+([0-9]+\.[0-9]+[a-z]*)',
                r'cisco ios.*?([0-9]+\.[0-9]+[a-z]*)',
                r'ios-xe.*?([0-9]+\.[0-9]+[a-z]*)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, version_output_lower)
                if match:
                    return f"Cisco IOS {match.group(1)}"
            
            return "Cisco IOS"
        except Exception as e:
            logger.debug(f"Cisco OS version extraction failed: {e}")
            return "Cisco IOS"
    
    def extract_cisco_serial(self, version_output: str) -> str:
        """Extract Cisco serial number from show version output"""
        try:
            import re
            logger.info(f"Extracting serial from: {version_output[:200]}...")
            
            # Look for serial number patterns
            patterns = [
                r'serial number[:\s]+([^\s]+)',
                r'sn[:\s]+([^\s]+)',
                r'board id[:\s]+([^\s]+)',
                r'serial[:\s]+([^\s]+)',
                r'processor board id[:\s]+([^\s]+)',
                r'processor[:\s]+([^\s]+)',
                r'chassis[:\s]+([^\s]+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, version_output.lower())
                if match:
                    serial = match.group(1).upper()
                    logger.info(f"Found serial number: {serial}")
                    return serial
            
            # Don't use device model as serial number - it's not accurate
            logger.warning("No serial number found in SNMP data - will try SSH if available")
            return "Unknown"
        except Exception as e:
            logger.error(f"Cisco serial extraction failed: {e}")
            return "Unknown"
    
    def extract_cisco_location(self, location_output: str) -> str:
        """Extract Cisco location from SNMP configuration"""
        try:
            import re
            if 'snmp-server location' in location_output.lower():
                match = re.search(r'snmp-server location\s+(.+)', location_output, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
            
            return "Unknown"
        except Exception as e:
            logger.debug(f"Cisco location extraction failed: {e}")
            return "Unknown"
    
    def extract_juniper_os_version(self, version_output: str) -> str:
        """Extract Juniper OS version from show version output"""
        try:
            import re
            version_output_lower = version_output.lower()
            
            # Look for JunOS version patterns
            patterns = [
                r'junos.*?([0-9]+\.[0-9]+[a-z]*)',
                r'version[:\s]+([0-9]+\.[0-9]+[a-z]*)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, version_output_lower)
                if match:
                    return f"Juniper JunOS {match.group(1)}"
            
            return "Juniper JunOS"
        except Exception as e:
            logger.debug(f"Juniper OS version extraction failed: {e}")
            return "Juniper JunOS"
    
    def extract_arista_os_version(self, version_output: str) -> str:
        """Extract Arista OS version from show version output"""
        try:
            import re
            version_output_lower = version_output.lower()
            
            # Look for EOS version patterns
            patterns = [
                r'eos.*?([0-9]+\.[0-9]+[a-z]*)',
                r'version[:\s]+([0-9]+\.[0-9]+[a-z]*)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, version_output_lower)
                if match:
                    return f"Arista EOS {match.group(1)}"
            
            return "Arista EOS"
        except Exception as e:
            logger.debug(f"Arista OS version extraction failed: {e}")
            return "Arista EOS"
    
    def extract_linux_os_version(self, system_info: str) -> str:
        """Extract Linux OS version from uname output"""
        try:
            import re
            system_info_lower = system_info.lower()
            
            # Look for Linux version patterns
            patterns = [
                r'linux.*?([0-9]+\.[0-9]+[a-z]*)',
                r'ubuntu.*?([0-9]+\.[0-9]+[a-z]*)',
                r'centos.*?([0-9]+\.[0-9]+[a-z]*)',
                r'red hat.*?([0-9]+\.[0-9]+[a-z]*)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, system_info_lower)
                if match:
                    return f"Linux {match.group(1)}"
            
            return "Linux"
        except Exception as e:
            logger.debug(f"Linux OS version extraction failed: {e}")
            return "Linux"
    
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
            logger.info(f"Extracting serial from description: {description[:200]}...")
            
            # Look for common serial number patterns - more specific to avoid false positives
            patterns = [
                # Cisco format: ABC1234DEF5 (3 letters, 4 digits, 4 alphanumeric)
                r'[A-Z]{3}[0-9]{4}[A-Z0-9]{4}',
                # Generic format: AB12345678 (2 letters, 8 alphanumeric)
                r'[A-Z]{2}[0-9]{8}',
                # Numeric format: 123456789012 (12 digits)
                r'[0-9]{12}',
                # Short numeric: 12345678 (8 digits)
                r'[0-9]{8}',
                # Alphanumeric with dashes: ABC-123-DEF
                r'[A-Z0-9]{3}-[0-9]{3}-[A-Z0-9]{3}',
                # Serial with letters and numbers (but not all letters)
                r'[A-Z]{2,3}[0-9]{6,8}[A-Z0-9]{2,4}'
            ]
            
            # Search in the entire description
            for pattern in patterns:
                matches = re.findall(pattern, description.upper())
                if matches:
                    # Return the first match that looks like a serial number
                    for match in matches:
                        if len(match) >= 8:  # Minimum length for a serial number
                            # Exclude common device model parts that might match serial patterns
                            exclude_patterns = ['UNIVERSAL', 'CATALYST', 'CISCO', 'IOS', 'SOFTWARE', 'VERSION', 'TECH', 'SUPPORT', 'COPYRIGHT', 'RELEASE', 'GIBRALTAR']
                            if not any(exclude in match for exclude in exclude_patterns):
                                logger.info(f"Found serial number pattern: {match}")
                                return match
                            else:
                                logger.info(f"Excluded device model part as serial: {match}")
            
            # If no valid serial found, return Unknown to trigger SSH fallback
            logger.warning("No valid serial number found in description")
            return "Unknown"
            
            # If no pattern found, look for "serial" or "sn" keywords
            serial_keywords = ['serial', 'sn:', 'serial number', 'serial#']
            for keyword in serial_keywords:
                if keyword in description.lower():
                    # Extract text after the keyword
                    import re
                    match = re.search(f'{keyword}[:\s]*([A-Z0-9-]+)', description, re.IGNORECASE)
                    if match:
                        serial = match.group(1).strip()
                        logger.info(f"Found serial via keyword '{keyword}': {serial}")
                        return serial
            
            logger.warning("No serial number found in description")
            return "Unknown"
            
        except Exception as e:
            logger.error(f"Error extracting serial number: {e}")
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
                r'location[:\s]*([^,\n]+)',
                r'loc[:\s]*([^,\n]+)',
                r'building[:\s]*([^,\n]+)',
                r'floor[:\s]*([^,\n]+)',
                r'room[:\s]*([^,\n]+)'
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
                r'contact[:\s]*([^,\n]+)',
                r'admin[:\s]*([^,\n]+)',
                r'email[:\s]*([^,\n]+)',
                r'phone[:\s]*([^,\n]+)'
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
    
    def extract_hostname_from_version(self, version_output: str) -> str:
        """Extract hostname from show version output"""
        try:
            lines = version_output.split('\n')
            for line in lines:
                line = line.strip()
                # Look for lines that might contain hostname
                if 'uptime' in line.lower() and '#' in line:
                    # Extract hostname from prompt-like format
                    parts = line.split('#')
                    if len(parts) > 0:
                        hostname = parts[0].strip()
                        if hostname and len(hostname) < 50:  # Reasonable hostname length
                            return hostname
                # Look for specific hostname patterns
                if 'hostname' in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.lower() == 'hostname' and i + 1 < len(parts):
                            return parts[i + 1]
        except:
            pass
        return None
    
    def extract_hostname_from_config(self, config_output: str) -> str:
        """Extract hostname from show running-config output"""
        try:
            lines = config_output.split('\n')
            for line in lines:
                line = line.strip()
                if line.startswith('hostname '):
                    hostname = line.replace('hostname ', '').strip()
                    if hostname and len(hostname) < 50:
                        return hostname
        except:
            pass
        return None
    
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
                f"{self.backend_url.rstrip('/')}/api/v1/agents/heartbeat",
                headers={'X-Agent-Token': self.agent_token},
                json=heartbeat_data,
                timeout=15
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
                f"{self.backend_url.rstrip('/')}/api/v1/agents/pong",
                headers={'X-Agent-Token': self.agent_token},
                json=pong_data,
                timeout=15
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
                f"{self.backend_url.rstrip('/')}/api/v1/agents/status",
                headers={'X-Agent-Token': self.agent_token},
                json=status_data,
                timeout=15
            )
            
            if response and response.status_code == 200:
                logger.info(f"Status updated to: {status}")
            else:
                logger.warning(f"Failed to update status: {response.status_code if response else 'No response'}")
                
        except Exception as e:
            logger.error(f"Error updating status: {e}")
    
    def discovery_loop(self):
        """Main discovery loop"""
        while self.running:
            try:
                # Check for discovery requests
                if not self.discovery_running:
                    time.sleep(5)
                    continue
                
                # Discovery is handled by enhanced discovery requests
                # No need for continuous discovery loop
                time.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in discovery loop: {e}")
                time.sleep(30)
    
    def handle_discovery_request(self, data: Dict):
        """Handle discovery request from backend"""
        try:
            subnet = data.get('subnet')
            discovery_type = data.get('discovery_type', 'auto')
            
            logger.info(f"Received discovery request for subnet: {subnet}")
            
            # Start discovery in background thread
            discovery_thread = threading.Thread(
                target=self.start_discovery,
                args=(subnet, discovery_type),
                daemon=True
            )
            discovery_thread.start()
            
        except Exception as e:
            logger.error(f"Error handling discovery request: {e}")
    
    def start_discovery(self, subnet: str, discovery_type: str):
        """Start device discovery for given subnet"""
        try:
            self.discovery_running = True
            logger.info(f"Starting discovery for subnet: {subnet}")
            
            # Notify backend that discovery started
            self.notify_discovery_status('started', subnet)
            
            # Perform discovery based on type
            if discovery_type == 'snmp':
                devices = self.snmp_discovery(subnet)
            elif discovery_type == 'ssh':
                devices = self.ssh_discovery(subnet)
            else:
                devices = self.auto_discovery(subnet)
            
            # Process discovered devices
            self.process_discovered_devices(devices, subnet)
            
            # Notify backend that discovery completed
            self.notify_discovery_status('completed', subnet, len(devices))
            
        except Exception as e:
            logger.error(f"Error during discovery: {e}")
            self.notify_discovery_status('failed', subnet, error=str(e))
        finally:
            self.discovery_running = False
    
    def auto_discovery(self, subnet: str) -> List[Dict]:
        """Perform automatic discovery using multiple methods"""
        devices = []
        
        # Try SNMP discovery first
        try:
            snmp_devices = self.snmp_discovery(subnet)
            devices.extend(snmp_devices)
        except Exception as e:
            logger.warning(f"SNMP discovery failed: {e}")
        
        # Try SSH discovery for devices not found via SNMP
        try:
            ssh_devices = self.ssh_discovery(subnet)
            # Filter out devices already discovered via SNMP
            existing_ips = {device['ip_address'] for device in devices}
            new_ssh_devices = [d for d in ssh_devices if d['ip_address'] not in existing_ips]
            devices.extend(new_ssh_devices)
        except Exception as e:
            logger.warning(f"SSH discovery failed: {e}")
        
        return devices
    
    def snmp_discovery(self, subnet: str) -> List[Dict]:
        """Discover devices using SNMP"""
        devices = []
        
        # Common SNMP community strings to try
        community_strings = ['public', 'private', 'cisco', 'admin']
        
        # Scan subnet for devices
        network_parts = subnet.split('.')
        base_ip = '.'.join(network_parts[:-1])
        
        for i in range(1, 255):  # Scan .1 to .254
            ip_address = f"{base_ip}.{i}"
            
            for community in community_strings:
                try:
                    device_info = self.snmp_get_device_info(ip_address, community)
                    if device_info:
                        device_info['discovery_method'] = 'snmp'
                        device_info['community_string'] = community
                        devices.append(device_info)
                        break  # Found device, try next IP
                        
                except Exception as e:
                    continue  # Try next community string
        
        return devices
    
    def snmp_get_device_info(self, ip_address: str, community: str) -> Optional[Dict]:
        """Get device information via SNMP"""
        try:
            # Try to get system description
            for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0 if snmp_version == 'v1' else 1),
                UdpTransportTarget((ip_address, 161), timeout=3, retries=1),
                ContextData(),
                *[ObjectType(ObjectIdentity(oid)) for oid in oids],
                lexicographicMode=False,
                maxRows=0
            ):
                if errorIndication:
                    error_msg = str(errorIndication).lower()
                    if 'timeout' in error_msg:
                        logger.error(f"SNMP timeout for {ip_address}: {errorIndication}")
                    elif 'no response' in error_msg:
                        logger.error(f"SNMP no response from {ip_address}: {errorIndication}")
                    elif 'authentication' in error_msg or 'community' in error_msg:
                        logger.error(f"SNMP authentication failed for {ip_address}: {errorIndication}")
                    else:
                        logger.error(f"SNMP error indication for {ip_address}: {errorIndication}")
                    return None
                if errorStatus:
                    logger.error(f"SNMP error status for {ip_address}: {errorStatus}")
                    return None
                
                # Extract device information
                device_info = {
                    'ip_address': ip_address,
                    'hostname': str(varBinds[1][1]) if len(varBinds) > 1 else ip_address,
                    'description': str(varBinds[0][1]) if varBinds else 'Unknown',
                    'location': str(varBinds[2][1]) if len(varBinds) > 2 else 'Unknown',
                    'device_type': self.detect_device_type(str(varBinds[0][1]) if varBinds else ''),
                    'capabilities': ['snmp']
                }
                
                return device_info
                
        except Exception as e:
            logger.debug(f"SNMP query failed for {ip_address}: {e}")
            return None
    
    def ssh_discovery(self, subnet: str) -> List[Dict]:
        """Discover devices using SSH"""
        devices = []
        
        # Common SSH credentials to try
        credentials = [
            ('admin', 'admin'),
            ('cisco', 'cisco'),
            ('root', 'root'),
            ('admin', 'password'),
            ('cisco', 'password')
        ]
        
        # Scan subnet for SSH services
        network_parts = subnet.split('.')
        base_ip = '.'.join(network_parts[:-1])
        
        for i in range(1, 255):
            ip_address = f"{base_ip}.{i}"
            
            for username, password in credentials:
                try:
                    device_info = self.ssh_get_device_info(ip_address, username, password)
                    if device_info:
                        device_info['discovery_method'] = 'ssh'
                        device_info['credentials'] = {'username': username, 'password': password}
                        devices.append(device_info)
                        break  # Found device, try next IP
                        
                except Exception as e:
                    continue  # Try next credentials
        
        return devices
    
    def ssh_get_device_info(self, ip_address: str, username: str, password: str) -> Optional[Dict]:
        """Get device information via SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Try to connect with timeout
            ssh.connect(ip_address, username=username, password=password, timeout=5)
            
            # Get device information
            device_info = {
                'ip_address': ip_address,
                'hostname': ip_address,  # Will be updated if we can get it
                'description': 'SSH Device',
                'location': 'Unknown',
                'device_type': 'network_device',
                'capabilities': ['ssh']
            }
            
            # Try to get hostname
            try:
                stdin, stdout, stderr = ssh.exec_command('hostname', timeout=5)
                hostname = stdout.read().decode().strip()
                if hostname:
                    device_info['hostname'] = hostname
            except:
                pass
            
            # Try to get system info
            try:
                stdin, stdout, stderr = ssh.exec_command('uname -a', timeout=5)
                system_info = stdout.read().decode().strip()
                if system_info:
                    device_info['description'] = system_info
                    device_info['device_type'] = self.detect_device_type(system_info)
            except:
                pass
            
            ssh.close()
            return device_info
            
        except Exception as e:
            logger.debug(f"SSH connection failed for {ip_address}: {e}")
            return None
    
    def detect_device_type(self, description: str) -> str:
        """Enhanced device type detection from description"""
        try:
            description_lower = description.lower()
            
            # Cisco devices
            if any(keyword in description_lower for keyword in ['cisco ios', 'ios-xe', 'ios xe']):
                if any(keyword in description_lower for keyword in ['router', 'rtr']):
                    return "Router"
                elif any(keyword in description_lower for keyword in ['switch', 'sw']):
                    return "Switch"
                elif any(keyword in description_lower for keyword in ['firewall', 'asa', 'fw']):
                    return "Firewall"
                else:
                    return "Network Device"
            
            # Cisco NX-OS
            elif 'nx-os' in description_lower:
                if 'switch' in description_lower:
                    return "Switch"
                else:
                    return "Network Device"
            
            # Juniper devices
            elif any(keyword in description_lower for keyword in ['junos', 'juniper']):
                if 'router' in description_lower:
                    return "Router"
                elif 'switch' in description_lower:
                    return "Switch"
                elif 'firewall' in description_lower:
                    return "Firewall"
                else:
                    return "Network Device"
            
            # HP/Aruba devices
            elif any(keyword in description_lower for keyword in ['hp', 'aruba', 'procurve']):
                if 'switch' in description_lower:
                    return "Switch"
                elif 'router' in description_lower:
                    return "Router"
                else:
                    return "Network Device"
            
            # Dell devices
            elif any(keyword in description_lower for keyword in ['dell', 'powerconnect']):
                if 'switch' in description_lower:
                    return "Switch"
                else:
                    return "Network Device"
            
            # Brocade devices
            elif 'brocade' in description_lower:
                if 'switch' in description_lower:
                    return "Switch"
                else:
                    return "Network Device"
            
            # Linux servers
            elif any(keyword in description_lower for keyword in ['linux', 'ubuntu', 'centos', 'debian', 'redhat']):
                return "Server"
            
            # Windows servers
            elif any(keyword in description_lower for keyword in ['windows', 'server']):
                return "Server"
            
            # VMware
            elif 'vmware' in description_lower:
                return "Virtual Machine"
            
            # Generic network devices
            elif any(keyword in description_lower for keyword in ['router', 'switch', 'firewall', 'gateway']):
                if 'router' in description_lower:
                    return "Router"
                elif 'switch' in description_lower:
                    return "Switch"
                elif 'firewall' in description_lower:
                    return "Firewall"
                else:
                    return "Network Device"
            
            # Default
            else:
                return "Unknown"
                
        except Exception as e:
            logger.debug(f"Error detecting device type: {e}")
            return "Unknown"
    
    def process_discovered_devices(self, devices: List[Dict], subnet: str):
        """Process and send discovered devices to backend"""
        try:
            for device in devices:
                # Add discovery metadata
                device['discovered_at'] = datetime.now().isoformat()
                device['discovered_by'] = self.agent_name
                device['subnet'] = subnet
                
                # Store locally
                self.discovered_devices[device['ip_address']] = device
            
            # Send to backend
            if devices:
                self.send_discovered_devices(devices)
                
        except Exception as e:
            logger.error(f"Error processing discovered devices: {e}")
    
    def send_discovered_devices(self, devices: List[Dict]):
        """Send discovered devices to backend"""
        try:
            discovery_data = {
                'agent_name': self.agent_name,
                'discovered_devices': devices,
                'timestamp': datetime.now().isoformat()
            }
            
            response = requests.post(
                f"{self.backend_url.rstrip('/')}/api/v1/agents/discovery",
                headers={'X-Agent-Token': self.agent_token},
                json=discovery_data,
                timeout=15
            )
            
            if response.status_code == 200:
                logger.info(f"Sent {len(devices)} discovered devices to backend")
            else:
                logger.warning(f"Failed to send discovered devices: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error sending discovered devices: {e}")
    
    def notify_discovery_status(self, status: str, subnet: str, count: int = 0, error: str = None):
        """Notify backend of discovery status"""
        try:
            status_data = {
                'agent_name': self.agent_name,
                'subnet': subnet,
                'status': status,
                'timestamp': datetime.now().isoformat()
            }
            
            if count > 0:
                status_data['device_count'] = count
            
            if error:
                status_data['error'] = error
            
            response = requests.post(
                f"{self.backend_url.rstrip('/')}/api/v1/agents/discovery-status",
                headers={'X-Agent-Token': self.agent_token},
                json=status_data,
                timeout=15
            )
            
            if response.status_code == 200:
                logger.info(f"Discovery status updated: {status}")
            else:
                logger.warning(f"Failed to update discovery status: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error notifying discovery status: {e}")
    
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

    def update_agent_token(self, new_token: str):
        """Update agent token in config and memory"""
        self.agent_token = new_token
        self.config['agent_token'] = new_token
        try:
            with open('config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
            logger.info("Agent token updated in config file.")
        except Exception as e:
            logger.error(f"Failed to update config file with new token: {e}")

    def handle_token_error(self, error_msg, new_token=None):
        logger.error(f"Agent token error: {error_msg}")
        self.running = False
        if new_token:
            self.update_agent_token(new_token)
        # Alert admin (popup if GUI, else log)
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Agent Token Error", f"Agent token is revoked or inactive. Please update the token.\n\n{error_msg}")
            root.destroy()
        except Exception:
            logger.error("Agent token is revoked or inactive. Please update the token.")
        sys.exit(1)

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


def fetch_organizations(agent_token, backend_url):
    try:
        headers = {"X-Agent-Token": agent_token}
        resp = requests.get(f"{backend_url}/api/v1/agents/agent/organizations", headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            return []
    except Exception as e:
        return []

def fetch_networks(agent_token, backend_url, org_id):
    try:
        headers = {"X-Agent-Token": agent_token}
        resp = requests.get(f"{backend_url}/api/v1/agents/agent/networks", headers=headers, timeout=10)
        if resp.status_code == 200:
            return resp.json()
        else:
            return []
    except Exception as e:
        return []

def gui_onboarding():
    root = tk.Tk()
    root.title("Cisco AI Agent Onboarding")
    root.geometry("500x500")

    backend_url = "https://cisco-ai-backend-production.up.railway.app"

    # Variables
    agent_token_var = tk.StringVar()
    org_var = tk.StringVar()
    network_var = tk.StringVar()
    subnet_var = tk.StringVar()
    ssh_user_var = tk.StringVar(value="admin")
    ssh_pass_var = tk.StringVar(value="cisco")
    snmp_comm_var = tk.StringVar(value="public")
    snmp_ver_var = tk.StringVar(value="v2c")

    orgs = []
    networks = []

    def load_orgs():
        nonlocal orgs
        agent_token = agent_token_var.get().strip()
        if not agent_token:
            messagebox.showerror("Error", "Please enter Agent token.")
            return
        orgs = fetch_organizations(agent_token, backend_url)
        org_menu['values'] = [f"{o['id']}: {o['name']}" for o in orgs]
        if orgs:
            org_var.set(f"{orgs[0]['id']}: {orgs[0]['name']}")
            load_networks()
        else:
            org_var.set("")
            network_menu['values'] = []
            network_var.set("")
            messagebox.showerror("Error", "No organizations found or invalid agent token.")

    def load_networks(*args):
        nonlocal networks
        agent_token = agent_token_var.get().strip()
        if not agent_token or not org_var.get():
            return
        org_id = org_var.get().split(":")[0]
        networks = fetch_networks(agent_token, backend_url, org_id)
        network_menu['values'] = [f"{n['id']}: {n['name']}" for n in networks]
        if networks:
            network_var.set(f"{networks[0]['id']}: {networks[0]['name']}")
        else:
            network_var.set("")

    def on_submit():
        if not agent_token_var.get().strip():
            messagebox.showerror("Error", "Agent token is required.")
            return
        if not org_var.get() or not network_var.get():
            messagebox.showerror("Error", "Please select organization and network.")
            return
        if not subnet_var.get().strip():
            messagebox.showerror("Error", "Please enter subnet/IP/range.")
            return
        root.quit()

    # Layout
    row = 0
    tk.Label(root, text="Agent Token:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=agent_token_var, width=50, show="*").grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Button(root, text="Load Organizations", command=load_orgs).grid(row=row, column=1, sticky="w", padx=5, pady=5)
    row += 1
    tk.Label(root, text="Organization:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    org_menu = ttk.Combobox(root, textvariable=org_var, state="readonly", width=47)
    org_menu.grid(row=row, column=1, padx=5, pady=5)
    org_menu.bind("<<ComboboxSelected>>", load_networks)
    row += 1
    tk.Label(root, text="Network:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    network_menu = ttk.Combobox(root, textvariable=network_var, state="readonly", width=47)
    network_menu.grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Label(root, text="Subnet/IP/Range:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=subnet_var, width=50).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Label(root, text="SSH Username:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=ssh_user_var, width=50).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Label(root, text="SSH Password:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=ssh_pass_var, width=50, show="*").grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Label(root, text="SNMP Community:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=snmp_comm_var, width=50).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Label(root, text="SNMP Version:").grid(row=row, column=0, sticky="e", padx=5, pady=5)
    tk.Entry(root, textvariable=snmp_ver_var, width=50).grid(row=row, column=1, padx=5, pady=5)
    row += 1
    tk.Button(root, text="Start Agent", command=on_submit, width=20).grid(row=row, column=1, pady=20)

    root.mainloop()

    # Return all values
    return {
        "agent_token": agent_token_var.get().strip(),
        "organization_id": int(org_var.get().split(":")[0]) if org_var.get() else None,
        "network_id": int(network_var.get().split(":")[0]) if network_var.get() else None,
        "subnet": subnet_var.get().strip(),
        "ssh_username": ssh_user_var.get().strip(),
        "ssh_password": ssh_pass_var.get().strip(),
        "snmp_community": snmp_comm_var.get().strip(),
        "snmp_version": snmp_ver_var.get().strip(),
    }


def main():
    """Main entry point - starts automatically with configuration file"""
    try:
        # Create agent instance - it will automatically load from agent_config.json
        agent = CiscoAIAgent()
        
        # Start agent service automatically
        logger.info("Starting agent automatically with configuration file...")
        agent.start()
        
    except KeyboardInterrupt:
        logger.info("Agent stopped by user")
    except Exception as e:
        logger.error(f"Agent failed to start: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 