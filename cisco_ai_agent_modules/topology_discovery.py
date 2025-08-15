#!/usr/bin/env python3
"""
Topology Discovery Module for Cisco AI Agent

This module handles network topology discovery including:
- Device discovery via SNMP
- Interface information gathering
- Neighbor discovery via CDP/LLDP
- Topology data reporting to backend
"""

import asyncio
import logging
import subprocess
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TopologyDiscovery:
    """Handles network topology discovery for the agent."""
    
    def __init__(self, agent_config: Dict[str, Any]):
        self.agent_config = agent_config
        self.backend_url = agent_config.get('backend_url')
        self.agent_token = agent_config.get('agent_token')
        self.agent_id = agent_config.get('agent_id')
        self.networks = agent_config.get('networks', [])
        self.discovery_config = agent_config.get('discovery_config', {})
        
        # SNMP configuration
        self.snmp_community = self.discovery_config.get('snmp_community', 'public')
        self.snmp_version = self.discovery_config.get('snmp_version', '2c')
        self.snmp_timeout = self.discovery_config.get('snmp_timeout', 5)
        self.snmp_retries = self.discovery_config.get('snmp_retries', 3)
        
        # Discovery settings
        self.ping_timeout = self.discovery_config.get('ping_timeout', 2)
        self.max_concurrent_discoveries = self.discovery_config.get('max_concurrent_discoveries', 10)
        self.discovery_interval = self.discovery_config.get('discovery_interval', 300)  # 5 minutes
        
        # Results storage
        self.discovered_devices = {}
        self.discovered_interfaces = {}
        self.discovered_neighbors = {}
        
    async def start_discovery(self, network_id: int, discovery_type: str = "full") -> bool:
        """Start topology discovery for a specific network."""
        try:
            logger.info(f"Starting topology discovery for network {network_id}")
            
            # Notify backend that discovery is starting
            await self._notify_discovery_start(network_id, discovery_type)
            
            # Get network configuration
            network_config = self._get_network_config(network_id)
            if not network_config:
                logger.error(f"No configuration found for network {network_id}")
                await self._notify_discovery_failed(network_id, "No network configuration found")
                return False
            
            # Start discovery based on type
            if discovery_type == "full":
                success = await self._full_discovery(network_id, network_config)
            elif discovery_type == "neighbors":
                success = await self._neighbor_discovery(network_id, network_config)
            elif discovery_type == "interfaces":
                success = await self._interface_discovery(network_id, network_config)
            else:
                logger.error(f"Unknown discovery type: {discovery_type}")
                await self._notify_discovery_failed(network_id, f"Unknown discovery type: {discovery_type}")
                return False
            
            if success:
                # Report results to backend
                await self._report_discovery_results(network_id)
                logger.info(f"Topology discovery completed successfully for network {network_id}")
                return True
            else:
                await self._notify_discovery_failed(network_id, "Discovery process failed")
                return False
                
        except Exception as e:
            logger.error(f"Error during topology discovery: {str(e)}")
            await self._notify_discovery_failed(network_id, str(e))
            return False
    
    async def _full_discovery(self, network_id: int, network_config: Dict[str, Any]) -> bool:
        """Perform full topology discovery."""
        try:
            logger.info(f"Starting full discovery for network {network_id}")
            
            # Step 1: Device discovery
            devices = await self._discover_devices(network_config)
            if not devices:
                logger.warning(f"No devices discovered in network {network_id}")
                return False
            
            # Step 2: Interface discovery
            interfaces = await self._discover_interfaces(devices)
            
            # Step 3: Neighbor discovery
            neighbors = await self._discover_neighbors(devices)
            
            # Store results
            self.discovered_devices[network_id] = devices
            self.discovered_interfaces[network_id] = interfaces
            self.discovered_neighbors[network_id] = neighbors
            
            logger.info(f"Full discovery completed: {len(devices)} devices, {len(interfaces)} interfaces, {len(neighbors)} neighbors")
            return True
            
        except Exception as e:
            logger.error(f"Error during full discovery: {str(e)}")
            return False
    
    async def _discover_devices(self, network_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Discover devices in the network."""
        devices = []
        
        # Get network range
        network_range = network_config.get('network_range')
        if not network_range:
            logger.warning("No network range specified for device discovery")
            return devices
        
        try:
            # Parse network range
            if '/' in network_range:
                # CIDR notation
                network = ipaddress.ip_network(network_range, strict=False)
                ip_addresses = [str(ip) for ip in network.hosts()]
            else:
                # Single IP or range
                ip_addresses = [network_range]
            
            logger.info(f"Scanning {len(ip_addresses)} IP addresses for devices")
            
            # Use ThreadPoolExecutor for concurrent scanning
            with ThreadPoolExecutor(max_workers=self.max_concurrent_discoveries) as executor:
                # Submit ping tasks
                future_to_ip = {
                    executor.submit(self._ping_device, ip): ip 
                    for ip in ip_addresses
                }
                
                # Process results as they complete
                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    try:
                        result = future.result()
                        if result:
                            devices.append(result)
                            logger.info(f"Discovered device: {result['hostname']} ({ip})")
                    except Exception as e:
                        logger.error(f"Error scanning IP {ip}: {str(e)}")
            
            logger.info(f"Device discovery completed: {len(devices)} devices found")
            return devices
            
        except Exception as e:
            logger.error(f"Error during device discovery: {str(e)}")
            return devices
    
    async def _ping_device(self, ip: str) -> Optional[Dict[str, Any]]:
        """Ping a device and return basic information if reachable."""
        try:
            # Ping the device
            if not self._is_device_reachable(ip):
                return None
            
            # Try to get device information via SNMP
            device_info = await self._get_device_info_snmp(ip)
            if device_info:
                return device_info
            
            # Fallback to basic ping response
            return {
                'ip_address': ip,
                'hostname': ip,
                'device_type': 'unknown',
                'platform': 'unknown',
                'vendor': 'unknown',
                'os_version': 'unknown',
                'serial_number': 'unknown',
                'uptime': None,
                'ping_status': True,
                'snmp_status': False,
                'ssh_status': False,
                'discovery_timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error pinging device {ip}: {str(e)}")
            return None
    
    def _is_device_reachable(self, ip: str) -> bool:
        """Check if a device is reachable via ping."""
        try:
            # Use ping command appropriate for the OS
            if self._is_windows():
                cmd = ['ping', '-n', '1', '-w', str(self.ping_timeout * 1000), ip]
            else:
                cmd = ['ping', '-c', '1', '-W', str(self.ping_timeout), ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.ping_timeout + 2)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error checking reachability for {ip}: {str(e)}")
            return False
    
    async def _get_device_info_snmp(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get device information via SNMP."""
        try:
            # This would use a proper SNMP library like pysnmp
            # For now, we'll simulate SNMP discovery
            logger.debug(f"Attempting SNMP discovery for {ip}")
            
            # Simulate SNMP response
            device_info = {
                'ip_address': ip,
                'hostname': f"device-{ip.replace('.', '-')}",
                'device_type': 'switch',  # Would be determined from SNMP
                'platform': 'Cisco IOS',  # Would be determined from SNMP
                'vendor': 'Cisco',        # Would be determined from SNMP
                'os_version': '15.0',    # Would be determined from SNMP
                'serial_number': 'ABC123', # Would be determined from SNMP
                'uptime': '1234567890',   # Would be determined from SNMP
                'ping_status': True,
                'snmp_status': True,
                'ssh_status': False,      # Would be determined from SSH test
                'discovery_timestamp': datetime.utcnow().isoformat()
            }
            
            return device_info
            
        except Exception as e:
            logger.error(f"Error getting SNMP info for {ip}: {str(e)}")
            return None
    
    async def _discover_interfaces(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Discover interfaces for discovered devices."""
        interfaces = []
        
        for device in devices:
            if device.get('snmp_status'):
                try:
                    device_interfaces = await self._get_device_interfaces(device['ip_address'])
                    interfaces.extend(device_interfaces)
                except Exception as e:
                    logger.error(f"Error discovering interfaces for {device['ip_address']}: {str(e)}")
        
        logger.info(f"Interface discovery completed: {len(interfaces)} interfaces found")
        return interfaces
    
    async def _get_device_interfaces(self, ip: str) -> List[Dict[str, Any]]:
        """Get interface information for a specific device."""
        try:
            # This would use SNMP to get interface information
            # For now, we'll simulate interface discovery
            logger.debug(f"Getting interfaces for device {ip}")
            
            # Simulate interface discovery
            interfaces = [
                {
                    'interface_name': 'GigabitEthernet0/1',
                    'interface_description': 'Uplink to Core Switch',
                    'interface_type': 'ethernet',
                    'operational_status': 'up',
                    'administrative_status': 'up',
                    'speed': '1000',
                    'mac_address': '00:11:22:33:44:55',
                    'ip_address': '192.168.1.1',
                    'vlan': '1'
                },
                {
                    'interface_name': 'GigabitEthernet0/2',
                    'interface_description': 'Access Port',
                    'interface_type': 'ethernet',
                    'operational_status': 'up',
                    'administrative_status': 'up',
                    'speed': '1000',
                    'mac_address': '00:11:22:33:44:66',
                    'ip_address': None,
                    'vlan': '10'
                }
            ]
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting interfaces for {ip}: {str(e)}")
            return []
    
    async def _discover_neighbors(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Discover neighbor relationships between devices."""
        neighbors = []
        
        for device in devices:
            if device.get('snmp_status'):
                try:
                    device_neighbors = await self._get_device_neighbors(device['ip_address'])
                    neighbors.extend(device_neighbors)
                except Exception as e:
                    logger.error(f"Error discovering neighbors for {device['ip_address']}: {str(e)}")
        
        logger.info(f"Neighbor discovery completed: {len(neighbors)} neighbors found")
        return neighbors
    
    async def _get_device_neighbors(self, ip: str) -> List[Dict[str, Any]]:
        """Get neighbor information for a specific device."""
        try:
            # This would use CDP/LLDP via SNMP or SSH
            # For now, we'll simulate neighbor discovery
            logger.debug(f"Getting neighbors for device {ip}")
            
            # Simulate neighbor discovery
            neighbors = [
                {
                    'local_device_ip': ip,
                    'local_interface': 'GigabitEthernet0/1',
                    'neighbor_device_ip': '192.168.1.2',
                    'neighbor_hostname': 'core-switch-01',
                    'neighbor_interface': 'GigabitEthernet1/1',
                    'neighbor_platform': 'Cisco IOS',
                    'discovery_protocol': 'cdp'
                }
            ]
            
            return neighbors
            
        except Exception as e:
            logger.error(f"Error getting neighbors for {ip}: {str(e)}")
            return []
    
    def _get_network_config(self, network_id: int) -> Optional[Dict[str, Any]]:
        """Get configuration for a specific network."""
        for network in self.networks:
            if network.get('id') == network_id:
                return network
        return None
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        import platform
        return platform.system().lower() == "windows"
    
    async def _notify_discovery_start(self, network_id: int, discovery_type: str) -> None:
        """Notify backend that discovery is starting."""
        try:
            url = f"{self.backend_url}/api/v1/agents/{self.agent_id}/topology/discover"
            headers = {'X-Agent-Token': self.agent_token}
            data = {
                'network_id': network_id,
                'discovery_type': discovery_type,
                'force_refresh': False
            }
            
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                logger.info(f"Backend notified of discovery start for network {network_id}")
            else:
                logger.warning(f"Failed to notify backend: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error notifying backend: {str(e)}")
    
    async def _notify_discovery_failed(self, network_id: int, error_message: str) -> None:
        """Notify backend that discovery failed."""
        try:
            # Update agent status to failed
            url = f"{self.backend_url}/api/v1/agents/{self.agent_id}/topology/progress"
            headers = {'X-Agent-Token': self.agent_token}
            data = {
                'progress': 0,
                'discovered_devices': 0,
                'error': error_message
            }
            
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                logger.info(f"Backend notified of discovery failure for network {network_id}")
            else:
                logger.warning(f"Failed to notify backend of failure: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error notifying backend of failure: {str(e)}")
    
    async def _report_discovery_results(self, network_id: int) -> None:
        """Report discovery results to backend."""
        try:
            url = f"{self.backend_url}/api/v1/agents/{self.agent_id}/topology/update"
            headers = {'X-Agent-Token': self.agent_token}
            
            data = {
                'network_id': network_id,
                'devices': self.discovered_devices.get(network_id, []),
                'interfaces': self.discovered_interfaces.get(network_id, []),
                'neighbors': self.discovered_neighbors.get(network_id, [])
            }
            
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                logger.info(f"Discovery results reported to backend for network {network_id}")
            else:
                logger.warning(f"Failed to report results to backend: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error reporting results to backend: {str(e)}")
    
    async def start_continuous_discovery(self):
        """Start continuous topology discovery for all networks."""
        logger.info("Starting continuous topology discovery")
        
        while True:
            try:
                for network in self.networks:
                    network_id = network.get('id')
                    if network_id:
                        logger.info(f"Starting discovery cycle for network {network_id}")
                        await self.start_discovery(network_id, "full")
                
                # Wait for next discovery cycle
                logger.info(f"Discovery cycle completed, waiting {self.discovery_interval} seconds")
                await asyncio.sleep(self.discovery_interval)
                
            except Exception as e:
                logger.error(f"Error in continuous discovery: {str(e)}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying


# Example usage
if __name__ == "__main__":
    # Example configuration
    config = {
        'backend_url': 'https://cisco-ai-backend-production.up.railway.app',
        'agent_token': 'your_agent_token_here',
        'agent_id': 123,
        'networks': [
            {
                'id': 1,
                'name': 'Main Network',
                'network_range': '192.168.1.0/24'
            }
        ],
        'discovery_config': {
            'snmp_community': 'public',
            'snmp_version': '2c',
            'ping_timeout': 2,
            'max_concurrent_discoveries': 10,
            'discovery_interval': 300
        }
    }
    
    # Create discovery instance
    discovery = TopologyDiscovery(config)
    
    # Run discovery
    asyncio.run(discovery.start_continuous_discovery()) 