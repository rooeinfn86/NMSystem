#!/usr/bin/env python3
"""
Interface Tracker Module for Cisco AI Agent

This module handles interface monitoring and tracking including:
- Interface status monitoring
- Interface configuration changes
- Bandwidth utilization tracking
- Error rate monitoring
"""

import asyncio
import logging
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class InterfaceTracker:
    """Handles interface monitoring and tracking for network devices."""
    
    def __init__(self, agent_config: Dict[str, Any]):
        self.agent_config = agent_config
        self.backend_url = agent_config.get('backend_url')
        self.agent_token = agent_config.get('agent_token')
        self.agent_id = agent_config.get('agent_id')
        self.networks = agent_config.get('networks', [])
        self.tracking_config = agent_config.get('interface_tracking_config', {})
        
        # Tracking settings
        self.interface_check_interval = self.tracking_config.get('interface_check_interval', 120)  # 2 minutes
        self.bandwidth_check_interval = self.tracking_config.get('bandwidth_check_interval', 300)  # 5 minutes
        self.error_check_interval = self.tracking_config.get('error_check_interval', 60)  # 1 minute
        self.config_check_interval = self.tracking_config.get('config_check_interval', 1800)  # 30 minutes
        
        # Interface data storage
        self.interface_status = {}
        self.interface_configs = {}
        self.bandwidth_history = {}
        self.error_history = {}
        self.tracking_tasks = {}
        self.is_running = False
        
    async def start_tracking(self):
        """Start interface tracking for all networks."""
        if self.is_running:
            logger.warning("Interface tracking is already running")
            return
        
        self.is_running = True
        logger.info("Starting interface tracking")
        
        try:
            # Start tracking tasks for each network
            for network in self.networks:
                network_id = network.get('id')
                if network_id:
                    await self._start_network_tracking(network_id)
            
            # Keep the tracking running
            while self.is_running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Error in interface tracking: {str(e)}")
            self.is_running = False
    
    async def stop_tracking(self):
        """Stop interface tracking."""
        logger.info("Stopping interface tracking")
        self.is_running = False
        
        # Cancel all tracking tasks
        for task in self.tracking_tasks.values():
            if not task.done():
                task.cancel()
        
        self.tracking_tasks.clear()
        logger.info("Interface tracking stopped")
    
    async def _start_network_tracking(self, network_id: int):
        """Start interface tracking for a specific network."""
        try:
            logger.info(f"Starting interface tracking for network {network_id}")
            
            # Start interface status tracking
            status_task = asyncio.create_task(
                self._interface_status_loop(network_id)
            )
            self.tracking_tasks[f"status_{network_id}"] = status_task
            
            # Start bandwidth tracking
            bandwidth_task = asyncio.create_task(
                self._bandwidth_tracking_loop(network_id)
            )
            self.tracking_tasks[f"bandwidth_{network_id}"] = bandwidth_task
            
            # Start error tracking
            error_task = asyncio.create_task(
                self._error_tracking_loop(network_id)
            )
            self.tracking_tasks[f"error_{network_id}"] = error_task
            
            # Start configuration tracking
            config_task = asyncio.create_task(
                self._config_tracking_loop(network_id)
            )
            self.tracking_tasks[f"config_{network_id}"] = config_task
            
            logger.info(f"Interface tracking tasks started for network {network_id}")
            
        except Exception as e:
            logger.error(f"Error starting interface tracking for network {network_id}: {str(e)}")
    
    async def _interface_status_loop(self, network_id: int):
        """Continuous interface status monitoring loop."""
        while self.is_running:
            try:
                await self._check_interface_status(network_id)
                await asyncio.sleep(self.interface_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in interface status tracking for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _bandwidth_tracking_loop(self, network_id: int):
        """Continuous bandwidth tracking loop."""
        while self.is_running:
            try:
                await self._check_bandwidth_utilization(network_id)
                await asyncio.sleep(self.bandwidth_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in bandwidth tracking for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _error_tracking_loop(self, network_id: int):
        """Continuous error tracking loop."""
        while self.is_running:
            try:
                await self._check_interface_errors(network_id)
                await asyncio.sleep(self.error_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in error tracking for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _config_tracking_loop(self, network_id: int):
        """Continuous configuration tracking loop."""
        while self.is_running:
            try:
                await self._check_interface_configs(network_id)
                await asyncio.sleep(self.config_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in config tracking for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _check_interface_status(self, network_id: int):
        """Check interface status for all devices in a network."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking interface status for {len(devices)} devices in network {network_id}")
            
            # Check interface status concurrently
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_device = {
                    executor.submit(self._get_device_interfaces, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        interfaces = future.result()
                        if interfaces:
                            await self._update_interface_status(network_id, device['ip'], interfaces)
                    except Exception as e:
                        logger.error(f"Error checking interfaces for {device['ip']}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error checking interface status for network {network_id}: {str(e)}")
    
    async def _check_bandwidth_utilization(self, network_id: int):
        """Check bandwidth utilization for interfaces."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking bandwidth for {len(devices)} devices in network {network_id}")
            
            # Check bandwidth concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_device = {
                    executor.submit(self._get_device_bandwidth, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        bandwidth_data = future.result()
                        if bandwidth_data:
                            await self._update_bandwidth_data(network_id, device['ip'], bandwidth_data)
                    except Exception as e:
                        logger.error(f"Error checking bandwidth for {device['ip']}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error checking bandwidth for network {network_id}: {str(e)}")
    
    async def _check_interface_errors(self, network_id: int):
        """Check interface error rates."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking interface errors for {len(devices)} devices in network {network_id}")
            
            # Check errors concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_device = {
                    executor.submit(self._get_device_errors, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        error_data = future.result()
                        if error_data:
                            await self._update_error_data(network_id, device['ip'], error_data)
                    except Exception as e:
                        logger.error(f"Error checking errors for {device['ip']}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error checking interface errors for network {network_id}: {str(e)}")
    
    async def _check_interface_configs(self, network_id: int):
        """Check interface configuration changes."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking interface configs for {len(devices)} devices in network {network_id}")
            
            # Check configs concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_device = {
                    executor.submit(self._get_device_configs, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        config_data = future.result()
                        if config_data:
                            await self._check_config_changes(network_id, device['ip'], config_data)
                    except Exception as e:
                        logger.error(f"Error checking configs for {device['ip']}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error checking interface configs for network {network_id}: {str(e)}")
    
    def _get_device_interfaces(self, device: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """Get interface information for a device."""
        try:
            # This would use SNMP to get interface information
            # For now, we'll simulate interface data
            ip = device['ip']
            logger.debug(f"Getting interfaces for device {ip}")
            
            # Simulate interface data
            interfaces = [
                {
                    'name': 'GigabitEthernet0/1',
                    'description': 'Uplink to Core',
                    'operational_status': 'up',
                    'administrative_status': 'up',
                    'speed': '1000',
                    'duplex': 'full',
                    'vlan': '1',
                    'ip_address': '192.168.1.1',
                    'subnet_mask': '255.255.255.0'
                },
                {
                    'name': 'GigabitEthernet0/2',
                    'description': 'Access Port',
                    'operational_status': 'up',
                    'administrative_status': 'up',
                    'speed': '1000',
                    'duplex': 'full',
                    'vlan': '10',
                    'ip_address': None,
                    'subnet_mask': None
                }
            ]
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Error getting interfaces for {device.get('ip', 'unknown')}: {str(e)}")
            return None
    
    def _get_device_bandwidth(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get bandwidth utilization for a device."""
        try:
            # This would use SNMP to get bandwidth data
            # For now, we'll simulate bandwidth data
            ip = device['ip']
            logger.debug(f"Getting bandwidth for device {ip}")
            
            # Simulate bandwidth data
            bandwidth_data = {
                'GigabitEthernet0/1': {
                    'in_octets': 1234567890,
                    'out_octets': 987654321,
                    'in_errors': 0,
                    'out_errors': 0,
                    'in_discards': 0,
                    'out_discards': 0
                },
                'GigabitEthernet0/2': {
                    'in_octets': 567890123,
                    'out_octets': 456789012,
                    'in_errors': 0,
                    'out_errors': 0,
                    'in_discards': 0,
                    'out_discards': 0
                }
            }
            
            return bandwidth_data
            
        except Exception as e:
            logger.error(f"Error getting bandwidth for {device.get('ip', 'unknown')}: {str(e)}")
            return None
    
    def _get_device_errors(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get interface error rates for a device."""
        try:
            # This would use SNMP to get error counters
            # For now, we'll simulate error data
            ip = device['ip']
            logger.debug(f"Getting errors for device {ip}")
            
            # Simulate error data
            error_data = {
                'GigabitEthernet0/1': {
                    'in_errors': 0,
                    'out_errors': 0,
                    'in_discards': 0,
                    'out_discards': 0,
                    'collisions': 0
                },
                'GigabitEthernet0/2': {
                    'in_errors': 0,
                    'out_errors': 0,
                    'in_discards': 0,
                    'out_discards': 0,
                    'collisions': 0
                }
            }
            
            return error_data
            
        except Exception as e:
            logger.error(f"Error getting errors for {device.get('ip', 'unknown')}: {str(e)}")
            return None
    
    def _get_device_configs(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get interface configuration for a device."""
        try:
            # This would use SNMP or SSH to get interface configs
            # For now, we'll simulate config data
            ip = device['ip']
            logger.debug(f"Getting configs for device {ip}")
            
            # Simulate config data
            config_data = {
                'GigabitEthernet0/1': {
                    'description': 'Uplink to Core',
                    'vlan': '1',
                    'speed': '1000',
                    'duplex': 'full',
                    'shutdown': False
                },
                'GigabitEthernet0/2': {
                    'description': 'Access Port',
                    'vlan': '10',
                    'speed': '1000',
                    'duplex': 'full',
                    'shutdown': False
                }
            }
            
            return config_data
            
        except Exception as e:
            logger.error(f"Error getting configs for {device.get('ip', 'unknown')}: {str(e)}")
            return None
    
    async def _get_network_devices(self, network_id: int) -> List[Dict[str, Any]]:
        """Get list of devices for a network."""
        try:
            # This would query the backend or local cache
            # For now, we'll return a simulated device list
            devices = [
                {'ip': '192.168.1.1', 'name': 'switch-01'},
                {'ip': '192.168.1.2', 'name': 'switch-02'},
                {'ip': '192.168.1.3', 'name': 'router-01'}
            ]
            
            return devices
            
        except Exception as e:
            logger.error(f"Error getting devices for network {network_id}: {str(e)}")
            return []
    
    async def _update_interface_status(self, network_id: int, ip: str, interfaces: List[Dict[str, Any]]):
        """Update interface status in local storage."""
        try:
            if network_id not in self.interface_status:
                self.interface_status[network_id] = {}
            
            if ip not in self.interface_status[network_id]:
                self.interface_status[network_id][ip] = {}
            
            for interface in interfaces:
                interface_name = interface['name']
                self.interface_status[network_id][ip][interface_name] = {
                    'status': interface,
                    'last_updated': datetime.utcnow().isoformat()
                }
            
        except Exception as e:
            logger.error(f"Error updating interface status: {str(e)}")
    
    async def _update_bandwidth_data(self, network_id: int, ip: str, bandwidth_data: Dict[str, Any]):
        """Update bandwidth data in local storage."""
        try:
            if network_id not in self.bandwidth_history:
                self.bandwidth_history[network_id] = {}
            
            if ip not in self.bandwidth_history[network_id]:
                self.bandwidth_history[network_id][ip] = {}
            
            timestamp = datetime.utcnow().isoformat()
            
            for interface_name, data in bandwidth_data.items():
                if interface_name not in self.bandwidth_history[network_id][ip]:
                    self.bandwidth_history[network_id][ip][interface_name] = []
                
                # Keep last 100 data points
                history = self.bandwidth_history[network_id][ip][interface_name]
                history.append({
                    'timestamp': timestamp,
                    'data': data
                })
                
                if len(history) > 100:
                    history.pop(0)
            
        except Exception as e:
            logger.error(f"Error updating bandwidth data: {str(e)}")
    
    async def _update_error_data(self, network_id: int, ip: str, error_data: Dict[str, Any]):
        """Update error data in local storage."""
        try:
            if network_id not in self.error_history:
                self.error_history[network_id] = {}
            
            if ip not in self.error_history[network_id]:
                self.error_history[network_id][ip] = {}
            
            timestamp = datetime.utcnow().isoformat()
            
            for interface_name, data in error_data.items():
                if interface_name not in self.error_history[network_id][ip]:
                    self.error_history[network_id][ip][interface_name] = []
                
                # Keep last 100 data points
                history = self.error_history[network_id][ip][interface_name]
                history.append({
                    'timestamp': timestamp,
                    'data': data
                })
                
                if len(history) > 100:
                    history.pop(0)
            
        except Exception as e:
            logger.error(f"Error updating error data: {str(e)}")
    
    async def _check_config_changes(self, network_id: int, ip: str, config_data: Dict[str, Any]):
        """Check for interface configuration changes."""
        try:
            if network_id not in self.interface_configs:
                self.interface_configs[network_id] = {}
            
            if ip not in self.interface_configs[network_id]:
                self.interface_configs[network_id][ip] = {}
            
            # Check for changes
            for interface_name, new_config in config_data.items():
                old_config = self.interface_configs[network_id][ip].get(interface_name)
                
                if old_config and old_config != new_config:
                    logger.info(f"Configuration change detected for {ip}:{interface_name}")
                    # Log the change
                    await self._log_config_change(network_id, ip, interface_name, old_config, new_config)
                
                # Update stored config
                self.interface_configs[network_id][ip][interface_name] = new_config
            
        except Exception as e:
            logger.error(f"Error checking config changes: {str(e)}")
    
    async def _log_config_change(self, network_id: int, ip: str, interface_name: str, 
                                old_config: Dict[str, Any], new_config: Dict[str, Any]):
        """Log interface configuration changes."""
        try:
            change_log = {
                'network_id': network_id,
                'device_ip': ip,
                'interface_name': interface_name,
                'old_config': old_config,
                'new_config': new_config,
                'timestamp': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Interface config change: {change_log}")
            
            # Here you could send the change to the backend or store it locally
            
        except Exception as e:
            logger.error(f"Error logging config change: {str(e)}")
    
    def get_interface_summary(self, network_id: int) -> Dict[str, Any]:
        """Get summary of interface status for a network."""
        try:
            if network_id not in self.interface_status:
                return {}
            
            devices = self.interface_status[network_id]
            total_interfaces = 0
            up_interfaces = 0
            down_interfaces = 0
            
            for device_ip, interfaces in devices.items():
                for interface_name, interface_data in interfaces.items():
                    total_interfaces += 1
                    status = interface_data['status']['operational_status']
                    if status == 'up':
                        up_interfaces += 1
                    else:
                        down_interfaces += 1
            
            return {
                'total_interfaces': total_interfaces,
                'up_interfaces': up_interfaces,
                'down_interfaces': down_interfaces,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting interface summary: {str(e)}")
            return {}


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
        'interface_tracking_config': {
            'interface_check_interval': 120,
            'bandwidth_check_interval': 300,
            'error_check_interval': 60,
            'config_check_interval': 1800
        }
    }
    
    # Create tracker instance
    tracker = InterfaceTracker(config)
    
    # Run tracking
    asyncio.run(tracker.start_tracking()) 