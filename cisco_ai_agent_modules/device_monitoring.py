#!/usr/bin/env python3
"""
Device Monitoring Module for Cisco AI Agent

This module handles continuous monitoring of device status including:
- Ping monitoring
- SNMP status monitoring
- SSH connectivity testing
- Health metrics collection
"""

import asyncio
import logging
import subprocess
import time
from typing import List, Dict, Any, Optional
from datetime import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DeviceMonitor:
    """Handles continuous monitoring of network devices."""
    
    def __init__(self, agent_config: Dict[str, Any]):
        self.agent_config = agent_config
        self.backend_url = agent_config.get('backend_url')
        self.agent_token = agent_config.get('agent_token')
        self.agent_id = agent_config.get('agent_id')
        self.networks = agent_config.get('networks', [])
        self.monitoring_config = agent_config.get('monitoring_config', {})
        
        # Monitoring settings
        self.ping_interval = self.monitoring_config.get('ping_interval', 60)  # 1 minute
        self.snmp_interval = self.monitoring_config.get('snmp_interval', 300)  # 5 minutes
        self.ssh_interval = self.monitoring_config.get('ssh_interval', 600)  # 10 minutes
        self.health_interval = self.monitoring_config.get('health_interval', 900)  # 15 minutes
        
        # Status storage
        self.device_status = {}
        self.monitoring_tasks = {}
        self.is_running = False
        
    async def start_monitoring(self):
        """Start continuous device monitoring."""
        if self.is_running:
            logger.warning("Device monitoring is already running")
            return
        
        self.is_running = True
        logger.info("Starting device monitoring")
        
        try:
            # Start monitoring tasks for each network
            for network in self.networks:
                network_id = network.get('id')
                if network_id:
                    await self._start_network_monitoring(network_id)
            
            # Keep the monitoring running
            while self.is_running:
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Error in device monitoring: {str(e)}")
            self.is_running = False
    
    async def stop_monitoring(self):
        """Stop device monitoring."""
        logger.info("Stopping device monitoring")
        self.is_running = False
        
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks.values():
            if not task.done():
                task.cancel()
        
        self.monitoring_tasks.clear()
        logger.info("Device monitoring stopped")
    
    async def _start_network_monitoring(self, network_id: int):
        """Start monitoring for a specific network."""
        try:
            logger.info(f"Starting monitoring for network {network_id}")
            
            # Start ping monitoring
            ping_task = asyncio.create_task(
                self._ping_monitoring_loop(network_id)
            )
            self.monitoring_tasks[f"ping_{network_id}"] = ping_task
            
            # Start SNMP monitoring
            snmp_task = asyncio.create_task(
                self._snmp_monitoring_loop(network_id)
            )
            self.monitoring_tasks[f"snmp_{network_id}"] = snmp_task
            
            # Start SSH monitoring
            ssh_task = asyncio.create_task(
                self._ssh_monitoring_loop(network_id)
            )
            self.monitoring_tasks[f"ssh_{network_id}"] = ssh_task
            
            # Start health monitoring
            health_task = asyncio.create_task(
                self._health_monitoring_loop(network_id)
            )
            self.monitoring_tasks[f"health_{network_id}"] = health_task
            
            logger.info(f"Monitoring tasks started for network {network_id}")
            
        except Exception as e:
            logger.error(f"Error starting monitoring for network {network_id}: {str(e)}")
    
    async def _ping_monitoring_loop(self, network_id: int):
        """Continuous ping monitoring loop."""
        while self.is_running:
            try:
                await self._check_ping_status(network_id)
                await asyncio.sleep(self.ping_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in ping monitoring for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _snmp_monitoring_loop(self, network_id: int):
        """Continuous SNMP monitoring loop."""
        while self.is_running:
            try:
                await self._check_snmp_status(network_id)
                await asyncio.sleep(self.snmp_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in SNMP monitoring for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _ssh_monitoring_loop(self, network_id: int):
        """Continuous SSH monitoring loop."""
        while self.is_running:
            try:
                await self._check_ssh_status(network_id)
                await asyncio.sleep(self.ssh_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in SSH monitoring for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _health_monitoring_loop(self, network_id: int):
        """Continuous health monitoring loop."""
        while self.is_running:
            try:
                await self._collect_health_metrics(network_id)
                await asyncio.sleep(self.health_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health monitoring for network {network_id}: {str(e)}")
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _check_ping_status(self, network_id: int):
        """Check ping status for all devices in a network."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking ping status for {len(devices)} devices in network {network_id}")
            
            # Check ping status concurrently
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_device = {
                    executor.submit(self._ping_device, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        ping_status = future.result()
                        await self._update_device_status(network_id, device['ip'], 'ping_status', ping_status)
                    except Exception as e:
                        logger.error(f"Error checking ping for {device['ip']}: {str(e)}")
            
            # Report status to backend
            await self._report_device_status(network_id)
            
        except Exception as e:
            logger.error(f"Error checking ping status for network {network_id}: {str(e)}")
    
    async def _check_snmp_status(self, network_id: int):
        """Check SNMP status for all devices in a network."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking SNMP status for {len(devices)} devices in network {network_id}")
            
            # Check SNMP status concurrently
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_device = {
                    executor.submit(self._check_snmp_device, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        snmp_status = future.result()
                        await self._update_device_status(network_id, device['ip'], 'snmp_status', snmp_status)
                    except Exception as e:
                        logger.error(f"Error checking SNMP for {device['ip']}: {str(e)}")
            
            # Report status to backend
            await self._report_device_status(network_id)
            
        except Exception as e:
            logger.error(f"Error checking SNMP status for network {network_id}: {str(e)}")
    
    async def _check_ssh_status(self, network_id: int):
        """Check SSH status for all devices in a network."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Checking SSH status for {len(devices)} devices in network {network_id}")
            
            # Check SSH status concurrently
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_device = {
                    executor.submit(self._check_ssh_device, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        ssh_status = future.result()
                        await self._update_device_status(network_id, device['ip'], 'ssh_status', ssh_status)
                    except Exception as e:
                        logger.error(f"Error checking SSH for {device['ip']}: {str(e)}")
            
            # Report status to backend
            await self._report_device_status(network_id)
            
        except Exception as e:
            logger.error(f"Error checking SSH status for network {network_id}: {str(e)}")
    
    async def _collect_health_metrics(self, network_id: int):
        """Collect health metrics for devices in a network."""
        try:
            # Get devices for this network
            devices = await self._get_network_devices(network_id)
            if not devices:
                return
            
            logger.debug(f"Collecting health metrics for {len(devices)} devices in network {network_id}")
            
            # Collect metrics concurrently
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_to_device = {
                    executor.submit(self._get_device_health, device): device 
                    for device in devices
                }
                
                # Process results
                for future in as_completed(future_to_device):
                    device = future_to_device[future]
                    try:
                        health_data = future.result()
                        if health_data:
                            await self._update_device_health(network_id, device['ip'], health_data)
                    except Exception as e:
                        logger.error(f"Error collecting health for {device['ip']}: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error collecting health metrics for network {network_id}: {str(e)}")
    
    def _ping_device(self, device: Dict[str, Any]) -> bool:
        """Ping a specific device."""
        try:
            ip = device['ip']
            
            # Use ping command appropriate for the OS
            if self._is_windows():
                cmd = ['ping', '-n', '1', '-w', '2000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '2', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            return result.returncode == 0
            
        except Exception as e:
            logger.error(f"Error pinging {device.get('ip', 'unknown')}: {str(e)}")
            return False
    
    def _check_snmp_device(self, device: Dict[str, Any]) -> bool:
        """Check SNMP connectivity to a device."""
        try:
            # This would use a proper SNMP library
            # For now, we'll simulate SNMP checks
            ip = device['ip']
            logger.debug(f"Checking SNMP for {ip}")
            
            # Simulate SNMP check (replace with actual implementation)
            return True
            
        except Exception as e:
            logger.error(f"Error checking SNMP for {device.get('ip', 'unknown')}: {str(e)}")
            return False
    
    def _check_ssh_device(self, device: Dict[str, Any]) -> bool:
        """Check SSH connectivity to a device."""
        try:
            # This would attempt SSH connection
            # For now, we'll simulate SSH checks
            ip = device['ip']
            logger.debug(f"Checking SSH for {ip}")
            
            # Simulate SSH check (replace with actual implementation)
            return False  # Most devices don't have SSH enabled by default
            
        except Exception as e:
            logger.error(f"Error checking SSH for {device.get('ip', 'unknown')}: {str(e)}")
            return False
    
    def _get_device_health(self, device: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get health metrics for a device."""
        try:
            # This would collect actual health metrics via SNMP
            # For now, we'll simulate health data
            ip = device['ip']
            logger.debug(f"Getting health metrics for {ip}")
            
            # Simulate health metrics
            health_data = {
                'cpu_usage': 25,  # Percentage
                'memory_usage': 60,  # Percentage
                'temperature': 45,  # Celsius
                'uptime': '1234567890',  # SNMP uptime
                'interface_count': 24,
                'active_interfaces': 18
            }
            
            return health_data
            
        except Exception as e:
            logger.error(f"Error getting health for {device.get('ip', 'unknown')}: {str(e)}")
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
    
    async def _update_device_status(self, network_id: int, ip: str, status_type: str, value: bool):
        """Update device status in local storage."""
        try:
            if network_id not in self.device_status:
                self.device_status[network_id] = {}
            
            if ip not in self.device_status[network_id]:
                self.device_status[network_id][ip] = {}
            
            self.device_status[network_id][ip][status_type] = value
            self.device_status[network_id][ip]['last_updated'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"Error updating device status: {str(e)}")
    
    async def _update_device_health(self, network_id: int, ip: str, health_data: Dict[str, Any]):
        """Update device health data in local storage."""
        try:
            if network_id not in self.device_status:
                self.device_status[network_id] = {}
            
            if ip not in self.device_status[network_id]:
                self.device_status[network_id][ip] = {}
            
            self.device_status[network_id][ip]['health'] = health_data
            self.device_status[network_id][ip]['health_updated'] = datetime.utcnow().isoformat()
            
        except Exception as e:
            logger.error(f"Error updating device health: {str(e)}")
    
    async def _report_device_status(self, network_id: int):
        """Report device status to backend."""
        try:
            if network_id not in self.device_status:
                return
            
            # Prepare status data
            device_statuses = []
            for ip, status in self.device_status[network_id].items():
                device_status = {
                    'ip': ip,
                    'ping_status': status.get('ping_status', False),
                    'snmp_status': status.get('snmp_status', False),
                    'ssh_status': status.get('ssh_status', False),
                    'timestamp': status.get('last_updated', datetime.utcnow().isoformat())
                }
                device_statuses.append(device_status)
            
            # Send to backend
            url = f"{self.backend_url}/api/v1/agents/{self.agent_id}/device-status-report"
            headers = {'X-Agent-Token': self.agent_token}
            data = {
                'network_id': network_id,
                'device_statuses': device_statuses
            }
            
            response = requests.post(url, headers=headers, json=data)
            if response.status_code == 200:
                logger.debug(f"Device status reported for network {network_id}")
            else:
                logger.warning(f"Failed to report device status: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Error reporting device status: {str(e)}")
    
    def _is_windows(self) -> bool:
        """Check if running on Windows."""
        import platform
        return platform.system().lower() == "windows"
    
    def get_device_status_summary(self, network_id: int) -> Dict[str, Any]:
        """Get summary of device status for a network."""
        try:
            if network_id not in self.device_status:
                return {}
            
            devices = self.device_status[network_id]
            total_devices = len(devices)
            online_devices = sum(1 for d in devices.values() if d.get('ping_status', False))
            snmp_devices = sum(1 for d in devices.values() if d.get('snmp_status', False))
            ssh_devices = sum(1 for d in devices.values() if d.get('ssh_status', False))
            
            return {
                'total_devices': total_devices,
                'online_devices': online_devices,
                'snmp_devices': snmp_devices,
                'ssh_devices': ssh_devices,
                'offline_devices': total_devices - online_devices,
                'last_updated': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting status summary: {str(e)}")
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
        'monitoring_config': {
            'ping_interval': 60,
            'snmp_interval': 300,
            'ssh_interval': 600,
            'health_interval': 900
        }
    }
    
    # Create monitor instance
    monitor = DeviceMonitor(config)
    
    # Run monitoring
    asyncio.run(monitor.start_monitoring()) 