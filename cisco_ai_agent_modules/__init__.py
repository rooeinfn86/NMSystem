#!/usr/bin/env python3
"""
Cisco AI Agent Topology Discovery Integration

This module integrates all topology discovery capabilities:
- TopologyDiscovery: Network device and neighbor discovery
- DeviceMonitor: Continuous device status monitoring
- InterfaceTracker: Interface status and configuration tracking
"""

import asyncio
import logging
import json
import os
from typing import Dict, Any, Optional
from datetime import datetime

# Import our modules
from .topology_discovery import TopologyDiscovery
from .device_monitoring import DeviceMonitor
from .interface_tracker import InterfaceTracker

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AgentTopologyManager:
    """Main manager for all agent topology discovery and monitoring capabilities."""
    
    def __init__(self, agent_config: Dict[str, Any]):
        self.agent_config = agent_config
        self.is_running = False
        
        # Initialize modules
        self.topology_discovery = TopologyDiscovery(agent_config)
        self.device_monitor = DeviceMonitor(agent_config)
        self.interface_tracker = InterfaceTracker(agent_config)
        
        # Status tracking
        self.discovery_status = {}
        self.monitoring_status = {}
        self.tracking_status = {}
        
        # Configuration validation
        self._validate_config()
    
    def _validate_config(self):
        """Validate agent configuration."""
        required_fields = ['backend_url', 'agent_token', 'agent_id', 'networks']
        
        for field in required_fields:
            if not self.agent_config.get(field):
                raise ValueError(f"Missing required configuration field: {field}")
        
        logger.info("Agent configuration validated successfully")
    
    async def start_all_services(self):
        """Start all topology discovery and monitoring services."""
        if self.is_running:
            logger.warning("Agent topology services are already running")
            return
        
        self.is_running = True
        logger.info("Starting all agent topology services")
        
        try:
            # Start all services concurrently
            await asyncio.gather(
                self._start_topology_discovery(),
                self._start_device_monitoring(),
                self._start_interface_tracking()
            )
            
        except Exception as e:
            logger.error(f"Error starting agent services: {str(e)}")
            self.is_running = False
            raise
    
    async def stop_all_services(self):
        """Stop all topology discovery and monitoring services."""
        logger.info("Stopping all agent topology services")
        self.is_running = False
        
        # Stop all services
        await asyncio.gather(
            self.topology_discovery.stop_discovery(),
            self.device_monitor.stop_monitoring(),
            self.interface_tracker.stop_tracking(),
            return_exceptions=True
        )
        
        logger.info("All agent topology services stopped")
    
    async def _start_topology_discovery(self):
        """Start topology discovery service."""
        try:
            logger.info("Starting topology discovery service")
            
            # Start discovery for all networks
            for network in self.agent_config['networks']:
                network_id = network.get('id')
                if network_id:
                    logger.info(f"Starting topology discovery for network {network_id}")
                    
                    # Start discovery
                    success = await self.topology_discovery.start_discovery(network_id, "full")
                    if success:
                        self.discovery_status[network_id] = "started"
                        logger.info(f"Topology discovery started for network {network_id}")
                    else:
                        self.discovery_status[network_id] = "failed"
                        logger.error(f"Failed to start topology discovery for network {network_id}")
            
            # Start continuous discovery
            await self.topology_discovery.start_continuous_discovery()
            
        except Exception as e:
            logger.error(f"Error in topology discovery service: {str(e)}")
            raise
    
    async def _start_device_monitoring(self):
        """Start device monitoring service."""
        try:
            logger.info("Starting device monitoring service")
            await self.device_monitor.start_monitoring()
            
        except Exception as e:
            logger.error(f"Error in device monitoring service: {str(e)}")
            raise
    
    async def _start_interface_tracking(self):
        """Start interface tracking service."""
        try:
            logger.info("Starting interface tracking service")
            await self.interface_tracker.start_tracking()
            
        except Exception as e:
            logger.error(f"Error in interface tracking service: {str(e)}")
            raise
    
    async def trigger_discovery(self, network_id: int, discovery_type: str = "full") -> bool:
        """Manually trigger topology discovery for a specific network."""
        try:
            logger.info(f"Manually triggering {discovery_type} discovery for network {network_id}")
            
            success = await self.topology_discovery.start_discovery(network_id, discovery_type)
            
            if success:
                self.discovery_status[network_id] = "triggered"
                logger.info(f"Discovery triggered successfully for network {network_id}")
            else:
                self.discovery_status[network_id] = "failed"
                logger.error(f"Failed to trigger discovery for network {network_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error triggering discovery: {str(e)}")
            return False
    
    def get_service_status(self) -> Dict[str, Any]:
        """Get status of all services."""
        return {
            'is_running': self.is_running,
            'discovery_status': self.discovery_status,
            'monitoring_status': self.monitoring_status,
            'tracking_status': self.tracking_status,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def get_network_summary(self, network_id: int) -> Dict[str, Any]:
        """Get summary of network topology and status."""
        try:
            summary = {
                'network_id': network_id,
                'discovery_status': self.discovery_status.get(network_id, 'unknown'),
                'device_count': len(self.device_monitor.device_status.get(network_id, {})),
                'interface_count': len(self.interface_tracker.interface_status.get(network_id, {})),
                'last_updated': datetime.utcnow().isoformat()
            }
            
            # Add device status summary
            device_summary = self.device_monitor.get_device_status_summary(network_id)
            summary.update(device_summary)
            
            # Add interface summary
            interface_summary = self.interface_tracker.get_interface_summary(network_id)
            summary.update(interface_summary)
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting network summary: {str(e)}")
            return {'error': str(e)}
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of all services."""
        try:
            health_status = {
                'timestamp': datetime.utcnow().isoformat(),
                'overall_status': 'healthy',
                'services': {}
            }
            
            # Check topology discovery
            try:
                discovery_healthy = all(
                    status in ['started', 'completed', 'triggered'] 
                    for status in self.discovery_status.values()
                )
                health_status['services']['topology_discovery'] = {
                    'status': 'healthy' if discovery_healthy else 'unhealthy',
                    'details': self.discovery_status
                }
            except Exception as e:
                health_status['services']['topology_discovery'] = {
                    'status': 'error',
                    'details': str(e)
                }
            
            # Check device monitoring
            try:
                monitoring_healthy = self.device_monitor.is_running
                health_status['services']['device_monitoring'] = {
                    'status': 'healthy' if monitoring_healthy else 'unhealthy',
                    'details': f"Running: {monitoring_healthy}"
                }
            except Exception as e:
                health_status['services']['device_monitoring'] = {
                    'status': 'error',
                    'details': str(e)
                }
            
            # Check interface tracking
            try:
                tracking_healthy = self.interface_tracker.is_running
                health_status['services']['interface_tracking'] = {
                    'status': 'healthy' if tracking_healthy else 'unhealthy',
                    'details': f"Running: {tracking_healthy}"
                }
            except Exception as e:
                health_status['services']['interface_tracking'] = {
                    'status': 'error',
                    'details': str(e)
                }
            
            # Determine overall status
            service_statuses = [service['status'] for service in health_status['services'].values()]
            if 'error' in service_statuses:
                health_status['overall_status'] = 'error'
            elif 'unhealthy' in service_statuses:
                health_status['overall_status'] = 'unhealthy'
            
            return health_status
            
        except Exception as e:
            logger.error(f"Error in health check: {str(e)}")
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'overall_status': 'error',
                'error': str(e)
            }


# Example usage and configuration
def create_agent_manager(config_file: str = None) -> AgentTopologyManager:
    """Create an agent manager instance with configuration."""
    
    if config_file and os.path.exists(config_file):
        # Load configuration from file
        with open(config_file, 'r') as f:
            config = json.load(f)
    else:
        # Use default configuration
        config = {
            'backend_url': 'https://cisco-ai-backend-production.up.railway.app',
            'agent_token': os.getenv('AGENT_TOKEN', 'your_agent_token_here'),
            'agent_id': int(os.getenv('AGENT_ID', '123')),
            'networks': [
                {
                    'id': 1,
                    'name': 'Main Network',
                    'network_range': '192.168.1.0/24'
                }
            ],
            'discovery_config': {
                'snmp_community': os.getenv('SNMP_COMMUNITY', 'public'),
                'snmp_version': '2c',
                'ping_timeout': 2,
                'max_concurrent_discoveries': 10,
                'discovery_interval': 300
            },
            'monitoring_config': {
                'ping_interval': 60,
                'snmp_interval': 300,
                'ssh_interval': 600,
                'health_interval': 900
            },
            'interface_tracking_config': {
                'interface_check_interval': 120,
                'bandwidth_check_interval': 300,
                'error_check_interval': 60,
                'config_check_interval': 1800
            }
        }
    
    return AgentTopologyManager(config)


# Main entry point for standalone operation
async def main():
    """Main entry point for standalone agent operation."""
    try:
        # Create agent manager
        agent_manager = create_agent_manager()
        
        # Start all services
        await agent_manager.start_all_services()
        
        # Keep running
        while agent_manager.is_running:
            await asyncio.sleep(10)
            
            # Perform health check
            health = await agent_manager.health_check()
            logger.info(f"Health check: {health['overall_status']}")
            
    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down...")
    except Exception as e:
        logger.error(f"Error in main: {str(e)}")
    finally:
        if 'agent_manager' in locals():
            await agent_manager.stop_all_services()


if __name__ == "__main__":
    # Run the agent
    asyncio.run(main()) 