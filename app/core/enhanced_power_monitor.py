#!/usr/bin/env python3
"""
Enhanced Power Monitoring System
Focuses on PSU (Power Supply Unit) information instead of generic power sensors
"""

import re
import logging
from typing import Dict, List, Optional
from pysnmp.hlapi import *
from app.services.ssh_engine.ssh_connector import run_show_command

logger = logging.getLogger(__name__)

class EnhancedPowerMonitor:
    """Enhanced power monitoring focusing on PSU information"""
    
    def __init__(self, snmp_poller: 'SNMPPoller', db_session=None):
        self.snmp_poller = snmp_poller
        self.db_session = db_session
        
    def get_power_data(self, ip_address: str, device_id: int = None) -> Dict:
        """Get comprehensive power data including PSU information"""
        try:
            logger.info(f"Getting enhanced power data for {ip_address}")
            
            # Try SNMP first for PSU information
            snmp_data = self._get_power_snmp(ip_address)
            
            if snmp_data and self._validate_power_data(snmp_data):
                logger.info(f"SNMP power data retrieved for {ip_address}: {snmp_data}")
                return snmp_data
            
            # Fallback to SSH for detailed PSU information
            ssh_data = self._get_power_ssh(ip_address, device_id)
            
            if ssh_data:
                logger.info(f"SSH power data retrieved for {ip_address}: {ssh_data}")
                return ssh_data
            
            logger.warning(f"No power data available for {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error getting power data for {ip_address}: {e}")
            return {}
    
    def _get_power_snmp(self, ip_address: str) -> Dict:
        """Get PSU information via SNMP"""
        try:
            power_data = {}
            
            # Cisco PSU OIDs
            psu_oids = {
                'psu_model': '1.3.6.1.4.1.9.9.13.1.5.1.2',      # PSU model
                'psu_serial': '1.3.6.1.4.1.9.9.13.1.5.1.3',     # PSU serial number
                'psu_capacity': '1.3.6.1.4.1.9.9.13.1.5.1.4',   # PSU capacity
                'psu_status': '1.3.6.1.4.1.9.9.13.1.5.1.5',     # PSU status
                'psu_voltage': '1.3.6.1.4.1.9.9.13.1.5.1.6',    # PSU voltage
                'psu_current': '1.3.6.1.4.1.9.9.13.1.5.1.7',    # PSU current
                'psu_power': '1.3.6.1.4.1.9.9.13.1.5.1.8',      # PSU power consumption
            }
            
            # Try to get PSU information for multiple PSUs (index 1, 2, etc.)
            for psu_index in range(1, 5):  # Try up to 4 PSUs
                psu_info = {}
                psu_found = False
                
                for oid_name, base_oid in psu_oids.items():
                    oid = f"{base_oid}.{psu_index}"
                    value = self._get_snmp_value(ip_address, oid)
                    
                    if value and value.strip() and value != 'No Such Object currently exists at this OID':
                        psu_info[oid_name] = value.strip()
                        psu_found = True
                
                if psu_found:
                    power_data[f'psu_{psu_index}'] = psu_info
            
            # If no PSU data found, try alternative OIDs
            if not power_data:
                power_data = self._get_alternative_power_oids(ip_address)
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error getting SNMP power data: {e}")
            return {}
    
    def _get_alternative_power_oids(self, ip_address: str) -> Dict:
        """Try alternative power OIDs for different device types"""
        try:
            power_data = {}
            
            # Alternative Cisco PSU OIDs
            alt_oids = [
                '1.3.6.1.4.1.9.9.13.1.5.1.2.1',  # Alternative PSU model
                '1.3.6.1.4.1.9.9.13.1.5.1.3.1',  # Alternative PSU serial
                '1.3.6.1.4.1.9.9.13.1.5.1.4.1',  # Alternative PSU capacity
                '1.3.6.1.4.1.9.9.13.1.5.1.5.1',  # Alternative PSU status
            ]
            
            for i, oid in enumerate(alt_oids):
                value = self._get_snmp_value(ip_address, oid)
                if value and value.strip() and value != 'No Such Object currently exists at this OID':
                    power_data[f'psu_alt_{i+1}'] = value.strip()
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error getting alternative power OIDs: {e}")
            return {}
    
    def _get_power_ssh(self, ip_address: str, device_id: int = None) -> Dict:
        """Get PSU information via SSH CLI commands"""
        try:
            # Get device credentials
            credentials = self._get_device_credentials(ip_address, device_id)
            if not credentials:
                logger.warning(f"No SSH credentials available for {ip_address}")
                return {}
            
            # Get device profile for vendor-specific commands
            device_profile = self._get_device_profile(ip_address)
            vendor = device_profile.get('vendor', 'cisco')
            
            # Execute vendor-specific power commands
            power_output = self._execute_power_commands(ip_address, credentials, vendor)
            
            if power_output:
                # Parse the output based on vendor
                return self._parse_power_cli(power_output, vendor)
            
            return {}
            
        except Exception as e:
            logger.error(f"Error getting SSH power data: {e}")
            return {}
    
    def _get_device_credentials(self, ip_address: str, device_id: int = None) -> Dict:
        """Get SSH credentials for the device"""
        try:
            if not self.db_session:
                return {}
            
            # Get device from database
            from app.models.base import Device
            device = self.db_session.query(Device).filter(Device.ip == ip_address).first()
            
            if device and device.username and device.password:
                return {
                    'username': device.username,
                    'password': device.password,
                    'ip': ip_address
                }
            
            return {}
            
        except Exception as e:
            logger.error(f"Error getting device credentials: {e}")
            return {}
    
    def _execute_power_commands(self, ip_address: str, credentials: Dict, vendor: str) -> str:
        """Execute vendor-specific power commands"""
        try:
            commands = self._get_power_commands(vendor)
            
            for command in commands:
                try:
                    output = run_show_command(
                        ip_address,
                        credentials['username'],
                        credentials['password'],
                        command
                    )
                    
                    if output and 'error' not in output.lower():
                        logger.info(f"Power command '{command}' executed successfully for {ip_address}")
                        return output
                        
                except Exception as e:
                    logger.debug(f"Command '{command}' failed for {ip_address}: {e}")
                    continue
            
            return ""
            
        except Exception as e:
            logger.error(f"Error executing power commands: {e}")
            return ""
    
    def _get_power_commands(self, vendor: str) -> List[str]:
        """Get vendor-specific power commands"""
        commands = {
            'cisco': [
                'show environment power',
                'show environment all',
                'show power inline',
                'show power',
                'show power supply',
                'show inventory power',
                'show power detail',
            ],
            'juniper': [
                'show chassis power',
                'show chassis environment',
                'show power',
            ],
            'arista': [
                'show power',
                'show environment power',
                'show power supply',
            ],
            'hp': [
                'show power',
                'show environment',
                'show power supply',
            ],
            'dell': [
                'show power',
                'show environment',
                'show power supply',
            ],
            'brocade': [
                'show power',
                'show environment',
                'show power supply',
            ]
        }
        
        return commands.get(vendor.lower(), commands['cisco'])
    
    def _parse_power_cli(self, output: str, vendor: str) -> Dict:
        """Parse power CLI output based on vendor"""
        try:
            if vendor.lower() == 'cisco':
                return self._parse_cisco_power(output)
            elif vendor.lower() == 'juniper':
                return self._parse_juniper_power(output)
            elif vendor.lower() == 'arista':
                return self._parse_arista_power(output)
            else:
                return self._parse_generic_power(output)
                
        except Exception as e:
            logger.error(f"Error parsing power CLI output: {e}")
            return {}
    
    def _parse_cisco_power(self, output: str) -> Dict:
        """Parse Cisco power CLI output"""
        power_data = {}
        
        try:
            # Parse PSU information from show environment power format
            # Format: SW  PID                 Serial#     Status           Sys Pwr  PoE Pwr  Watts
            lines = output.strip().split('\n')
            
            for line in lines:
                # Skip header lines and empty lines
                if not line.strip() or 'SW' in line or '--' in line:
                    continue
                
                # Split the line by whitespace and handle multi-word fields
                parts = line.split()
                if len(parts) >= 7:
                    slot = parts[0]
                    # Handle multi-word PID (e.g., "PWR-C1-715WAC")
                    pid_end = 1
                    while pid_end < len(parts) and not parts[pid_end].startswith('LIT') and not parts[pid_end] == 'Unknown':
                        pid_end += 1
                    pid = ' '.join(parts[1:pid_end])
                    
                    # Handle multi-word Serial (e.g., "LIT17235R4W")
                    serial_end = pid_end + 1
                    while serial_end < len(parts) and not any(word in parts[serial_end] for word in ['Power', 'Bad', 'Good', 'No']):
                        serial_end += 1
                    serial = ' '.join(parts[pid_end:serial_end])
                    
                    # Handle multi-word Status (e.g., "No Input Power", "No Response")
                    status_end = serial_end + 1
                    while status_end < len(parts) and not any(word in parts[status_end] for word in ['Bad', 'Good']):
                        status_end += 1
                    status = ' '.join(parts[serial_end:status_end])
                    
                    # Get remaining fields
                    if len(parts) >= status_end + 2:
                        sys_pwr = parts[status_end]
                        poe_pwr = parts[status_end + 1]
                        watts = parts[status_end + 2]
                        
                        # Only process if not "Not Present"
                        if 'present' not in status.lower():
                            psu_info = {
                                'model': pid,
                                'serial': serial,
                                'capacity': f"{watts}W" if watts != 'Unknown' else 'Unknown',
                                'status': status,
                                'power_consumption': f"{watts}W" if watts != 'Unknown' else 'Unknown',
                                'sys_power': sys_pwr,
                                'poe_power': poe_pwr
                            }
                            power_data[f'psu_{slot}'] = psu_info
            
            # If no PSU data found in table format, try alternative patterns
            if not power_data:
                power_data = self._parse_cisco_power_alternative(output)
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error parsing Cisco power output: {e}")
            return {}
    
    def _parse_cisco_power_alternative(self, output: str) -> Dict:
        """Parse Cisco power output using alternative patterns"""
        power_data = {}
        
        try:
            # Parse inline power information
            # Format: Module   Available     Used     Remaining
            inline_match = re.search(r'(\d+)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)', output)
            if inline_match:
                module, available, used, remaining = inline_match.groups()
                power_data['inline_power'] = {
                    'module': module,
                    'available': f"{available}W",
                    'used': f"{used}W",
                    'remaining': f"{remaining}W"
                }
            
            # Look for any power-related information
            power_matches = re.findall(r'(\d+)\s*W', output)
            if power_matches:
                power_data['total_power'] = f"{max(map(int, power_matches))}W"
            
            # Look for PSU status
            status_matches = re.findall(r'(OK|FAIL|WARNING|CRITICAL)', output, re.IGNORECASE)
            if status_matches:
                power_data['overall_status'] = status_matches[0].upper()
            
            # Look for voltage information
            voltage_matches = re.findall(r'(\d+)\s*V', output)
            if voltage_matches:
                power_data['voltage'] = f"{voltage_matches[0]}V"
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error parsing Cisco power alternative: {e}")
            return {}
    
    def _parse_juniper_power(self, output: str) -> Dict:
        """Parse Juniper power CLI output"""
        power_data = {}
        
        try:
            # Parse PSU information
            psu_sections = re.split(r'Power Supply\s+\d+:', output, flags=re.IGNORECASE)
            
            for i, section in enumerate(psu_sections[1:], 1):
                psu_info = {}
                
                # Extract PSU model
                model_match = re.search(r'Model\s*:\s*([^\n]+)', section, re.IGNORECASE)
                if model_match:
                    psu_info['model'] = model_match.group(1).strip()
                
                # Extract PSU status
                status_match = re.search(r'Status\s*:\s*([^\n]+)', section, re.IGNORECASE)
                if status_match:
                    psu_info['status'] = status_match.group(1).strip()
                
                # Extract power consumption
                power_match = re.search(r'(\d+)\s*W', section)
                if power_match:
                    psu_info['power_consumption'] = f"{power_match.group(1)}W"
                
                if psu_info:
                    power_data[f'psu_{i}'] = psu_info
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error parsing Juniper power output: {e}")
            return {}
    
    def _parse_arista_power(self, output: str) -> Dict:
        """Parse Arista power CLI output"""
        power_data = {}
        
        try:
            # Parse PSU information
            psu_sections = re.split(r'Power Supply\s+\d+:', output, flags=re.IGNORECASE)
            
            for i, section in enumerate(psu_sections[1:], 1):
                psu_info = {}
                
                # Extract PSU model
                model_match = re.search(r'Model\s*:\s*([^\n]+)', section, re.IGNORECASE)
                if model_match:
                    psu_info['model'] = model_match.group(1).strip()
                
                # Extract PSU status
                status_match = re.search(r'Status\s*:\s*([^\n]+)', section, re.IGNORECASE)
                if status_match:
                    psu_info['status'] = status_match.group(1).strip()
                
                # Extract power consumption
                power_match = re.search(r'(\d+)\s*W', section)
                if power_match:
                    psu_info['power_consumption'] = f"{power_match.group(1)}W"
                
                if psu_info:
                    power_data[f'psu_{i}'] = psu_info
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error parsing Arista power output: {e}")
            return {}
    
    def _parse_generic_power(self, output: str) -> Dict:
        """Parse generic power CLI output"""
        power_data = {}
        
        try:
            # Look for any power-related information
            power_matches = re.findall(r'(\d+)\s*W', output)
            if power_matches:
                power_data['total_power'] = f"{max(map(int, power_matches))}W"
            
            # Look for status information
            status_matches = re.findall(r'(OK|FAIL|WARNING|CRITICAL|ON|OFF)', output, re.IGNORECASE)
            if status_matches:
                power_data['overall_status'] = status_matches[0].upper()
            
            # Look for voltage information
            voltage_matches = re.findall(r'(\d+)\s*V', output)
            if voltage_matches:
                power_data['voltage'] = f"{voltage_matches[0]}V"
            
            return power_data
            
        except Exception as e:
            logger.error(f"Error parsing generic power output: {e}")
            return {}
    
    def _get_device_profile(self, ip_address: str) -> Dict:
        """Get device profile for vendor identification"""
        try:
            # Use the existing smart discovery to get device profile
            from app.core.snmp_poller import SmartSNMPDiscovery
            smart_discovery = SmartSNMPDiscovery(self.snmp_poller.community, self.db_session)
            return smart_discovery._get_device_profile(ip_address)
        except Exception as e:
            logger.error(f"Error getting device profile: {e}")
            return {'vendor': 'cisco'}
    
    def _get_snmp_value(self, ip_address: str, oid: str) -> str:
        """Get single SNMP value"""
        try:
            snmp_engine = SnmpEngine()
            auth_data = CommunityData(self.snmp_poller.community, mpModel=1)
            target = UdpTransportTarget((ip_address, 161), timeout=2, retries=1)
            context = ContextData()
            
            error_indication, error_status, error_index, var_binds = next(
                getCmd(snmp_engine, auth_data, target, context,
                      ObjectType(ObjectIdentity(oid)))
            )
            
            if error_indication or error_status:
                return None
            
            for var_bind in var_binds:
                return str(var_bind[1])
            
            return None
            
        except Exception:
            return None
    
    def _validate_power_data(self, data: Dict) -> bool:
        """Validate power data quality"""
        if not data:
            return False
        
        # Check if we have meaningful power information
        for key, value in data.items():
            if isinstance(value, dict):
                # Check PSU information
                if any(field in value for field in ['model', 'serial', 'capacity', 'status', 'power_consumption']):
                    return True
            elif isinstance(value, str):
                # Check for power-related keywords
                if any(keyword in value.lower() for keyword in ['w', 'v', 'psu', 'power', 'supply']):
                    return True
        
        return False 