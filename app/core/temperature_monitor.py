from typing import Dict, Optional
from sqlalchemy.orm import Session
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class EnhancedTemperatureMonitor:
    """Enhanced temperature monitoring with multiple data sources"""
    
    def __init__(self, snmp_poller: 'SNMPPoller', db_session: Session = None):
        self.snmp_poller = snmp_poller
        self.db_session = db_session
        self.temperature_cache = {}
        self.cache_timeout = 300  # 5 minutes
        
        # Temperature thresholds by vendor
        self.temperature_thresholds = {
            'cisco': {
                'warning': 45,
                'critical': 60,
                'shutdown': 70
            },
            'juniper': {
                'warning': 50,
                'critical': 65,
                'shutdown': 75
            },
            'arista': {
                'warning': 45,
                'critical': 60,
                'shutdown': 70
            },
            'hp': {
                'warning': 50,
                'critical': 65,
                'shutdown': 75
            },
            'generic': {
                'warning': 50,
                'critical': 65,
                'shutdown': 75
            }
        }
    
    def get_temperature_data(self, ip_address: str, device_id: int = None) -> Dict:
        """Get comprehensive temperature data for a device."""
        try:
            logger.info(f"Getting temperature data for {ip_address}")
            
            # Check cache first
            cache_key = f"{ip_address}_temperature"
            if cache_key in self.temperature_cache:
                cache_data = self.temperature_cache[cache_key]
                if (datetime.now() - cache_data['timestamp']).seconds < self.cache_timeout:
                    logger.info(f"Using cached temperature data for {ip_address}")
                    return cache_data['data']
            
            # Try SNMP first
            snmp_data = self._get_temperature_snmp(ip_address)
            
            if snmp_data:
                # Add metadata
                snmp_data['source'] = 'snmp'
                snmp_data['timestamp'] = datetime.now().isoformat()
                snmp_data['device_id'] = device_id
                
                # Cache the result
                self.temperature_cache[cache_key] = {
                    'data': snmp_data,
                    'timestamp': datetime.now()
                }
                
                return snmp_data
            
            # Fallback to SSH
            ssh_data = self._get_temperature_ssh(ip_address, device_id)
            
            if ssh_data:
                # Add metadata
                ssh_data['source'] = 'ssh'
                ssh_data['timestamp'] = datetime.now().isoformat()
                ssh_data['device_id'] = device_id
                
                # Cache the result
                self.temperature_cache[cache_key] = {
                    'data': ssh_data,
                    'timestamp': datetime.now()
                }
                
                return ssh_data
            
            logger.warning(f"No temperature data available for {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error getting temperature data for {ip_address}: {str(e)}")
            return {}
    
    def _get_temperature_snmp(self, ip_address: str) -> Dict:
        """Get temperature data using SNMP."""
        try:
            temperature_data = {}
            
            # Common SNMP OIDs for temperature
            temp_oids = [
                '1.3.6.1.4.1.9.9.13.1.3.1.3',  # Cisco temperature
                '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.3',  # Juniper temperature
                '1.3.6.1.2.1.99.1.1.1.2',  # Generic temperature
                '1.3.6.1.4.1.9.9.13.1.3.1.2',  # Cisco temperature threshold
                '1.3.6.1.4.1.9.9.13.1.3.1.4'   # Cisco temperature status
            ]
            
            for oid in temp_oids:
                try:
                    value = self.snmp_poller._get_snmp_value(ip_address, oid)
                    if value and value != 'No Such Object currently exists at this OID':
                        # Parse the value
                        try:
                            temp_value = float(value)
                            if 0 <= temp_value <= 150:  # Reasonable temperature range
                                sensor_name = f"temp_sensor_{oid.split('.')[-1]}"
                                temperature_data[sensor_name] = {
                                    'value': temp_value,
                                    'unit': 'celsius',
                                    'oid': oid,
                                    'status': self._get_temperature_status(temp_value, 'generic')
                                }
                        except ValueError:
                            # Non-numeric value, might be status string
                            sensor_name = f"temp_status_{oid.split('.')[-1]}"
                            temperature_data[sensor_name] = {
                                'value': value,
                                'unit': 'status',
                                'oid': oid
                            }
                
                except Exception as e:
                    logger.debug(f"Error getting SNMP temperature for OID {oid}: {str(e)}")
                    continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error in SNMP temperature collection: {str(e)}")
            return {}
    
    def _get_temperature_ssh(self, ip_address: str, device_id: int = None) -> Dict:
        """Get temperature data using SSH."""
        try:
            # Get device credentials
            credentials = self._get_device_credentials(ip_address, device_id)
            if not credentials:
                logger.warning(f"No credentials available for SSH temperature check on {ip_address}")
                return {}
            
            # Get device platform
            platform = credentials.get('platform', 'cisco')
            
            # Run temperature command based on platform
            if platform == 'cisco':
                command = 'show environment temperature'
            elif platform == 'juniper':
                command = 'show chassis temperature'
            elif platform == 'arista':
                command = 'show environment temperature'
            elif platform == 'hp':
                command = 'show environment temperature'
            else:
                command = 'show environment'
            
            # Execute command
            from app.services.ssh_engine.ssh_connector import run_show_command
            output = run_show_command(ip_address, command, credentials)
            
            if output:
                return self._parse_temperature_cli(output, platform)
            
            return {}
            
        except Exception as e:
            logger.error(f"Error in SSH temperature collection: {str(e)}")
            return {}
    
    def _get_device_credentials(self, ip_address: str, device_id: int = None) -> Dict:
        """Get device credentials for SSH access."""
        try:
            if self.db_session and device_id:
                # Get credentials from database
                from app.models.base import Device
                device = self.db_session.query(Device).filter(Device.id == device_id).first()
                
                if device:
                    return {
                        'username': device.username,
                        'password': device.password,
                        'platform': device.platform or 'cisco',
                        'ip_address': device.ip_address
                    }
            
            # Fallback to default credentials
            return {
                'username': 'admin',
                'password': 'admin',
                'platform': 'cisco',
                'ip_address': ip_address
            }
            
        except Exception as e:
            logger.error(f"Error getting device credentials: {str(e)}")
            return {}
    
    def _parse_temperature_cli(self, output: str, platform: str) -> Dict:
        """Parse temperature data from CLI output."""
        try:
            if platform == 'cisco':
                return self._parse_cisco_temperature(output)
            elif platform == 'juniper':
                return self._parse_juniper_temperature(output)
            elif platform == 'arista':
                return self._parse_arista_temperature(output)
            elif platform == 'hp':
                return self._parse_hp_temperature(output)
            else:
                return self._parse_generic_temperature(output)
                
        except Exception as e:
            logger.error(f"Error parsing temperature CLI output: {str(e)}")
            return {}
    
    def _parse_cisco_temperature(self, output: str) -> Dict:
        """Parse Cisco temperature output."""
        try:
            temperature_data = {}
            
            # Common patterns for Cisco temperature output
            patterns = [
                r'(\w+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\w+)',  # Standard format
                r'(\w+)\s+(\d+)C',  # Simple format
                r'(\w+)\s+(\d+)°C',  # With degree symbol
                r'(\w+)\s+(\d+)\s+degrees'  # Text format
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        sensor_name = match.group(1).strip()
                        try:
                            temp_value = float(match.group(2))
                            temperature_data[sensor_name] = {
                                'value': temp_value,
                                'unit': 'celsius',
                                'source': 'cli',
                                'status': self._get_temperature_status(temp_value, 'cisco')
                            }
                        except ValueError:
                            continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Cisco temperature: {str(e)}")
            return {}
    
    def _parse_juniper_temperature(self, output: str) -> Dict:
        """Parse Juniper temperature output."""
        try:
            temperature_data = {}
            
            # Juniper temperature patterns
            patterns = [
                r'(\w+)\s+(\d+)C',
                r'(\w+)\s+(\d+)°C',
                r'(\w+)\s+(\d+)\s+degrees'
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        sensor_name = match.group(1).strip()
                        try:
                            temp_value = float(match.group(2))
                            temperature_data[sensor_name] = {
                                'value': temp_value,
                                'unit': 'celsius',
                                'source': 'cli',
                                'status': self._get_temperature_status(temp_value, 'juniper')
                            }
                        except ValueError:
                            continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Juniper temperature: {str(e)}")
            return {}
    
    def _parse_arista_temperature(self, output: str) -> Dict:
        """Parse Arista temperature output."""
        try:
            temperature_data = {}
            
            # Arista temperature patterns
            patterns = [
                r'(\w+)\s+(\d+)C',
                r'(\w+)\s+(\d+)°C'
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        sensor_name = match.group(1).strip()
                        try:
                            temp_value = float(match.group(2))
                            temperature_data[sensor_name] = {
                                'value': temp_value,
                                'unit': 'celsius',
                                'source': 'cli',
                                'status': self._get_temperature_status(temp_value, 'arista')
                            }
                        except ValueError:
                            continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Arista temperature: {str(e)}")
            return {}
    
    def _parse_hp_temperature(self, output: str) -> Dict:
        """Parse HP temperature output."""
        try:
            temperature_data = {}
            
            # HP temperature patterns
            patterns = [
                r'(\w+)\s+(\d+)C',
                r'(\w+)\s+(\d+)°C'
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        sensor_name = match.group(1).strip()
                        try:
                            temp_value = float(match.group(2))
                            temperature_data[sensor_name] = {
                                'value': temp_value,
                                'unit': 'celsius',
                                'source': 'cli',
                                'status': self._get_temperature_status(temp_value, 'hp')
                            }
                        except ValueError:
                            continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing HP temperature: {str(e)}")
            return {}
    
    def _parse_generic_temperature(self, output: str) -> Dict:
        """Parse generic temperature output."""
        try:
            temperature_data = {}
            
            # Generic temperature patterns
            patterns = [
                r'(\w+)\s+(\d+)C',
                r'(\w+)\s+(\d+)°C',
                r'(\w+)\s+(\d+)\s+degrees',
                r'temperature[:\s]+(\d+)',
                r'temp[:\s]+(\d+)'
            ]
            
            lines = output.split('\n')
            for line in lines:
                for pattern in patterns:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        sensor_name = match.group(1).strip() if len(match.groups()) > 1 else 'generic_temp'
                        try:
                            temp_value = float(match.group(2) if len(match.groups()) > 1 else match.group(1))
                            temperature_data[sensor_name] = {
                                'value': temp_value,
                                'unit': 'celsius',
                                'source': 'cli',
                                'status': self._get_temperature_status(temp_value, 'generic')
                            }
                        except ValueError:
                            continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing generic temperature: {str(e)}")
            return {}
    
    def _get_device_profile(self, ip_address: str) -> Dict:
        """Get device profile for temperature monitoring."""
        try:
            # Get basic device info using SNMP
            device_info = self.snmp_poller.get_basic_device_info(ip_address)
            
            profile = {
                'vendor': 'generic',
                'model': 'unknown',
                'platform': 'unknown'
            }
            
            if device_info:
                sys_descr = device_info.get('sysDescr', '')
                sys_object_id = device_info.get('sysObjectID', '')
                
                # Identify vendor
                if 'cisco' in sys_descr.lower() or 'cisco' in sys_object_id.lower():
                    profile['vendor'] = 'cisco'
                elif 'juniper' in sys_descr.lower() or 'juniper' in sys_object_id.lower():
                    profile['vendor'] = 'juniper'
                elif 'arista' in sys_descr.lower() or 'arista' in sys_object_id.lower():
                    profile['vendor'] = 'arista'
                elif 'hp' in sys_descr.lower() or 'hpe' in sys_descr.lower():
                    profile['vendor'] = 'hp'
                
                profile['platform'] = sys_descr
                profile['model'] = sys_descr.split()[0] if sys_descr else 'unknown'
            
            return profile
            
        except Exception as e:
            logger.error(f"Error getting device profile: {str(e)}")
            return {'vendor': 'generic', 'model': 'unknown', 'platform': 'unknown'}
    
    def _get_snmp_value(self, ip_address: str, oid: str) -> str:
        """Get SNMP value for a specific OID."""
        try:
            return self.snmp_poller._get_snmp_value(ip_address, oid)
        except Exception as e:
            logger.error(f"Error getting SNMP value: {str(e)}")
            return None
    
    def _generate_additional_temperature_oids(self, vendor: str) -> Dict:
        """Generate additional temperature OIDs based on vendor."""
        additional_oids = {
            'cisco': [
                '1.3.6.1.4.1.9.9.13.1.3.1.3.1',  # CPU temperature
                '1.3.6.1.4.1.9.9.13.1.3.1.3.2',  # Ambient temperature
                '1.3.6.1.4.1.9.9.13.1.3.1.3.3'   # Inlet temperature
            ],
            'juniper': [
                '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.3.1',
                '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.3.2'
            ],
            'arista': [
                '1.3.6.1.2.1.99.1.1.1.2.1',
                '1.3.6.1.2.1.99.1.1.1.2.2'
            ],
            'hp': [
                '1.3.6.1.2.1.99.1.1.1.2.1',
                '1.3.6.1.2.1.99.1.1.1.2.2'
            ]
        }
        
        return additional_oids.get(vendor, [])
    
    def _is_valid_temperature(self, value: str) -> bool:
        """Check if a temperature value is valid."""
        try:
            temp_value = float(value)
            return 0 <= temp_value <= 150  # Reasonable temperature range
        except ValueError:
            return False
    
    def _get_temperature_status(self, temperature: float, vendor: str) -> str:
        """Get temperature status based on thresholds."""
        try:
            thresholds = self.temperature_thresholds.get(vendor, self.temperature_thresholds['generic'])
            
            if temperature >= thresholds['shutdown']:
                return 'critical'
            elif temperature >= thresholds['critical']:
                return 'critical'
            elif temperature >= thresholds['warning']:
                return 'warning'
            else:
                return 'normal'
                
        except Exception as e:
            logger.error(f"Error getting temperature status: {str(e)}")
            return 'unknown'
    
    def _validate_temperature_data(self, data: Dict) -> bool:
        """Validate temperature data."""
        try:
            if not data:
                return False
            
            for sensor_name, sensor_data in data.items():
                if 'value' not in sensor_data:
                    return False
                
                try:
                    temp_value = float(sensor_data['value'])
                    if not (0 <= temp_value <= 150):
                        return False
                except ValueError:
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating temperature data: {str(e)}")
            return False 