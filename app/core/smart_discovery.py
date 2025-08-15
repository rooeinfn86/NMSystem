from typing import Dict, List, Optional
from pysnmp.hlapi import *
from sqlalchemy.orm import Session
import logging
import re
from datetime import datetime

logger = logging.getLogger(__name__)

class SmartSNMPDiscovery:
    """Universal smart SNMP discovery system for any type of device data"""
    
    # Class-level storage for OID mappings (persistent across instances)
    oid_mappings = {}
    
    def __init__(self, snmp_community: str, db_session: Session = None):
        self.snmp_community = snmp_community
        self.db_session = db_session
        self.discovery_cache = {}
        self.learned_oids = {}
        
        # Initialize with common OID patterns
        self._initialize_common_oids()
    
    def _initialize_common_oids(self):
        """Initialize common OID patterns for different data categories."""
        self.oid_mappings = {
            'cpu': {
                'cisco': ['1.3.6.1.4.1.9.9.109.1.1.1.1.3', '1.3.6.1.4.1.9.9.109.1.1.1.1.4'],
                'juniper': ['1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.1'],
                'generic': ['1.3.6.1.2.1.25.3.3.1.2']
            },
            'memory': {
                'cisco': ['1.3.6.1.4.1.9.9.48.1.1.1.6', '1.3.6.1.4.1.9.9.48.1.1.1.5'],
                'juniper': ['1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.2'],
                'generic': ['1.3.6.1.2.1.25.2.3.1.6']
            },
            'temperature': {
                'cisco': ['1.3.6.1.4.1.9.9.13.1.3.1.3', '1.3.6.1.4.1.9.9.13.1.3.1.2'],
                'juniper': ['1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.3'],
                'generic': ['1.3.6.1.2.1.99.1.1.1.2']
            }
        }
    
    def discover_data(self, ip_address: str, data_category: str) -> dict:
        """Discover data for a specific category using smart SNMP discovery."""
        try:
            logger.info(f"Starting smart discovery for {data_category} on {ip_address}")
            
            # Check cache first
            cache_key = f"{ip_address}_{data_category}"
            if cache_key in self.discovery_cache:
                logger.info(f"Using cached data for {cache_key}")
                return self.discovery_cache[cache_key]
            
            # Get device profile
            device_profile = self._get_device_profile(ip_address)
            
            # Try preferred OIDs first
            preferred_oids = self._get_preferred_oids(data_category, device_profile)
            result = self._try_preferred_oids(ip_address, data_category, preferred_oids)
            
            if result:
                self.discovery_cache[cache_key] = result
                return result
            
            # Try SNMP walk discovery
            result = self._snmp_walk_discovery(ip_address, data_category, device_profile)
            
            if result:
                self.discovery_cache[cache_key] = result
                return result
            
            # Try pattern-based discovery
            result = self._pattern_based_discovery(ip_address, data_category, device_profile)
            
            if result:
                self.discovery_cache[cache_key] = result
                return result
            
            # Try MIB-based discovery
            result = self._mib_based_discovery(ip_address, data_category, device_profile)
            
            if result:
                self.discovery_cache[cache_key] = result
                return result
            
            logger.warning(f"No data discovered for {data_category} on {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error in smart discovery for {data_category} on {ip_address}: {str(e)}")
            return {}
    
    def _try_preferred_oids(self, ip_address: str, data_category: str, preferred_oids: List[str]) -> dict:
        """Try to get data using preferred OIDs."""
        try:
            result = {}
            
            for oid in preferred_oids:
                value = self._get_snmp_value(ip_address, oid)
                if value and value != 'No Such Object currently exists at this OID':
                    sensor_name = self._generate_sensor_name(oid, value, data_category)
                    result[sensor_name] = {
                        'value': value,
                        'oid': oid,
                        'type': 'preferred'
                    }
            
            return result if result else {}
            
        except Exception as e:
            logger.error(f"Error trying preferred OIDs: {str(e)}")
            return {}
    
    def _get_device_profile(self, ip_address: str) -> dict:
        """Get device profile based on SNMP system information."""
        try:
            profile = {
                'vendor': 'unknown',
                'model': 'unknown',
                'platform': 'unknown'
            }
            
            # Get system description
            sys_descr = self._get_snmp_value(ip_address, '1.3.6.1.2.1.1.1.0')
            if sys_descr:
                profile['vendor'] = self._identify_vendor(sys_descr)
                profile['model'] = self._extract_model(sys_descr)
                profile['platform'] = sys_descr
            
            # Get system object ID
            sys_object_id = self._get_snmp_value(ip_address, '1.3.6.1.2.1.1.2.0')
            if sys_object_id:
                profile['sys_object_id'] = sys_object_id
            
            return profile
            
        except Exception as e:
            logger.error(f"Error getting device profile: {str(e)}")
            return {'vendor': 'unknown', 'model': 'unknown', 'platform': 'unknown'}
    
    def _identify_vendor(self, sys_object_id: str) -> str:
        """Identify vendor from system object ID."""
        if 'cisco' in sys_object_id.lower():
            return 'cisco'
        elif 'juniper' in sys_object_id.lower():
            return 'juniper'
        elif 'arista' in sys_object_id.lower():
            return 'arista'
        elif 'hp' in sys_object_id.lower() or 'hpe' in sys_object_id.lower():
            return 'hp'
        else:
            return 'generic'
    
    def _extract_model(self, sys_descr: str) -> str:
        """Extract model information from system description."""
        try:
            # Common patterns for different vendors
            patterns = [
                r'Cisco\s+(\w+)',
                r'Juniper\s+(\w+)',
                r'Arista\s+(\w+)',
                r'HP\s+(\w+)',
                r'HPE\s+(\w+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, sys_descr, re.IGNORECASE)
                if match:
                    return match.group(1)
            
            return 'unknown'
            
        except Exception as e:
            logger.error(f"Error extracting model: {str(e)}")
            return 'unknown'
    
    def _snmp_walk_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using SNMP walk."""
        try:
            result = {}
            oid_trees = self._get_oid_trees_for_category(data_category, device_profile)
            
            for tree_name, oid_pattern in oid_trees.items():
                try:
                    # Perform SNMP walk
                    for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        SnmpEngine(),
                        CommunityData(self.snmp_community),
                        UdpTransportTarget((ip_address, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity(oid_pattern)),
                        lexicographicMode=False,
                        maxRows=100
                    ):
                        if error_indication or error_status:
                            break
                        
                        for var_bind in var_binds:
                            oid = str(var_bind[0])
                            value = str(var_bind[1])
                            
                            if self._is_relevant_data(oid, value, data_category):
                                sensor_name = self._generate_sensor_name(oid, value, data_category)
                                result[sensor_name] = {
                                    'value': value,
                                    'oid': oid,
                                    'type': 'walk_discovery'
                                }
                
                except Exception as e:
                    logger.warning(f"Error in SNMP walk for {tree_name}: {str(e)}")
                    continue
            
            return result
            
        except Exception as e:
            logger.error(f"Error in SNMP walk discovery: {str(e)}")
            return {}
    
    def _get_oid_trees_for_category(self, data_category: str, device_profile: dict) -> dict:
        """Get OID trees for a specific data category."""
        vendor = device_profile.get('vendor', 'generic')
        
        trees = {
            'cpu': {
                'cisco': '1.3.6.1.4.1.9.9.109',
                'juniper': '1.3.6.1.4.1.2636.3.1.2.1.1.1',
                'generic': '1.3.6.1.2.1.25.3.3'
            },
            'memory': {
                'cisco': '1.3.6.1.4.1.9.9.48',
                'juniper': '1.3.6.1.4.1.2636.3.1.2.1.1.1',
                'generic': '1.3.6.1.2.1.25.2.3'
            },
            'temperature': {
                'cisco': '1.3.6.1.4.1.9.9.13',
                'juniper': '1.3.6.1.4.1.2636.3.1.2.1.1.1',
                'generic': '1.3.6.1.2.1.99.1.1'
            }
        }
        
        return {data_category: trees.get(data_category, {}).get(vendor, '1.3.6.1.2.1')}
    
    def _is_relevant_data(self, oid: str, value: str, data_category: str) -> bool:
        """Check if the data is relevant for the category."""
        try:
            # Skip empty or null values
            if not value or value in ['No Such Object', 'No Such Instance', 'End of MIB View']:
                return False
            
            # Check if value is numeric
            try:
                float(value)
                return True
            except ValueError:
                # For non-numeric values, check if they contain relevant keywords
                relevant_keywords = {
                    'cpu': ['cpu', 'processor', 'utilization'],
                    'memory': ['memory', 'ram', 'storage'],
                    'temperature': ['temp', 'thermal', 'temperature']
                }
                
                keywords = relevant_keywords.get(data_category, [])
                return any(keyword in value.lower() for keyword in keywords)
        
        except Exception as e:
            logger.error(f"Error checking data relevance: {str(e)}")
            return False
    
    def _generate_sensor_name(self, oid: str, value: str, data_category: str) -> str:
        """Generate a sensor name from OID and value."""
        try:
            # Extract the last part of the OID
            oid_parts = oid.split('.')
            if len(oid_parts) > 1:
                sensor_id = oid_parts[-1]
            else:
                sensor_id = 'unknown'
            
            return f"{data_category}_{sensor_id}"
            
        except Exception as e:
            logger.error(f"Error generating sensor name: {str(e)}")
            return f"{data_category}_unknown"
    
    def _get_snmp_value(self, ip_address: str, oid: str) -> str:
        """Get SNMP value for a specific OID."""
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(self.snmp_community),
                    UdpTransportTarget((ip_address, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
            )
            
            if error_indication or error_status:
                return None
            
            for var_bind in var_binds:
                return str(var_bind[1])
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting SNMP value for {oid}: {str(e)}")
            return None
    
    def _pattern_based_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using pattern-based approach."""
        try:
            result = {}
            patterns = self._generate_oid_patterns(data_category, device_profile)
            
            for pattern_name, oid_pattern in patterns.items():
                try:
                    value = self._get_snmp_value(ip_address, oid_pattern)
                    if value and value != 'No Such Object currently exists at this OID':
                        sensor_name = f"{data_category}_{pattern_name}"
                        result[sensor_name] = {
                            'value': value,
                            'oid': oid_pattern,
                            'type': 'pattern_discovery'
                        }
                
                except Exception as e:
                    logger.warning(f"Error in pattern discovery for {pattern_name}: {str(e)}")
                    continue
            
            return result
            
        except Exception as e:
            logger.error(f"Error in pattern-based discovery: {str(e)}")
            return {}
    
    def _generate_oid_patterns(self, data_category: str, device_profile: dict) -> dict:
        """Generate OID patterns for discovery."""
        vendor = device_profile.get('vendor', 'generic')
        
        patterns = {
            'cpu': {
                'cisco': {
                    'cpu_utilization': '1.3.6.1.4.1.9.9.109.1.1.1.1.3.1',
                    'cpu_5min': '1.3.6.1.4.1.9.9.109.1.1.1.1.4.1'
                },
                'juniper': {
                    'cpu_utilization': '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.1.1'
                },
                'generic': {
                    'cpu_utilization': '1.3.6.1.2.1.25.3.3.1.2.1'
                }
            },
            'memory': {
                'cisco': {
                    'memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.6.1',
                    'memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.5.1'
                },
                'juniper': {
                    'memory_used': '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.2.1'
                },
                'generic': {
                    'memory_used': '1.3.6.1.2.1.25.2.3.1.6.1'
                }
            },
            'temperature': {
                'cisco': {
                    'temp_current': '1.3.6.1.4.1.9.9.13.1.3.1.3.1',
                    'temp_threshold': '1.3.6.1.4.1.9.9.13.1.3.1.2.1'
                },
                'juniper': {
                    'temp_current': '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1.3.1'
                },
                'generic': {
                    'temp_current': '1.3.6.1.2.1.99.1.1.1.2.1'
                }
            }
        }
        
        return patterns.get(data_category, {}).get(vendor, {})
    
    def _mib_based_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using MIB-based approach."""
        try:
            # This is a placeholder for MIB-based discovery
            # In a real implementation, you would load MIB files and parse them
            logger.info(f"MIB-based discovery not implemented for {data_category}")
            return {}
            
        except Exception as e:
            logger.error(f"Error in MIB-based discovery: {str(e)}")
            return {}
    
    def _validate_discovered_data(self, discovered_data: dict, data_category: str) -> dict:
        """Validate discovered data."""
        try:
            validated_data = {}
            
            for sensor_name, sensor_data in discovered_data.items():
                value = sensor_data.get('value', '')
                
                # Basic validation
                if value and value != 'No Such Object currently exists at this OID':
                    try:
                        # Try to convert to float for numeric validation
                        float_value = float(value)
                        
                        # Range validation based on category
                        if data_category == 'cpu' and 0 <= float_value <= 100:
                            validated_data[sensor_name] = sensor_data
                        elif data_category == 'memory' and 0 <= float_value <= 100:
                            validated_data[sensor_name] = sensor_data
                        elif data_category == 'temperature' and -50 <= float_value <= 150:
                            validated_data[sensor_name] = sensor_data
                        else:
                            logger.warning(f"Value {value} for {sensor_name} is outside expected range")
                    
                    except ValueError:
                        # Non-numeric values might still be valid
                        validated_data[sensor_name] = sensor_data
            
            return validated_data
            
        except Exception as e:
            logger.error(f"Error validating discovered data: {str(e)}")
            return discovered_data
    
    def _learn_from_discovery(self, ip_address: str, data_category: str, discovered_data: dict, device_profile: dict):
        """Learn from discovery results for future use."""
        try:
            # Store learned OIDs for this device and category
            learned_oids = []
            
            for sensor_name, sensor_data in discovered_data.items():
                oid = sensor_data.get('oid', '')
                if oid:
                    learned_oids.append(oid)
            
            # Store in learned OIDs cache
            cache_key = f"{ip_address}_{data_category}"
            self.learned_oids[cache_key] = learned_oids
            
            logger.info(f"Learned {len(learned_oids)} OIDs for {cache_key}")
            
        except Exception as e:
            logger.error(f"Error learning from discovery: {str(e)}")
    
    def _get_learned_oids_for_category(self, ip_address: str, data_category: str) -> List[str]:
        """Get learned OIDs for a specific device and category."""
        cache_key = f"{ip_address}_{data_category}"
        return self.learned_oids.get(cache_key, []) 