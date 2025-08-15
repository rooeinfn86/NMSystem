#!/usr/bin/env python3
"""
Multi-Vendor Support System for Network Device Monitoring
Supports Cisco, Juniper, Arista, HP, Dell, Brocade, and other vendors
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class VendorProfile:
    """Vendor-specific configuration and capabilities"""
    name: str
    aliases: List[str]
    snmp_oids: Dict[str, List[str]]
    cli_commands: Dict[str, List[str]]
    parsing_patterns: Dict[str, List[str]]
    os_versions: List[str]

class MultiVendorSupport:
    """Comprehensive multi-vendor support system"""
    
    def __init__(self):
        self.vendor_profiles = self._initialize_vendor_profiles()
    
    def _initialize_vendor_profiles(self) -> Dict[str, VendorProfile]:
        """Initialize vendor profiles with comprehensive support"""
        
        profiles = {}
        
        # Cisco Systems
        profiles['cisco'] = VendorProfile(
            name='Cisco',
            aliases=['cisco', 'ios', 'ios-xe', 'nx-os', 'catos'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.9.9.13.1.3.1.2',  # Inlet temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.3',  # Hotspot temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.4',  # Yellow threshold
                    '1.3.6.1.4.1.9.9.13.1.3.1.5',  # Red threshold
                    '1.3.6.1.4.1.9.9.13.1.3.1.6',  # CPU temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.7',  # Board temperature
                ],
                'cpu': [
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.3',  # CPU utilization
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.20',  # CPU 5-minute average
                ],
                'memory': [
                    '1.3.6.1.4.1.9.9.48.1.1.1.6',  # Memory used
                    '1.3.6.1.4.1.9.9.48.1.1.1.5',  # Memory free
                    '1.3.6.1.4.1.9.9.48.1.1.1.4',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.9.9.13.1.5.1.2',  # Power consumption
                    '1.3.6.1.4.1.9.9.13.1.5.1.3',  # Power status
                ],
                'fan': [
                    '1.3.6.1.4.1.9.9.13.1.4.1.2',  # Fan speed
                    '1.3.6.1.4.1.9.9.13.1.4.1.3',  # Fan status
                ]
            },
            cli_commands={
                'temperature': [
                    'show environment temperature',
                    'show environment all',
                    'show environment',
                    'show temperature',
                ],
                'cpu': [
                    'show processes cpu',
                    'show processes cpu history',
                    'show processes cpu sorted',
                ],
                'memory': [
                    'show memory statistics',
                    'show memory summary',
                    'show memory',
                ],
                'power': [
                    'show environment power',
                    'show power',
                    'show environment all',
                ],
                'fan': [
                    'show environment fan',
                    'show fan',
                    'show environment all',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'Inlet Temperature Value:\s*(\d+)\s*Degree Celsius',
                    r'Hotspot Temperature Value:\s*(\d+)\s*Degree Celsius',
                    r'SYSTEM TEMPERATURE is (\w+)',
                    r'Yellow Threshold\s*:\s*(\d+)\s*Degree Celsius',
                    r'Red Threshold\s*:\s*(\d+)\s*Degree Celsius',
                    r'Temperature State:\s*(\w+)',
                ],
                'cpu': [
                    r'CPU utilization for five seconds:\s*(\d+)%',
                    r'CPU usage:\s*(\d+)%',
                    r'CPU utilization:\s*(\d+)%',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Processor\s+(\d+)\s+(\d+)\s+(\d+)',
                    r'Total memory:\s*(\d+)\s*Used memory:\s*(\d+)\s*Free memory:\s*(\d+)',
                ]
            },
            os_versions=['ios', 'ios-xe', 'nx-os', 'catos', 'ios-xr']
        )
        
        # Juniper Networks
        profiles['juniper'] = VendorProfile(
            name='Juniper',
            aliases=['juniper', 'junos', 'juniper-networks'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.2636.3.1.8.1.5',  # Temperature sensors
                    '1.3.6.1.4.1.2636.3.1.8.1.6',  # Temperature values
                    '1.3.6.1.4.1.2636.3.1.8.1.7',  # Temperature thresholds
                ],
                'cpu': [
                    '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.1',  # CPU utilization
                    '1.3.6.1.4.1.2636.3.1.2.1.1.1.1.2',  # CPU 5-minute average
                ],
                'memory': [
                    '1.3.6.1.4.1.2636.3.1.3.1.1.1.1.1',  # Memory used
                    '1.3.6.1.4.1.2636.3.1.3.1.1.1.1.2',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.2636.3.1.8.1.8',  # Power consumption
                    '1.3.6.1.4.1.2636.3.1.8.1.9',  # Power status
                ],
                'fan': [
                    '1.3.6.1.4.1.2636.3.1.8.1.10',  # Fan speed
                    '1.3.6.1.4.1.2636.3.1.8.1.11',  # Fan status
                ]
            },
            cli_commands={
                'temperature': [
                    'show chassis temperature',
                    'show chassis environment',
                    'show environment',
                ],
                'cpu': [
                    'show system processes cpu',
                    'show system processes extensive',
                    'show system processes',
                ],
                'memory': [
                    'show system memory',
                    'show system memory extensive',
                    'show memory',
                ],
                'power': [
                    'show chassis power',
                    'show chassis environment',
                ],
                'fan': [
                    'show chassis fan',
                    'show chassis environment',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'(\d+)\s*C\s*/\s*(\d+)\s*F',
                    r'Temperature:\s*(\d+)\s*C',
                    r'(\d+)\s*degrees C',
                ],
                'cpu': [
                    r'CPU utilization:\s*(\d+)%',
                    r'CPU usage:\s*(\d+)%',
                    r'(\d+)%\s*CPU',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Memory utilization:\s*(\d+)%',
                ]
            },
            os_versions=['junos', 'junos-evolved']
        )
        
        # Arista Networks
        profiles['arista'] = VendorProfile(
            name='Arista',
            aliases=['arista', 'eos'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.30065.3.1.1.1.1',  # Temperature sensors
                    '1.3.6.1.4.1.30065.3.1.1.1.2',  # Temperature values
                ],
                'cpu': [
                    '1.3.6.1.4.1.30065.3.1.2.1.1',  # CPU utilization
                    '1.3.6.1.4.1.30065.3.1.2.1.2',  # CPU 5-minute average
                ],
                'memory': [
                    '1.3.6.1.4.1.30065.3.1.3.1.1',  # Memory used
                    '1.3.6.1.4.1.30065.3.1.3.1.2',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.30065.3.1.4.1.1',  # Power consumption
                ],
                'fan': [
                    '1.3.6.1.4.1.30065.3.1.5.1.1',  # Fan speed
                ]
            },
            cli_commands={
                'temperature': [
                    'show environment temperature',
                    'show environment',
                    'show temperature',
                ],
                'cpu': [
                    'show processes cpu',
                    'show processes cpu sorted',
                    'show processes',
                ],
                'memory': [
                    'show memory',
                    'show memory summary',
                ],
                'power': [
                    'show environment power',
                    'show power',
                ],
                'fan': [
                    'show environment fan',
                    'show fan',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'(\d+)\s*C',
                    r'Temperature:\s*(\d+)\s*C',
                    r'(\d+)\s*degrees C',
                ],
                'cpu': [
                    r'CPU utilization:\s*(\d+)%',
                    r'(\d+)%\s*CPU',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Memory:\s*(\d+)%',
                ]
            },
            os_versions=['eos', 'eos-x']
        )
        
        # HP/Aruba Networks
        profiles['hp'] = VendorProfile(
            name='HP',
            aliases=['hp', 'hewlett-packard', 'aruba', 'procurve'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.11.2.14.11.1.2.1.1.1',  # Temperature sensors
                    '1.3.6.1.4.1.11.2.14.11.1.2.1.1.2',  # Temperature values
                ],
                'cpu': [
                    '1.3.6.1.4.1.11.2.14.11.1.2.2.1.1',  # CPU utilization
                ],
                'memory': [
                    '1.3.6.1.4.1.11.2.14.11.1.2.3.1.1',  # Memory used
                    '1.3.6.1.4.1.11.2.14.11.1.2.3.1.2',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.11.2.14.11.1.2.4.1.1',  # Power consumption
                ],
                'fan': [
                    '1.3.6.1.4.1.11.2.14.11.1.2.5.1.1',  # Fan speed
                ]
            },
            cli_commands={
                'temperature': [
                    'show environment',
                    'show temperature',
                    'show sensors',
                ],
                'cpu': [
                    'show cpu',
                    'show processes cpu',
                ],
                'memory': [
                    'show memory',
                    'show memory summary',
                ],
                'power': [
                    'show power',
                    'show environment',
                ],
                'fan': [
                    'show fan',
                    'show environment',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'(\d+)\s*C',
                    r'Temperature:\s*(\d+)\s*C',
                ],
                'cpu': [
                    r'CPU utilization:\s*(\d+)%',
                    r'(\d+)%\s*CPU',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Memory:\s*(\d+)%',
                ]
            },
            os_versions=['provision', 'arubaos', 'comware']
        )
        
        # Dell Networks
        profiles['dell'] = VendorProfile(
            name='Dell',
            aliases=['dell', 'force10', 'powerconnect'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.674.10895.3000.1.2.100.1.1.1',  # Temperature sensors
                    '1.3.6.1.4.1.674.10895.3000.1.2.100.1.1.2',  # Temperature values
                ],
                'cpu': [
                    '1.3.6.1.4.1.674.10895.3000.1.2.200.1.1.1',  # CPU utilization
                ],
                'memory': [
                    '1.3.6.1.4.1.674.10895.3000.1.2.300.1.1.1',  # Memory used
                    '1.3.6.1.4.1.674.10895.3000.1.2.300.1.1.2',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.674.10895.3000.1.2.400.1.1.1',  # Power consumption
                ],
                'fan': [
                    '1.3.6.1.4.1.674.10895.3000.1.2.500.1.1.1',  # Fan speed
                ]
            },
            cli_commands={
                'temperature': [
                    'show environment',
                    'show temperature',
                    'show sensors',
                ],
                'cpu': [
                    'show cpu',
                    'show processes cpu',
                ],
                'memory': [
                    'show memory',
                    'show memory summary',
                ],
                'power': [
                    'show power',
                    'show environment',
                ],
                'fan': [
                    'show fan',
                    'show environment',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'(\d+)\s*C',
                    r'Temperature:\s*(\d+)\s*C',
                ],
                'cpu': [
                    r'CPU utilization:\s*(\d+)%',
                    r'(\d+)%\s*CPU',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Memory:\s*(\d+)%',
                ]
            },
            os_versions=['ftos', 'dnos', 'powerconnect']
        )
        
        # Brocade Communications
        profiles['brocade'] = VendorProfile(
            name='Brocade',
            aliases=['brocade', 'foundry'],
            snmp_oids={
                'temperature': [
                    '1.3.6.1.4.1.1991.1.1.1.1.1.1',  # Temperature sensors
                    '1.3.6.1.4.1.1991.1.1.1.1.1.2',  # Temperature values
                ],
                'cpu': [
                    '1.3.6.1.4.1.1991.1.1.2.1.1.1',  # CPU utilization
                ],
                'memory': [
                    '1.3.6.1.4.1.1991.1.1.3.1.1.1',  # Memory used
                    '1.3.6.1.4.1.1991.1.1.3.1.1.2',  # Memory total
                ],
                'power': [
                    '1.3.6.1.4.1.1991.1.1.4.1.1.1',  # Power consumption
                ],
                'fan': [
                    '1.3.6.1.4.1.1991.1.1.5.1.1.1',  # Fan speed
                ]
            },
            cli_commands={
                'temperature': [
                    'show environment',
                    'show temperature',
                    'show sensors',
                ],
                'cpu': [
                    'show cpu',
                    'show processes cpu',
                ],
                'memory': [
                    'show memory',
                    'show memory summary',
                ],
                'power': [
                    'show power',
                    'show environment',
                ],
                'fan': [
                    'show fan',
                    'show environment',
                ]
            },
            parsing_patterns={
                'temperature': [
                    r'(\d+)\s*C',
                    r'Temperature:\s*(\d+)\s*C',
                ],
                'cpu': [
                    r'CPU utilization:\s*(\d+)%',
                    r'(\d+)%\s*CPU',
                ],
                'memory': [
                    r'Total:\s*(\d+)\s*Used:\s*(\d+)\s*Free:\s*(\d+)',
                    r'Memory:\s*(\d+)%',
                ]
            },
            os_versions=['fastiron', 'netiron', 'turboiron']
        )
        
        return profiles
    
    def identify_vendor(self, sys_object_id: str, sys_descr: str) -> str:
        """Identify vendor from system information"""
        sys_descr_lower = sys_descr.lower()
        sys_object_id_lower = sys_object_id.lower()
        
        for vendor_name, profile in self.vendor_profiles.items():
            # Check sysObjectID patterns
            for alias in profile.aliases:
                if alias in sys_object_id_lower:
                    return vendor_name
            
            # Check sysDescr patterns
            for alias in profile.aliases:
                if alias in sys_descr_lower:
                    return vendor_name
        
        # Check for specific patterns
        if 'cisco' in sys_descr_lower or '1.3.6.1.4.1.9.' in sys_object_id:
            return 'cisco'
        elif 'juniper' in sys_descr_lower or '1.3.6.1.4.1.2636.' in sys_object_id:
            return 'juniper'
        elif 'arista' in sys_descr_lower or '1.3.6.1.4.1.30065.' in sys_object_id:
            return 'arista'
        elif 'hp' in sys_descr_lower or 'hewlett' in sys_descr_lower or '1.3.6.1.4.1.11.' in sys_object_id:
            return 'hp'
        elif 'dell' in sys_descr_lower or '1.3.6.1.4.1.674.' in sys_object_id:
            return 'dell'
        elif 'brocade' in sys_descr_lower or '1.3.6.1.4.1.1991.' in sys_object_id:
            return 'brocade'
        
        return 'generic'
    
    def get_vendor_profile(self, vendor: str) -> Optional[VendorProfile]:
        """Get vendor profile by name"""
        return self.vendor_profiles.get(vendor.lower())
    
    def get_snmp_oids(self, vendor: str, category: str) -> List[str]:
        """Get SNMP OIDs for specific vendor and category"""
        profile = self.get_vendor_profile(vendor)
        if profile and category in profile.snmp_oids:
            return profile.snmp_oids[category]
        return []
    
    def get_cli_commands(self, vendor: str, category: str) -> List[str]:
        """Get CLI commands for specific vendor and category"""
        profile = self.get_vendor_profile(vendor)
        if profile and category in profile.cli_commands:
            return profile.cli_commands[category]
        return []
    
    def get_parsing_patterns(self, vendor: str, category: str) -> List[str]:
        """Get parsing patterns for specific vendor and category"""
        profile = self.get_vendor_profile(vendor)
        if profile and category in profile.parsing_patterns:
            return profile.parsing_patterns[category]
        return []
    
    def parse_cli_output(self, vendor: str, category: str, output: str) -> Dict:
        """Parse CLI output using vendor-specific patterns"""
        patterns = self.get_parsing_patterns(vendor, category)
        parsed_data = {}
        
        for pattern in patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if category == 'temperature':
                    parsed_data.update(self._parse_temperature_matches(matches, vendor))
                elif category == 'cpu':
                    parsed_data.update(self._parse_cpu_matches(matches, vendor))
                elif category == 'memory':
                    parsed_data.update(self._parse_memory_matches(matches, vendor))
        
        return parsed_data
    
    def _parse_temperature_matches(self, matches: List, vendor: str) -> Dict:
        """Parse temperature matches based on vendor"""
        data = {}
        
        if vendor == 'cisco':
            # Cisco specific parsing
            if len(matches) >= 2:
                data['inlet_temp'] = matches[0]
                data['hotspot_temp'] = matches[1]
            if len(matches) >= 4:
                data['threshold_yellow'] = matches[2]
                data['threshold_red'] = matches[3]
        else:
            # Generic parsing for other vendors
            if matches:
                data['system_temp'] = matches[0]
                if len(matches) > 1:
                    data['cpu_temp'] = matches[1]
        
        return data
    
    def _parse_cpu_matches(self, matches: List, vendor: str) -> Dict:
        """Parse CPU matches based on vendor"""
        data = {}
        
        if matches:
            data['cpu_usage'] = matches[0]
        
        return data
    
    def _parse_memory_matches(self, matches: List, vendor: str) -> Dict:
        """Parse memory matches based on vendor"""
        data = {}
        
        if len(matches) >= 3:
            data['memory_total'] = matches[0]
            data['memory_used'] = matches[1]
            data['memory_free'] = matches[2]
        elif len(matches) == 1:
            data['memory_usage'] = matches[0]
        
        return data
    
    def get_supported_vendors(self) -> List[str]:
        """Get list of supported vendors"""
        return list(self.vendor_profiles.keys())
    
    def get_vendor_capabilities(self, vendor: str) -> Dict:
        """Get vendor capabilities"""
        profile = self.get_vendor_profile(vendor)
        if profile:
            return {
                'name': profile.name,
                'os_versions': profile.os_versions,
                'supported_categories': list(profile.snmp_oids.keys()),
                'snmp_support': bool(profile.snmp_oids),
                'cli_support': bool(profile.cli_commands),
            }
        return {} 