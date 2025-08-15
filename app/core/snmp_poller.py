from typing import Dict, List, Optional
from pysnmp.hlapi import *

from pysnmp.proto.rfc1902 import *
import logging
import re
from datetime import datetime
from sqlalchemy.orm import Session
from app.core.database import Base
from app.models.base import Device
from app.models.base import Device as BaseDevice
from app.services.adaptive_learning import AdaptiveLearningEngine
from app.services.ssh_engine.ssh_connector import run_show_command
from app.core.enhanced_power_monitor import EnhancedPowerMonitor
import time

logger = logging.getLogger(__name__)

class SNMPPoller:
    health_cache = {}
    cache_timeout = 30  # seconds

    def __init__(self, community: str = None, version: str = "2c", 
                 username: str = None, auth_protocol: str = None, 
                 auth_password: str = None, priv_protocol: str = None, 
                 priv_password: str = None):
        self.community = community
        self.version = version
        self.username = username
        self.auth_protocol = auth_protocol
        self.auth_password = auth_password
        self.priv_protocol = priv_protocol
        self.priv_password = priv_password
        self.snmp_engine = SnmpEngine()
        self.auth_data = None
        self.target = None
        self.context_data = None
        
    def _get_snmp_engine(self):
        try:
            return SnmpEngine()
        except Exception as e:
            logger.warning(f"Error creating SNMP engine: {str(e)}")
            return None

    def _get_context_data(self) -> ContextData:
        """Get SNMP context data."""
        try:
            return ContextData()
        except Exception as e:
            logger.warning(f"Error creating context data: {str(e)}")
            return None

    def _get_target(self, ip: str) -> UdpTransportTarget:
        """Get SNMP target."""
        try:
            return UdpTransportTarget((ip, 161), timeout=2, retries=1)
        except Exception as e:
            logger.warning(f"Error creating target for {ip}: {str(e)}")
            return None

    def _get_auth_data(self) -> CommunityData:
        """Get SNMP authentication data."""
        try:
            # Try v2c first
            return CommunityData(self.community, mpModel=1)  # v2c
        except Exception as e:
            logger.warning(f"Error creating v2c auth data: {str(e)}")
            return None

    def test_connection(self, host: str) -> bool:
        """Test SNMP connection to a device."""
        try:
            logger.info(f"Testing SNMP connection to {host} with community {self.community}")
            # Try to get system description
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    self._get_snmp_engine(),
                    self._get_auth_data(),
                    self._get_target(host),
                    self._get_context_data(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
                )
            )

            if error_indication:
                logger.warning(f"SNMP connection test failed for {host}: {error_indication}")
                return False
            if error_status:
                logger.warning(f"SNMP connection test failed for {host}: {error_status}")
                return False

            logger.info(f"SNMP connection test successful for {host}")
            return True
        except Exception as e:
            logger.error(f"Error testing SNMP connection to {host}: {str(e)}")
            return False

    def get_basic_device_info(self, host: str) -> Dict:
        """Get basic device information using SNMP."""
        try:
            # OIDs for basic device info
            oids = {
                'sysDescr': '1.3.6.1.2.1.1.1.0',    # System description
                'sysObjectID': '1.3.6.1.2.1.1.2.0',  # System object ID
                'sysUpTime': '1.3.6.1.2.1.1.3.0',    # System uptime
                'sysContact': '1.3.6.1.2.1.1.4.0',   # System contact
                'sysName': '1.3.6.1.2.1.1.5.0',      # System name
                'sysLocation': '1.3.6.1.2.1.1.6.0'   # System location
            }

            results = {}
            for name, oid in oids.items():
                try:
                    # Create ObjectIdentity with the raw OID
                    obj_identity = ObjectIdentity(oid)
                    
                    error_indication, error_status, error_index, var_binds = next(
                        getCmd(
                            self._get_snmp_engine(),
                            self._get_auth_data(),
                            self._get_target(host),
                            self._get_context_data(),
                            ObjectType(obj_identity)
                        )
                    )

                    if error_indication:
                        logger.warning(f"SNMP error for {name} on {host}: {error_indication}")
                        continue

                    if error_status:
                        logger.warning(f"SNMP error for {name} on {host}: {error_status}")
                        continue

                    for var_bind in var_binds:
                        results[name] = str(var_bind[1])
                        logger.debug(f"Successfully got {name} for {host}: {results[name]}")
                except Exception as e:
                    logger.warning(f"Error getting {name} for {host}: {str(e)}")
                    continue

            return results
        except Exception as e:
            logger.error(f"Error getting basic device info for {host}: {str(e)}")
            return {}

    def _get_interface_names(self, ip: str) -> Dict[str, str]:
        """Get interface names for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface names
            if_names = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2")),  # ifDescr
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface names on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface names on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_names[if_index] = val
                                logger.debug(f"Found interface name on {ip}: {if_index} -> {val}")
                        except Exception as e:
                            logger.warning(f"Error processing interface name for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface names on {ip}: {str(e)}")

            return if_names

        except Exception as e:
            logger.error(f"Error getting interface names for {ip}: {str(e)}")
            return {}

    def _get_interface_descriptions(self, ip: str) -> Dict[str, str]:
        """Get interface descriptions for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface descriptions
            if_descriptions = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.2")),  # ifDescr
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface descriptions on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface descriptions on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_descriptions[if_index] = val
                                logger.debug(f"Found interface description on {ip}: {if_index} -> {val}")
                        except Exception as e:
                            logger.warning(f"Error processing interface description for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface descriptions on {ip}: {str(e)}")

            return if_descriptions

        except Exception as e:
            logger.error(f"Error getting interface descriptions for {ip}: {str(e)}")
            return {}

    def _get_interface_status(self, ip: str) -> Dict[str, str]:
        """Get interface status for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface status
            if_status = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.8")),  # ifOperStatus
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface status on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface status on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_status[if_index] = "up" if val == 1 else "down"
                                logger.debug(f"Found interface status on {ip}: {if_index} -> {if_status[if_index]}")
                        except Exception as e:
                            logger.warning(f"Error processing interface status for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface status on {ip}: {str(e)}")

            return if_status

        except Exception as e:
            logger.error(f"Error getting interface status for {ip}: {str(e)}")
            return {}

    def _get_interface_admin_status(self, ip: str) -> Dict[str, str]:
        """Get interface administrative status for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface administrative status
            if_admin_status = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.7")),  # ifAdminStatus
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface admin status on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface admin status on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_admin_status[if_index] = "up" if val == 1 else "down"
                                logger.debug(f"Found interface admin status on {ip}: {if_index} -> {if_admin_status[if_index]}")
                        except Exception as e:
                            logger.warning(f"Error processing interface admin status for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface admin status on {ip}: {str(e)}")

            return if_admin_status

        except Exception as e:
            logger.error(f"Error getting interface admin status for {ip}: {str(e)}")
            return {}

    def _get_interface_speeds(self, ip: str) -> Dict[str, int]:
        """Get interface speeds for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface speeds
            if_speeds = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.5")),  # ifSpeed
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface speeds on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface speeds on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                # Convert speed to Mbps (divide by 1,000,000)
                                speed_mbps = val // 1000000
                                if_speeds[if_index] = speed_mbps
                                logger.debug(f"Found interface speed on {ip}: {if_index} -> {if_speeds[if_index]} Mbps")
                        except Exception as e:
                            logger.warning(f"Error processing interface speed for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface speeds on {ip}: {str(e)}")

            return if_speeds

        except Exception as e:
            logger.error(f"Error getting interface speeds for {ip}: {str(e)}")
            return {}

    def _get_interface_macs(self, ip: str) -> Dict[str, str]:
        """Get interface MAC addresses for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface MAC addresses
            if_macs = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.6")),  # ifPhysAddress
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface MAC addresses on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface MAC addresses on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_macs[if_index] = val
                                logger.debug(f"Found interface MAC address on {ip}: {if_index} -> {if_macs[if_index]}")
                        except Exception as e:
                            logger.warning(f"Error processing interface MAC address for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface MAC addresses on {ip}: {str(e)}")

            return if_macs

        except Exception as e:
            logger.error(f"Error getting interface MAC addresses for {ip}: {str(e)}")
            return {}

    def _get_interface_ips(self, ip: str) -> Dict[str, List[str]]:
        """Get interface IP addresses for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface IP addresses - improved approach
            if_ips = {}
            try:
                # First, try ipNetToMediaTable as the primary approach (most reliable)
                logger.info(f"Trying ipNetToMediaTable as primary approach for {ip}")
                
                # First, get the list of locally configured IPs from ipAdEntTable
                local_ips = set()
                for (local_error_indication, local_error_status, local_error_index, local_var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    self._get_auth_data(),
                    self._get_target(ip),
                    self._get_context_data(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.1")),  # ipAdEntAddr
                    lexicographicMode=False
                ):
                    if local_error_indication or local_error_status:
                        break
                    for local_var_bind in local_var_binds:
                        local_name, local_val = local_var_bind
                        local_oid_str = str(local_name)
                        if local_oid_str.startswith("1.3.6.1.2.1.4.20.1.1."):
                            local_ip_part = local_oid_str.replace("1.3.6.1.2.1.4.20.1.1.", "")
                            local_parts = local_ip_part.split(".")
                            if len(local_parts) == 4:
                                local_ip = ".".join(local_parts)
                                local_ips.add(local_ip)
                                logger.info(f"Found locally configured IP: {local_ip}")
                
                logger.info(f"Locally configured IPs: {local_ips}")
                
                # Now get ipNetToMediaTable and filter for locally configured IPs only
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    self._get_auth_data(),
                    self._get_target(ip),
                    self._get_context_data(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.4.22.1.1")),  # ipNetToMediaPhysAddress
                    lexicographicMode=False
                ):
                    if error_indication or error_status:
                        break
                    for var_bind in var_binds:
                        name, val = var_bind
                        oid_str = str(name)
                        if oid_str.startswith("1.3.6.1.2.1.4.22.1.1."):
                            # Extract IP from OID: 1.3.6.1.2.1.4.22.1.1.ifIndex.IP_ADDRESS
                            ip_part = oid_str.replace("1.3.6.1.2.1.4.22.1.1.", "")
                            parts = ip_part.split(".")
                            if len(parts) >= 5:  # Should have ifIndex + 4 IP octets
                                if_index = parts[0]
                                ip_addr = ".".join(parts[1:5])
                                
                                # Only include IPs that are locally configured
                                if ip_addr in local_ips:
                                    if if_index not in if_ips:
                                        if_ips[if_index] = []
                                    if_ips[if_index].append(ip_addr)
                                    logger.info(f"ipNetToMedia: Mapped local IP {ip_addr} to interface {if_index}")
                                else:
                                    logger.debug(f"ipNetToMedia: Skipping non-local IP {ip_addr} on interface {if_index}")

                logger.info(f"ipNetToMediaTable mapping result for {ip}: {if_ips}")

                # If we still don't have mappings, try the ipAdEntTable approach as fallback
                if not if_ips:
                    logger.info(f"No mappings from ipNetToMediaTable, trying ipAdEntTable approach for {ip}")
                    
                    # Try a simpler approach: walk the entire ipAdEntTable
                    logger.info(f"Walking ipAdEntTable for {ip}")
                    for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        self._get_snmp_engine(),
                        auth_data,
                        target,
                        context_data,
                        ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.1")),  # ipAdEntAddr
                        lexicographicMode=False
                    ):
                        if error_indication:
                            logger.warning(f"SNMP error walking ipAdEntTable on {ip}: {error_indication}")
                            break
                        if error_status:
                            logger.warning(f"SNMP error walking ipAdEntTable on {ip}: {error_status}")
                            break

                        for var_bind in var_binds:
                            try:
                                name, val = var_bind
                                oid_str = str(name)
                                logger.debug(f"Processing ipAdEntTable OID: {oid_str}")
                                
                                # The OID format is: 1.3.6.1.2.1.4.20.1.1.IP_ADDRESS
                                if oid_str.startswith("1.3.6.1.2.1.4.20.1.1."):
                                    # Extract IP from OID
                                    ip_part = oid_str.replace("1.3.6.1.2.1.4.20.1.1.", "")
                                    parts = ip_part.split(".")
                                    if len(parts) == 4:
                                        ip_addr = ".".join(parts)
                                        logger.info(f"Found IP address in ipAdEntTable: {ip_addr}")
                                        
                                        # Now get the interface index for this IP
                                        try:
                                            logger.debug(f"Querying interface index for IP {ip_addr}")
                                            for (if_error_indication, if_error_status, if_error_index, if_var_binds) in nextCmd(
                                                self._get_snmp_engine(),
                                                auth_data,
                                                target,
                                                context_data,
                                                ObjectType(ObjectIdentity(f"1.3.6.1.2.1.4.20.1.2.{ip_addr}")),  # ipAdEntIfIndex
                                                lexicographicMode=False
                                            ):
                                                if if_error_indication:
                                                    logger.warning(f"Error getting interface index for IP {ip_addr}: {if_error_indication}")
                                                    break
                                                if if_error_status:
                                                    logger.warning(f"Error getting interface index for IP {ip_addr}: {if_error_status}")
                                                    break
                                                for if_var_bind in if_var_binds:
                                                    if_name, if_val = if_var_bind
                                                    logger.debug(f"Interface index response for IP {ip_addr}: {if_name} = {if_val}")
                                                    if isinstance(if_val, Integer32):
                                                        if_val = int(if_val)
                                                    if_index = str(if_val)
                                                    if if_index not in if_ips:
                                                        if_ips[if_index] = []
                                                    if_ips[if_index].append(ip_addr)
                                                    logger.info(f"Successfully mapped IP {ip_addr} to interface {if_index}")
                                                    break
                                                break
                                        except Exception as e:
                                            logger.warning(f"Error getting interface index for IP {ip_addr}: {str(e)}")
                            except Exception as e:
                                logger.warning(f"Error processing ipAdEntTable entry for {name} on {ip}: {str(e)}")
                                continue

                    logger.info(f"ipAdEntTable mapping result for {ip}: {if_ips}")

                    # If we still don't have mappings, try the original approach
                    if not if_ips:
                        logger.info(f"No mappings from ipAdEntTable, trying original approach for {ip}")
                        
                        # Get IP to interface mapping using ipAdEntIfIndex
                        ip_to_ifindex = {}
                        logger.info(f"Starting ipAdEntIfIndex query for {ip}")
                        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                            self._get_snmp_engine(),
                            auth_data,
                            target,
                            context_data,
                            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.2")),  # ipAdEntIfIndex
                            lexicographicMode=False
                        ):
                            if error_indication:
                                logger.warning(f"SNMP error getting IP to interface mapping on {ip}: {error_indication}")
                                break
                            if error_status:
                                logger.warning(f"SNMP error getting IP to interface mapping on {ip}: {error_status}")
                                break

                            for var_bind in var_binds:
                                try:
                                    name, val = var_bind
                                    if isinstance(val, Integer32):
                                        val = int(val)

                                    oid_str = str(name)
                                    logger.debug(f"Processing IP mapping OID: {oid_str} = {val}")
                                    
                                    # The OID format is: 1.3.6.1.2.1.4.20.1.2.IP_ADDRESS.ifIndex
                                    if oid_str.startswith("1.3.6.1.2.1.4.20.1.2."):
                                        # Remove the base OID part
                                        ip_part = oid_str.replace("1.3.6.1.2.1.4.20.1.2.", "")
                                        logger.debug(f"IP part after removing base OID: {ip_part}")
                                        
                                        # Split by dots to get IP address
                                        parts = ip_part.split(".")
                                        logger.debug(f"Parts after splitting: {parts}")
                                        
                                        if len(parts) == 4:  # Should have exactly 4 IP octets
                                            # The IP address is in the OID path
                                            ip_addr = ".".join(parts)
                                            # The interface index is the value
                                            if_index = str(val)
                                            ip_to_ifindex[ip_addr] = if_index
                                            logger.info(f"Found IP to interface mapping on {ip}: IP {ip_addr} -> Interface {if_index}")
                                        else:
                                            logger.warning(f"Unexpected OID format: {oid_str} with {len(parts)} parts")
                                except Exception as e:
                                    logger.warning(f"Error processing IP mapping for {name} on {ip}: {str(e)}")
                                    continue

                        logger.info(f"IP to interface mapping found for {ip}: {ip_to_ifindex}")

                        # Now get the actual IP addresses and map them to interfaces
                        logger.info(f"Starting ipAdEntAddr query for {ip}")
                        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                            self._get_snmp_engine(),
                            auth_data,
                            target,
                            context_data,
                            ObjectType(ObjectIdentity("1.3.6.1.2.1.4.20.1.1")),  # ipAdEntAddr
                            lexicographicMode=False
                        ):
                            if error_indication:
                                logger.warning(f"SNMP error getting IP addresses on {ip}: {error_indication}")
                                break
                            if error_status:
                                logger.warning(f"SNMP error getting IP addresses on {ip}: {error_status}")
                                break

                            for var_bind in var_binds:
                                try:
                                    name, val = var_bind
                                    if isinstance(val, OctetString):
                                        val = val.prettyPrint()
                                    elif isinstance(val, Integer32):
                                        val = int(val)

                                    oid_str = str(name)
                                    logger.debug(f"Processing IP address OID: {oid_str} = {val}")
                                    
                                    # The OID format is: 1.3.6.1.2.1.4.20.1.1.IP_ADDRESS
                                    if oid_str.startswith("1.3.6.1.2.1.4.20.1.1."):
                                        # Remove the base OID part
                                        ip_part = oid_str.replace("1.3.6.1.2.1.4.20.1.1.", "")
                                        logger.debug(f"IP part after removing base OID: {ip_part}")
                                        
                                        # Split by dots to get IP address
                                        parts = ip_part.split(".")
                                        logger.debug(f"Parts after splitting: {parts}")
                                        
                                        if len(parts) == 4:  # Should have exactly 4 IP octets
                                            ip_addr = ".".join(parts)
                                            logger.info(f"Found IP address on {ip}: {ip_addr}")
                                            
                                            # Map IP to interface using the mapping we got earlier
                                            if ip_addr in ip_to_ifindex:
                                                if_index = ip_to_ifindex[ip_addr]
                                                # Initialize list if not exists, then append IP
                                                if if_index not in if_ips:
                                                    if_ips[if_index] = []
                                                if_ips[if_index].append(ip_addr)
                                                logger.info(f"Mapped IP {ip_addr} to interface {if_index}")
                                            else:
                                                logger.warning(f"No interface mapping found for IP {ip_addr}")
                                        else:
                                            logger.warning(f"Unexpected IP OID format: {oid_str} with {len(parts)} parts")
                                except Exception as e:
                                    logger.warning(f"Error processing IP address for {name} on {ip}: {str(e)}")
                                    continue

            except Exception as e:
                logger.warning(f"Error walking interface IPs on {ip}: {str(e)}")

            logger.info(f"Final IP mapping for {ip}: {if_ips}")

            return if_ips

        except Exception as e:
            logger.error(f"Error getting interface IPs for {ip}: {str(e)}")
            return {}

    def _get_interface_oper_status(self, ip: str) -> Dict[str, str]:
        """Get interface operational status for a device."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return {}

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return {}

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return {}

            # Get interface operational status
            if_oper_status = {}
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.2.2.1.8")),  # ifOperStatus
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error getting interface operational status on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error getting interface operational status on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                if_index = oid_parts[-1]
                                if_oper_status[if_index] = "up" if val == 1 else "down"
                                logger.debug(f"Found interface operational status on {ip}: {if_index} -> {if_oper_status[if_index]}")
                        except Exception as e:
                            logger.warning(f"Error processing interface operational status for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking interface operational status on {ip}: {str(e)}")

            return if_oper_status

        except Exception as e:
            logger.error(f"Error getting interface operational status for {ip}: {str(e)}")
            return {}

    def get_interfaces(self, ip: str) -> List[Dict]:
        """Get interfaces for a device."""
        try:
            # Get interface names
            if_names = self._get_interface_names(ip)
            if not if_names:
                logger.warning(f"No interface names found for {ip}")
                return []

            # Get interface descriptions
            if_descriptions = self._get_interface_descriptions(ip)
            if not if_descriptions:
                logger.warning(f"No interface descriptions found for {ip}")

            # Get interface status
            if_status = self._get_interface_status(ip)
            if not if_status:
                logger.warning(f"No interface status found for {ip}")

            # Get interface administrative status
            if_admin_status = self._get_interface_admin_status(ip)
            if not if_admin_status:
                logger.warning(f"No interface administrative status found for {ip}")

            # Get interface operational status
            if_oper_status = self._get_interface_oper_status(ip)
            if not if_oper_status:
                logger.warning(f"No interface operational status found for {ip}")

            # Get interface speeds
            if_speeds = self._get_interface_speeds(ip)
            if not if_speeds:
                logger.warning(f"No interface speeds found for {ip}")

            # Get interface MAC addresses
            if_macs = self._get_interface_macs(ip)
            if not if_macs:
                logger.warning(f"No interface MAC addresses found for {ip}")

            # Get proper IP-to-interface mapping using SNMP
            if_ips = self._get_interface_ips(ip)
            logger.info(f"SNMP IP-to-interface mapping for {ip}: {if_ips}")

            # Combine all interface information
            interfaces = []
            for if_index, if_name in if_names.items():
                try:
                    # Skip interfaces that should not be shown
                    skip_interfaces = [
                        "null0", "stackport", "stacksub", "unrouted", 
                        "loopback", "tunnel", "virtual", "async", "dialer"
                    ]
                    should_skip = any(skip_name in if_name.lower() for skip_name in skip_interfaces)
                    
                    if should_skip:
                        logger.debug(f"Skipping excluded interface: {if_name}")
                        continue
                    
                    # Clean up interface name
                    if_name = if_name.replace("GigabitEthernet", "Gi")
                    if_name = if_name.replace("FastEthernet", "Fa")
                    if_name = if_name.replace("TenGigabitEthernet", "Te")
                    if_name = if_name.replace("Ethernet", "Eth")
                    if_name = if_name.replace("Loopback", "Lo")
                    if_name = if_name.replace("Vlan", "Vl")
                    if_name = if_name.replace("Port-channel", "Po")
                    if_name = if_name.replace("Tunnel", "Tu")
                    if_name = if_name.replace("Serial", "Se")
                    if_name = if_name.replace("Async", "As")
                    if_name = if_name.replace("Dialer", "Di")
                    if_name = if_name.replace("Virtual-Access", "Vi")
                    if_name = if_name.replace("Virtual-Template", "Vt")
                    if_name = if_name.replace("Virtual-PPP", "Vp")
                    if_name = if_name.replace("Virtual-TokenRing", "Vr")
                    if_name = if_name.replace("Virtual-FDDI", "Vf")
                    if_name = if_name.replace("Virtual-ATM", "Va")
                    if_name = if_name.replace("Virtual-Ethernet", "Ve")
                    if_name = if_name.replace("Virtual-FrameRelay", "Vfr")
                    if_name = if_name.replace("Virtual-ISDN", "Vi")
                    if_name = if_name.replace("Virtual-Async", "Va")
                    if_name = if_name.replace("Virtual-Dialer", "Vd")
                    if_name = if_name.replace("Virtual-Serial", "Vs")
                    if_name = if_name.replace("Virtual-Tunnel", "Vt")
                    if_name = if_name.replace("Virtual-Port-channel", "Vp")
                    if_name = if_name.replace("Virtual-Loopback", "Vl")
                    if_name = if_name.replace("Virtual-Vlan", "Vv")
                    if_name = if_name.replace("Virtual-BVI", "Vb")
                    if_name = if_name.replace("Virtual-Dot11Radio", "Vd")
                    if_name = if_name.replace("Virtual-Wlan-GigabitEthernet", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Ap", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Radio", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Slot", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Port", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Interface", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Service", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Client", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Group", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Profile", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Policy", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Security", "Vw")
                    if_name = if_name.replace("Virtual-Wlan-Qos", "Vw")

                    # Get speed in Mbps, default to None if not found or invalid
                    speed_mbps = if_speeds.get(if_index)
                    if speed_mbps is not None:
                        try:
                            speed_mbps = int(speed_mbps)
                        except (ValueError, TypeError):
                            speed_mbps = None
                    else:
                        speed_mbps = None

                    # Get MAC address, default to None if empty
                    mac = if_macs.get(if_index)
                    if mac == "" or mac is None:
                        mac = None

                    # Get IP addresses for this specific interface using SNMP mapping
                    interface_ips = []
                    if if_index in if_ips:
                        # This interface has IPs configured according to SNMP
                        interface_ips = if_ips[if_index]
                        logger.info(f"Interface {if_name} (index {if_index}) has configured IPs: {interface_ips}")
                    else:
                        # No IPs configured on this interface
                        logger.info(f"Interface {if_name} (index {if_index}) has no configured IPs")

                    interface = {
                        "ifIndex": str(if_index),  # Make sure ifIndex is a string
                        "ifDescr": if_name,  # Add ifDescr field
                        "ifAdminStatus": if_admin_status.get(if_index, "unknown"),  # Add ifAdminStatus field
                        "ifOperStatus": if_oper_status.get(if_index, "unknown"),  # Add ifOperStatus field
                        "ifSpeed": speed_mbps,  # Add ifSpeed field (in Mbps)
                        "ifPhysAddress": mac,  # Add ifPhysAddress field
                        "name": if_name,
                        "description": if_descriptions.get(if_index, ""),
                        "status": if_status.get(if_index, "unknown"),
                        "speed": speed_mbps,  # Speed in Mbps
                        "mac": mac,
                        "ip": ", ".join(interface_ips) if interface_ips else "Not configured"
                    }
                    interfaces.append(interface)
                    logger.debug(f"Added interface {if_name} (index {if_index}) for {ip} with IPs: {interface_ips}")
                except Exception as e:
                    logger.warning(f"Error processing interface {if_index} for {ip}: {str(e)}")
                    continue

            return interfaces

        except Exception as e:
            logger.error(f"Error getting interfaces for {ip}: {str(e)}")
            return []

    def discover_available_mibs(self, ip: str) -> List[str]:
        """Discover available MIBs on a device."""
        try:
            # Initialize SNMP components
            auth_data = self._get_auth_data()
            target = self._get_target(ip)
            context_data = self._get_context_data()

            # Try to walk the device MIB tree
            available_mibs = []
            for oid in [
                "1.3.6.1.2.1",  # MIB-2
                "1.3.6.1.4.1.9",  # Cisco
                "1.0.8802.1.1.2",  # LLDP
                "1.3.6.1.4.1.9.9.23"  # CDP
            ]:
                try:
                    error_indication, error_status, error_index, var_binds = next(
                        nextCmd(
                            self._get_snmp_engine(),
                            auth_data,
                            target,
                            context_data,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        )
                    )

                    if not error_indication and not error_status:
                        available_mibs.append(oid)
                        logger.info(f"Found available MIB on {ip}: {oid}")

                except Exception as e:
                    logger.warning(f"Error checking MIB {oid} on {ip}: {str(e)}")
                    continue

            return available_mibs

        except Exception as e:
            logger.error(f"Error discovering MIBs for {ip}: {str(e)}")
            return []

    def get_cdp_neighbors(self, ip: str) -> List[Dict]:
        """Get CDP neighbors for a device."""
        try:
            # First discover available MIBs
            available_mibs = self.discover_available_mibs(ip)
            logger.info(f"Available MIBs on {ip}: {available_mibs}")

            # Try different neighbor discovery methods based on available MIBs
            neighbors = []
            
            # Try CDP if available
            if "1.3.6.1.4.1.9.9.23" in available_mibs:
                try:
                    # CDP OIDs for Cisco devices
                    cdp_cache_device_id = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId
                    cdp_cache_device_port = "1.3.6.1.4.1.9.9.23.1.2.1.1.7"  # cdpCacheDevicePort
                    cdp_cache_if_index = "1.3.6.1.4.1.9.9.23.1.2.1.1.1"  # cdpCacheIfIndex
                    cdp_cache_platform = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"  # cdpCachePlatform
                    cdp_cache_capabilities = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"  # cdpCacheCapabilities
                    cdp_cache_version = "1.3.6.1.4.1.9.9.23.1.2.1.1.5"  # cdpCacheVersion
                    cdp_cache_address = "1.3.6.1.4.1.9.9.23.1.2.1.1.3"  # cdpCacheAddress

                    logger.info(f"Starting CDP neighbor discovery on {ip}")

                    # Get device IDs and ports
                    device_ids = {}
                    device_ports = {}
                    if_indices = {}
                    platforms = {}
                    capabilities = {}
                    versions = {}
                    addresses = {}

                    # Query device IDs
                    logger.info(f"Querying CDP device IDs on {ip}")
                    for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        self._get_snmp_engine(),
                        self._get_auth_data(),
                        self._get_target(ip),
                        self._get_context_data(),
                        ObjectType(ObjectIdentity(cdp_cache_device_id)),
                        lexicographicMode=False
                    ):
                        if error_indication:
                            logger.warning(f"SNMP error getting CDP device IDs on {ip}: {error_indication}")
                            break
                        if error_status:
                            logger.warning(f"SNMP error getting CDP device IDs on {ip}: {error_status}")
                            break

                        for var_bind in var_binds:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                index = oid_parts[-2]
                                device_ids[index] = val
                                logger.info(f"Found CDP device ID on {ip}: {name} = {val}")

                    # Query device ports
                    logger.info(f"Querying CDP device ports on {ip}")
                    for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        self._get_snmp_engine(),
                        self._get_auth_data(),
                        self._get_target(ip),
                        self._get_context_data(),
                        ObjectType(ObjectIdentity(cdp_cache_device_port)),
                        lexicographicMode=False
                    ):
                        if error_indication:
                            logger.warning(f"SNMP error getting CDP device ports on {ip}: {error_indication}")
                            break
                        if error_status:
                            logger.warning(f"SNMP error getting CDP device ports on {ip}: {error_status}")
                            break

                        for var_bind in var_binds:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                index = oid_parts[-2]
                                device_ports[index] = val
                                logger.info(f"Found CDP device port on {ip}: {name} = {val}")

                    # Query interface indices
                    logger.info(f"Querying CDP interface indices on {ip}")
                    for (error_indication, error_status, error_index, var_binds) in nextCmd(
                        self._get_snmp_engine(),
                        self._get_auth_data(),
                        self._get_target(ip),
                        self._get_context_data(),
                        ObjectType(ObjectIdentity(cdp_cache_if_index)),
                        lexicographicMode=False
                    ):
                        if error_indication:
                            logger.warning(f"SNMP error getting CDP interface indices on {ip}: {error_indication}")
                            break
                        if error_status:
                            logger.warning(f"SNMP error getting CDP interface indices on {ip}: {error_status}")
                            break

                        for var_bind in var_binds:
                            name, val = var_bind
                            if isinstance(val, Integer32):
                                val = int(val)
                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                index = oid_parts[-2]
                                if_indices[index] = val
                                logger.info(f"Found CDP interface index on {ip}: {name} = {val}")

                    # If we didn't get interface indices, try to get them from the device IDs
                    if not if_indices and device_ids:
                        logger.info(f"No interface indices found, trying to extract from device IDs on {ip}")
                        for index in device_ids.keys():
                            # The interface index is often the same as the device ID index
                            if_indices[index] = int(index)
                            logger.info(f"Using device ID index as interface index on {ip}: {index}")

                    # Build neighbor entries from the collected data
                    for index in device_ids.keys():
                        if index in device_ports and index in if_indices:
                            # Clean up the device ID (remove domain if present)
                            device_id = device_ids[index].split('.')[0] if '.' in device_ids[index] else device_ids[index]
                            
                            # Create a properly formatted neighbor entry
                            neighbors.append({
                                "device_id": device_id,
                                "local_port": str(if_indices[index]),
                                "remote_port": device_ports[index],
                                "platform": platforms.get(index, "Unknown"),
                                "capabilities": capabilities.get(index, "Unknown"),
                                "version": versions.get(index, "Unknown"),
                                "address": addresses.get(index, "Unknown")
                            })
                            logger.info(f"Found complete CDP neighbor on {ip}: {neighbors[-1]}")
                        else:
                            missing_keys = []
                            if index not in device_ports:
                                missing_keys.append("device_port")
                            if index not in if_indices:
                                missing_keys.append("interface_index")
                            logger.warning(f"Incomplete CDP neighbor entry on {ip}, missing keys: {missing_keys}")
                            logger.debug(f"Raw data for index {index}: device_id={device_ids.get(index)}, device_port={device_ports.get(index)}, if_index={if_indices.get(index)}")

                    if not neighbors:
                        logger.warning(f"No complete CDP neighbors found on {ip}, CDP might be disabled")

                except Exception as e:
                    logger.warning(f"Error getting CDP neighbors on {ip}: {str(e)}")

            # Try LLDP if available
            if "1.0.8802.1.1.2" in available_mibs:
                try:
                    lldp_rem_sys_name = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName
                    lldp_rem_port_desc = "1.0.8802.1.1.2.1.4.2.1.4"  # lldpRemPortDesc
                    lldp_rem_port_id = "1.0.8802.1.1.2.1.4.2.1.3"  # lldpRemPortId
                    lldp_neighbors = self._get_neighbors_lldp(ip, lldp_rem_sys_name, lldp_rem_port_desc, lldp_rem_port_id)
                    if lldp_neighbors:
                        logger.info(f"Found {len(lldp_neighbors)} LLDP neighbors on {ip}")
                        neighbors.extend(lldp_neighbors)
                    else:
                        logger.warning(f"No LLDP neighbors found on {ip}, LLDP might be disabled")
                except Exception as e:
                    logger.warning(f"Error getting LLDP neighbors on {ip}: {str(e)}")

            return neighbors

        except Exception as e:
            logger.error(f"Error getting neighbors for {ip}: {str(e)}")
            return []

    def _get_neighbors_cdp(self, ip: str, device_id_oid: str, port_oid: str, if_index_oid: str, 
                          platform_oid: str, capabilities_oid: str, version_oid: str, address_oid: str) -> List[Dict]:
        """Get neighbors using CDP MIB."""
        try:
            auth_data = self._get_auth_data()
            if not auth_data:
                logger.error(f"Failed to create auth data for {ip}")
                return []

            target = self._get_target(ip)
            if not target:
                logger.error(f"Failed to create target for {ip}")
                return []

            context_data = self._get_context_data()
            if not context_data:
                logger.error(f"Failed to create context data for {ip}")
                return []

            # First try to get the CDP cache table
            cdp_cache_table = "1.3.6.1.4.1.9.9.23.1.2.1"
            logger.debug(f"Walking CDP cache table {cdp_cache_table} on {ip}")
            
            neighbors = []
            try:
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    self._get_snmp_engine(),
                    auth_data,
                    target,
                    context_data,
                    ObjectType(ObjectIdentity(cdp_cache_table)),
                    lexicographicMode=False
                ):
                    if error_indication:
                        logger.warning(f"SNMP error walking CDP table on {ip}: {error_indication}")
                        break
                    if error_status:
                        logger.warning(f"SNMP error walking CDP table on {ip}: {error_status}")
                        break

                    for var_bind in var_binds:
                        try:
                            name, val = var_bind
                            if isinstance(val, OctetString):
                                val = val.prettyPrint()
                            elif isinstance(val, Integer32):
                                val = int(val)

                            oid_parts = str(name).split('.')
                            if len(oid_parts) >= 4:
                                index = oid_parts[-2]
                                neighbor = next((n for n in neighbors if n.get("index") == index), None)
                                if not neighbor:
                                    neighbor = {"index": index}
                                    neighbors.append(neighbor)

                                # Map OIDs to their meanings
                                oid_suffix = '.'.join(oid_parts[-2:])
                                if oid_suffix.endswith('.1'):  # cdpCacheIfIndex
                                    neighbor["cdpCacheIfIndex"] = val
                                    logger.debug(f"Found CDP interface index on {ip}: {val}")
                                elif oid_suffix.endswith('.3'):  # cdpCacheAddress
                                    neighbor["cdpCacheAddress"] = val
                                    logger.debug(f"Found CDP address on {ip}: {val}")
                                elif oid_suffix.endswith('.4'):  # cdpCacheCapabilities
                                    neighbor["cdpCacheCapabilities"] = val
                                    logger.debug(f"Found CDP capabilities on {ip}: {val}")
                                elif oid_suffix.endswith('.5'):  # cdpCacheVersion
                                    neighbor["cdpCacheVersion"] = val
                                    logger.debug(f"Found CDP version on {ip}: {val}")
                                elif oid_suffix.endswith('.6'):  # cdpCacheDeviceId
                                    neighbor["cdpCacheDeviceId"] = val
                                    logger.debug(f"Found CDP device ID on {ip}: {val}")
                                elif oid_suffix.endswith('.7'):  # cdpCacheDevicePort
                                    neighbor["cdpCacheDevicePort"] = val
                                    logger.debug(f"Found CDP port on {ip}: {val}")
                                elif oid_suffix.endswith('.8'):  # cdpCachePlatform
                                    neighbor["cdpCachePlatform"] = val
                                    logger.debug(f"Found CDP platform on {ip}: {val}")

                        except Exception as e:
                            logger.warning(f"Error processing CDP data for {name} on {ip}: {str(e)}")
                            continue

            except Exception as e:
                logger.warning(f"Error walking CDP table on {ip}: {str(e)}")

            # Filter out incomplete neighbor entries and format them
            valid_neighbors = []
            for n in neighbors:
                if all(k in n for k in ["cdpCacheDeviceId", "cdpCacheDevicePort", "cdpCacheIfIndex"]):
                    # Clean up the device ID (remove domain if present)
                    device_id = n["cdpCacheDeviceId"].split('.')[0] if '.' in n["cdpCacheDeviceId"] else n["cdpCacheDeviceId"]
                    
                    # Create a properly formatted neighbor entry
                    valid_neighbors.append({
                        "device_id": device_id,
                        "local_port": str(n["cdpCacheIfIndex"]),
                        "remote_port": n["cdpCacheDevicePort"],
                        "platform": n.get("cdpCachePlatform", "Unknown"),
                        "capabilities": n.get("cdpCacheCapabilities", "Unknown"),
                        "version": n.get("cdpCacheVersion", "Unknown"),
                        "address": n.get("cdpCacheAddress", "Unknown")
                    })
                    logger.info(f"Formatted CDP neighbor on {ip}: {valid_neighbors[-1]}")
            
            return valid_neighbors

        except Exception as e:
            logger.error(f"Error getting CDP neighbors for {ip}: {str(e)}")
            return []

    def _get_neighbors_lldp(self, ip: str, sys_name_oid: str, port_desc_oid: str, port_id_oid: str) -> List[Dict]:
        """Get neighbors using LLDP MIB."""
        try:
            auth_data = self._get_auth_data()
            target = self._get_target(ip)
            context_data = self._get_context_data()

            neighbors = []
            for oid in [sys_name_oid, port_desc_oid, port_id_oid]:
                try:
                    error_indication, error_status, error_index, var_binds = next(
                        nextCmd(
                            self._get_snmp_engine(),
                            auth_data,
                            target,
                            context_data,
                            ObjectType(ObjectIdentity(oid)),
                            lexicographicMode=False
                        )
                    )

                    if error_indication or error_status:
                        continue

                    for var_bind in var_binds:
                        name, val = var_bind
                        if isinstance(val, OctetString):
                            val = val.prettyPrint()
                        elif isinstance(val, Integer32):
                            val = int(val)

                        oid_parts = str(name).split('.')
                        if len(oid_parts) >= 4:
                            index = oid_parts[-2]
                            neighbor = next((n for n in neighbors if n.get("index") == index), None)
                            if not neighbor:
                                neighbor = {"index": index}
                                neighbors.append(neighbor)

                            if oid == sys_name_oid:
                                neighbor["cdpCacheDeviceId"] = val
                            elif oid == port_desc_oid:
                                neighbor["cdpCacheDevicePort"] = val
                            elif oid == port_id_oid:
                                neighbor["cdpCacheIfIndex"] = val

                except Exception as e:
                    logger.warning(f"Error getting LLDP neighbor info for {oid} on {ip}: {str(e)}")
                    continue

            return [n for n in neighbors if all(k in n for k in ["cdpCacheDeviceId", "cdpCacheDevicePort", "cdpCacheIfIndex"])]

        except Exception as e:
            logger.error(f"Error getting LLDP neighbors for {ip}: {str(e)}")
            return []

    def get_device_health(self, host: str, db_session: Session = None, device_id: int = None) -> Dict:
        """Get comprehensive device health information using smart discovery with fast-path optimization and fallback."""
        try:
            logger.info(f"Getting device health for {host}")
            
            # Clean up expired cache entries periodically
            if len(SNMPPoller.health_cache) > 10:  # Only cleanup if cache has many entries
                self.cleanup_expired_cache()
            
            # Check cache first
            current_time = time.time()
            if host in SNMPPoller.health_cache:
                cache_entry = SNMPPoller.health_cache[host]
                if current_time - cache_entry['timestamp'] < SNMPPoller.cache_timeout:
                    logger.info(f"Using cached health data for {host} (age: {current_time - cache_entry['timestamp']:.1f}s)")
                    return cache_entry['data']
                else:
                    # Cache expired, remove it
                    del SNMPPoller.health_cache[host]
            
            # Initialize smart discovery
            smart_discovery = SmartSNMPDiscovery("cisco", db_session)
            self.smart_discovery = smart_discovery
            
            # Try fast-path first (using learned OIDs)
            fast_health = self._get_health_fast_path(host, smart_discovery, device_id)
            needs_fallback = False
            # Check if any main category is missing or empty
            if fast_health:
                if (
                    not fast_health.get('cpu_details') or not fast_health['cpu_details']
                    or not fast_health.get('memory_details') or not fast_health['memory_details']
                    or not fast_health.get('temperature_details') or not fast_health['temperature_details']
                ):
                    needs_fallback = True
                # Check if we have enough memory values for proper calculation
                elif fast_health.get('memory_details') and len(fast_health['memory_details']) < 3:
                    # If we have less than 3 memory values, we might not have enough for proper calculation
                    # Check if the calculated memory values are all 0 (indicating insufficient data)
                    if (fast_health.get('memory_used_gb', 0) == 0 and 
                        fast_health.get('memory_free_gb', 0) == 0 and 
                        fast_health.get('memory_total_gb', 0) == 0):
                        logger.info(f"Fast-path found insufficient memory data for {host}, falling back to full discovery")
                        needs_fallback = True
                # Also check for new categories
                if (
                    'power_details' in fast_health and not fast_health['power_details']
                ) or (
                    'fan_details' in fast_health and not fast_health['fan_details']
                ):
                    needs_fallback = True
            else:
                needs_fallback = True
            
            if not needs_fallback:
                logger.info(f"Fast-path health check successful for {host}")
                SNMPPoller.health_cache[host] = {
                    'data': fast_health,
                    'timestamp': current_time,
                    'method': 'fast_path'
                }
                return fast_health
            
            logger.info(f"Fast-path incomplete for {host}, using full discovery fallback")
            # Do full discovery for missing categories
            full_health = self._get_health_full_discovery(host, smart_discovery, device_id)
            # Merge: prefer full discovery for missing/empty categories
            merged = fast_health or {}
            for key in ['cpu_details', 'memory_details', 'temperature_details', 'power_details', 'fan_details',
                        'cpu_usage', 'memory_usage', 'temperature', 'power_consumption', 'fan_speed']:
                if not merged.get(key):
                    merged[key] = full_health.get(key)
            # Also update the main values if they are 0 or missing
            for key in ['cpu_usage', 'memory_usage', 'temperature', 'power_consumption', 'fan_speed']:
                if not merged.get(key) or merged[key] == 0:
                    merged[key] = full_health.get(key)
            # CRITICAL FIX: Always use full discovery for memory GB values
            for key in ['memory_used_gb', 'memory_free_gb', 'memory_total_gb']:
                merged[key] = full_health.get(key, 0)
            SNMPPoller.health_cache[host] = {
                'data': merged,
                'timestamp': current_time,
                'method': 'fallback_full_discovery'
            }
            return merged
        except Exception as e:
            logger.error(f"Error getting device health for {host}: {e}")
            return {
                'cpu_usage': '0%',
                'memory_usage': '0%',
                'temperature': '0°C',
                'cpu_details': {},
                'memory_details': {},
                'temperature_details': {},
                'power_details': {},
                'fan_details': {},
                'status': 'error',
                'error': str(e)
            }
    
    def _get_health_fast_path(self, host: str, smart_discovery: 'SmartSNMPDiscovery', device_id: int = None) -> Dict:
        """Fast-path health check using learned OIDs"""
        try:
            logger.info(f"Attempting fast-path health check for {host}")
            
            # Get device profile for vendor/model info
            device_profile = smart_discovery._get_device_profile(host)
            logger.info(f"Device profile: {device_profile.get('vendor')} {device_profile.get('model')}")
            
            # Get learned OIDs from smart discovery first
            cpu_oids = smart_discovery._get_learned_oids_for_category(host, 'cpu')
            memory_oids = smart_discovery._get_learned_oids_for_category(host, 'memory')
            temperature_oids = smart_discovery._get_learned_oids_for_category(host, 'temperature')
            power_oids = smart_discovery._get_learned_oids_for_category(host, 'power')
            fan_oids = smart_discovery._get_learned_oids_for_category(host, 'fan')
            
            # Also try to get from learning engine if available
            if smart_discovery.learning_engine:
                try:
                    predicted_cpu_oids = smart_discovery.learning_engine.predict_successful_oids(device_profile, 'cpu')
                    predicted_memory_oids = smart_discovery.learning_engine.predict_successful_oids(device_profile, 'memory')
                    predicted_temp_oids = smart_discovery.learning_engine.predict_successful_oids(device_profile, 'temperature')
                    predicted_power_oids = smart_discovery.learning_engine.predict_successful_oids(device_profile, 'power')
                    predicted_fan_oids = smart_discovery.learning_engine.predict_successful_oids(device_profile, 'fan')
                    
                    # Combine learned and predicted OIDs
                    cpu_oids.extend(predicted_cpu_oids)
                    memory_oids.extend(predicted_memory_oids)
                    temperature_oids.extend(predicted_temp_oids)
                    power_oids.extend(predicted_power_oids)
                    fan_oids.extend(predicted_fan_oids)
                except Exception as e:
                    logger.warning(f"Learning engine prediction failed: {e}")
            
            logger.info(f"Smart discovery learned OIDs - CPU: {len(cpu_oids)}, Memory: {len(memory_oids)}, Temperature: {len(temperature_oids)}, Power: {len(power_oids)}, Fan: {len(fan_oids)}")
            
            # Perform fast SNMP gets for each category
            cpu_data = self._fast_snmp_get(host, cpu_oids, 'cpu')
            memory_data = self._fast_snmp_get(host, memory_oids, 'memory')
            
            # Use enhanced temperature monitoring for better accuracy
            temp_monitor = EnhancedTemperatureMonitor(self, smart_discovery.db_session)
            temperature_data = temp_monitor.get_temperature_data(host, device_id)
            
            # Use enhanced power monitoring for PSU information
            power_monitor = EnhancedPowerMonitor(self, smart_discovery.db_session)
            power_data = power_monitor.get_power_data(host, device_id)
            fan_data = self._fast_snmp_get(host, fan_oids, 'fan')
            
            logger.info(f"Fast-path results - CPU: {len(cpu_data)}, Memory: {len(memory_data)}, Temperature: {len(temperature_data)}, Power: {len(power_data)}, Fan: {len(fan_data)}")
            
            # Process the data
            health_data = self._process_health_data(cpu_data, memory_data, temperature_data, power_data, fan_data)
            
            logger.info(f"Fast-path health check completed for {host}")
            return health_data
            
        except Exception as e:
            logger.error(f"Error in fast-path health check for {host}: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'temperature': 0,
                'power_consumption': 0,
                'fan_speed': 0,
                'cpu_details': {},
                'memory_details': {},
                'temperature_details': {},
                'power_details': {},
                'fan_details': {}
            }
    
    def _fast_snmp_get(self, host: str, sensor_names: List[str], data_category: str) -> Dict:
        """Perform fast SNMP gets using stored sensor mappings"""
        try:
            discovered_data = {}
            
            # Get stored mappings for this host and category (using class-level storage)
            mapping_key = f"{host}_{data_category}"
            if mapping_key in SmartSNMPDiscovery.oid_mappings:
                stored_mappings = SmartSNMPDiscovery.oid_mappings[mapping_key]
                
                # If we have stored mappings, use them directly for fast-path
                # This avoids the need to query sensor_names that might not exist
                for sensor_name, mapping_data in stored_mappings.items():
                    discovered_data[sensor_name] = mapping_data['value']
                    logger.debug(f"Fast-path using stored value for {sensor_name}")
                
                logger.info(f"Fast-path retrieved {len(discovered_data)} {data_category} values from stored mappings")
            else:
                logger.warning(f"No stored mappings found for {host}_{data_category}")
            
            return discovered_data
            
        except Exception as e:
            logger.error(f"Error in fast SNMP get for {host}: {e}")
            return {}
    
    def _get_health_full_discovery(self, host: str, smart_discovery: 'SmartSNMPDiscovery', device_id: int = None) -> Dict:
        """Full health discovery using smart SNMP discovery with enhanced temperature monitoring"""
        try:
            logger.info(f"Performing full health discovery for {host}")
            
            # Discover all health data categories
            cpu_data = smart_discovery.discover_data(host, "cpu")
            memory_data = smart_discovery.discover_data(host, "memory")
            
            # Use enhanced temperature monitoring with SSH fallback
            temp_monitor = EnhancedTemperatureMonitor(self, smart_discovery.db_session)
            temperature_data = temp_monitor.get_temperature_data(host, device_id)
            
            # Use enhanced power monitoring for PSU information
            power_monitor = EnhancedPowerMonitor(self, smart_discovery.db_session)
            power_data = power_monitor.get_power_data(host, device_id)
            fan_data = smart_discovery.discover_data(host, "fan")
            
            # Learn from discoveries
            device_profile = smart_discovery._get_device_profile(host)
            smart_discovery._learn_from_discovery(host, "cpu", cpu_data, device_profile)
            smart_discovery._learn_from_discovery(host, "memory", memory_data, device_profile)
            smart_discovery._learn_from_discovery(host, "temperature", temperature_data, device_profile)
            smart_discovery._learn_from_discovery(host, "power", power_data, device_profile)
            smart_discovery._learn_from_discovery(host, "fan", fan_data, device_profile)
            
            # Process all health data
            health_data = self._process_health_data(cpu_data, memory_data, temperature_data, power_data, fan_data)
            
            logger.info(f"Full discovery completed for {host}")
            return health_data
            
        except Exception as e:
            logger.error(f"Error in full health discovery for {host}: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'temperature': 0,
                'power_consumption': 0,
                'fan_speed': 0,
                'cpu_details': {},
                'memory_details': {},
                'temperature_details': {},
                'power_details': {},
                'fan_details': {}
            }
    
    def _process_health_data(self, cpu_data: Dict, memory_data: Dict, temperature_data: Dict, 
                           power_data: Dict = None, fan_data: Dict = None) -> Dict:
        """Process and extract best health metrics from discovered data"""
        try:
            def safe_cpu_compare(cpu_value):
                try:
                    if isinstance(cpu_value, str):
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', cpu_value)
                        return float(match.group(1)) if match else 0
                    return float(cpu_value)
                except:
                    return 0

            def safe_memory_compare(memory_value):
                try:
                    if isinstance(memory_value, str):
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', memory_value)
                        return float(match.group(1)) if match else 0
                    return float(memory_value)
                except:
                    return 0

            def safe_temp_compare(temp_value):
                try:
                    if isinstance(temp_value, str):
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', temp_value)
                        return float(match.group(1)) if match else 0
                    return float(temp_value)
                except:
                    return 0

            def safe_power_compare(power_value):
                try:
                    if isinstance(power_value, str):
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', power_value)
                        return float(match.group(1)) if match else 0
                    return float(power_value)
                except:
                    return 0

            def safe_fan_compare(fan_value):
                try:
                    if isinstance(fan_value, str):
                        import re
                        match = re.search(r'(\d+(?:\.\d+)?)', fan_value)
                        return float(match.group(1)) if match else 0
                    return float(fan_value)
                except:
                    return 0

            # Process CPU data
            best_cpu = 0
            if cpu_data:
                cpu_values = [safe_cpu_compare(val) for val in cpu_data.values()]
                best_cpu = max(cpu_values) if cpu_values else 0

            # Process memory data with enhanced logic
            best_memory_percent = 0
            memory_used_gb = 0
            memory_free_gb = 0
            memory_total_gb = 0
            
            if memory_data:
                # Extract memory values and categorize them
                memory_percentages = []
                memory_raw_values = {}  # Store raw values for calculation
                
                for memory_name, memory_value in memory_data.items():
                    try:
                        raw_value = safe_memory_compare(memory_value)
                        
                        # Categorize based on sensor name and value range
                        memory_name_lower = memory_name.lower()
                        
                        # Check if it's a percentage - ONLY if:
                        # 1. Value is between 0-100 AND string contains '%' or name contains 'percent', OR
                        # 2. String contains '%' (regardless of value), OR  
                        # 3. Name contains 'percent' (regardless of value)
                        # This prevents large raw values from being treated as percentages
                        if ('%' in str(memory_value)) or ('percent' in memory_name_lower) or ((0 <= raw_value <= 100) and ('%' in str(memory_value) or 'percent' in memory_name_lower)):
                            memory_percentages.append(raw_value)
                            logger.info(f"Found memory percentage: {memory_name} = {raw_value}%")
                        elif raw_value > 1000:
                            # Store raw values for calculation - enhanced logic for Cisco memory pools
                            if 'used' in memory_name_lower or 'cisco_memory_6' in memory_name_lower or 'cisco_memory_used' in memory_name_lower:
                                memory_raw_values['used'] = raw_value
                                logger.info(f"Found used memory: {memory_name} = {raw_value}")
                            elif 'free' in memory_name_lower or 'cisco_memory_5' in memory_name_lower or 'cisco_memory_free' in memory_name_lower:
                                memory_raw_values['free'] = raw_value
                                logger.info(f"Found free memory: {memory_name} = {raw_value}")
                            elif 'total' in memory_name_lower or 'cisco_memory_4' in memory_name_lower or 'cisco_memory_total' in memory_name_lower:
                                memory_raw_values['total'] = raw_value
                                logger.info(f"Found total memory: {memory_name} = {raw_value}")
                            elif 'available' in memory_name_lower or 'cisco_memory_7' in memory_name_lower or 'cisco_memory_util' in memory_name_lower:
                                memory_raw_values['available'] = raw_value
                                logger.info(f"Found available memory: {memory_name} = {raw_value}")
                            else:
                                # Store by OID pattern for later analysis
                                memory_raw_values[memory_name] = raw_value
                                logger.info(f"Found memory value: {memory_name} = {raw_value}")
                        else:
                            # Store as raw value (small, but not a percentage)
                            memory_raw_values[memory_name] = raw_value
                            logger.info(f"Found small memory value: {memory_name} = {raw_value}")
                            
                    except Exception as e:
                        logger.debug(f"Error processing memory value {memory_value}: {e}")
                        continue
                
                # Enhanced logic: Look for realistic memory values (KB values in reasonable range)
                # Real memory values should be in the range of 1-10 million KB (1-10 GB)
                realistic_memory_values = {}
                system_memory_values = {}  # Prioritize larger values that represent system memory
                
                for name, value in memory_raw_values.items():
                    # Filter out unreasonably large values (> 50 million KB = ~50 GB)
                    # and focus on realistic values (1-50 million KB)
                    if 1000 <= value <= 50000000:  # 1MB to 50GB in KB
                        realistic_memory_values[name] = value
                        logger.info(f"Found realistic memory value: {name} = {value} KB")
                    # Also check for values that might be in bytes (much larger numbers)
                    elif 1000000 <= value <= 50000000000:  # 1MB to 50GB in bytes
                        # Convert bytes to KB for consistency
                        value_kb = value / 1024
                        realistic_memory_values[name] = value_kb
                        logger.info(f"Found memory value in bytes, converted to KB: {name} = {value} bytes = {value_kb} KB")
                    # Handle very large values that are clearly in bytes (like 580825424)
                    elif value > 50000000000:  # Values > 50GB in bytes
                        # Convert bytes to KB for consistency
                        value_kb = value / 1024
                        realistic_memory_values[name] = value_kb
                        logger.info(f"Found large memory value in bytes, converted to KB: {name} = {value} bytes = {value_kb} KB")
                
                # Prioritize larger memory values that are more likely to be system memory
                # System memory is typically larger than processor memory
                if realistic_memory_values:
                    sorted_by_size = sorted(realistic_memory_values.items(), key=lambda x: x[1], reverse=True)
                    logger.info(f"Memory values sorted by size: {sorted_by_size}")
                    
                    # Look for specific system memory OIDs that should match CLI output
                    # Cisco system memory OIDs: 1.3.6.1.4.1.9.9.48.1.1.1.x
                    system_memory_oids = []
                    processor_memory_oids = []
                    
                    for name, value in realistic_memory_values.items():
                        # Prioritize system memory over processor memory
                        if 'cisco_system_memory_' in name:
                            system_memory_oids.append((name, value))
                            logger.info(f"Found explicit system memory OID: {name} = {value} KB")
                        elif 'cisco_memory_' in name and any(x in name for x in ['4', '5', '6', '7', '8']):
                            # Check if this is processor memory (pool 1) or system memory (other pools)
                            if '_1' in name and 'name' in name:
                                # This is the memory pool name - check if it's "Processor"
                                logger.info(f"Found memory pool name OID: {name} = {value}")
                            elif '_1' in name:
                                # Pool 1 might be processor memory
                                processor_memory_oids.append((name, value))
                                logger.info(f"Found potential processor memory OID: {name} = {value} KB")
                            else:
                                # Other pools might be system memory
                                system_memory_oids.append((name, value))
                                logger.info(f"Found potential system memory OID: {name} = {value} KB")
                    
                    # If we found system memory OIDs, prioritize them
                    if system_memory_oids:
                        for name, value in system_memory_oids:
                            system_memory_values[name] = value
                        logger.info(f"Prioritized system memory OIDs: {system_memory_oids}")
                    elif processor_memory_oids:
                        # If no system memory found, use processor memory but log it
                        for name, value in processor_memory_oids:
                            system_memory_values[name] = value
                        logger.info(f"Using processor memory OIDs (no system memory found): {processor_memory_oids}")
                    else:
                        # If we have multiple memory pools, prioritize the largest ones as system memory
                        if len(sorted_by_size) >= 2:
                            # Take the largest values as potential system memory
                            largest_values = sorted_by_size[:3]  # Top 3 largest values
                            for name, value in largest_values:
                                system_memory_values[name] = value
                                logger.info(f"Prioritized as system memory (by size): {name} = {value} KB")
                        else:
                            # Only one value found, use it
                            system_memory_values = realistic_memory_values
                
                # If we found realistic values, try to categorize them by OID pattern
                if system_memory_values:
                    logger.info(f"Found system memory values: {system_memory_values}")
                    
                    # Sort by value size to identify total, used, free
                    sorted_values = sorted(system_memory_values.items(), key=lambda x: x[1], reverse=True)
                    
                    # If we have multiple values, try to identify them properly
                    if len(sorted_values) >= 2:
                        # Assume the largest value is total memory
                        largest_name, largest_value = sorted_values[0]
                        memory_raw_values['total'] = largest_value
                        logger.info(f"Identified system total memory: {largest_name} = {largest_value} KB")
                        
                        # Look for used and free values in system memory pool
                        for name, value in system_memory_values.items():
                            if 'used' in name.lower() or '6' in name or 'used' in name:  # Cisco used memory OID ends with .6
                                # Convert to KB if the value is in bytes
                                if value > 1000000:  # Likely in bytes
                                    value_kb = value / 1024
                                    memory_raw_values['used'] = value_kb
                                    logger.info(f"Identified system used memory: {name} = {value} bytes = {value_kb} KB")
                                else:
                                    memory_raw_values['used'] = value
                                    logger.info(f"Identified system used memory: {name} = {value} KB")
                            elif 'free' in name.lower() or '5' in name or 'free' in name:  # Cisco free memory OID ends with .5
                                # Convert to KB if the value is in bytes
                                if value > 1000000:  # Likely in bytes
                                    value_kb = value / 1024
                                    memory_raw_values['free'] = value_kb
                                    logger.info(f"Identified system free memory: {name} = {value} bytes = {value_kb} KB")
                                else:
                                    memory_raw_values['free'] = value
                                    logger.info(f"Identified system free memory: {name} = {value} KB")
                        
                        # Calculate total memory as sum of used + free if we have both
                        used_kb = memory_raw_values.get('used', 0)
                        free_kb = memory_raw_values.get('free', 0)
                        if used_kb > 0 and free_kb > 0:
                            # Ensure both values are in the same unit (KB)
                            if used_kb > 1000000:  # Likely in bytes, convert to KB
                                used_kb = used_kb / 1024
                            if free_kb > 1000000:  # Likely in bytes, convert to KB
                                free_kb = free_kb / 1024
                            
                            total_kb = used_kb + free_kb
                            memory_raw_values['total'] = total_kb
                            memory_raw_values['used'] = used_kb
                            memory_raw_values['free'] = free_kb
                            logger.info(f"Calculated system total memory: {total_kb} KB (used: {used_kb} + free: {free_kb})")
                    elif len(sorted_values) == 1:
                        # Only one value found - this might be total memory
                        largest_name, largest_value = sorted_values[0]
                        memory_raw_values['total'] = largest_value
                        logger.info(f"Found single system memory value (assuming total): {largest_name} = {largest_value} KB")
                elif realistic_memory_values:
                    # Fallback to realistic memory values if no system memory found
                    logger.info(f"Using fallback realistic memory values: {realistic_memory_values}")
                    
                    # Sort by value size to identify total, used, free
                    sorted_values = sorted(realistic_memory_values.items(), key=lambda x: x[1], reverse=True)
                    
                    # If we have multiple values, try to identify them properly
                    if len(sorted_values) >= 2:
                        # Assume the largest value is total memory
                        largest_name, largest_value = sorted_values[0]
                        memory_raw_values['total'] = largest_value
                        logger.info(f"Identified total memory (fallback): {largest_name} = {largest_value} KB")
                        
                        # Look for used and free values
                        for name, value in realistic_memory_values.items():
                            if 'used' in name.lower() or '6' in name or 'used' in name:  # Cisco used memory OID ends with .6
                                memory_raw_values['used'] = value
                                logger.info(f"Identified used memory (fallback): {name} = {value} KB")
                            elif 'free' in name.lower() or '5' in name or 'free' in name:  # Cisco free memory OID ends with .5
                                memory_raw_values['free'] = value
                                logger.info(f"Identified free memory (fallback): {name} = {value} KB")
                        
                        # Calculate total memory as sum of used + free if we have both
                        used_kb = memory_raw_values.get('used', 0)
                        free_kb = memory_raw_values.get('free', 0)
                        if used_kb > 0 and free_kb > 0:
                            # Ensure both values are in the same unit (KB)
                            if used_kb > 1000000:  # Likely in bytes, convert to KB
                                used_kb = used_kb / 1024
                            if free_kb > 1000000:  # Likely in bytes, convert to KB
                                free_kb = free_kb / 1024
                            
                            total_kb = used_kb + free_kb
                            memory_raw_values['total'] = total_kb
                            memory_raw_values['used'] = used_kb
                            memory_raw_values['free'] = free_kb
                            logger.info(f"Calculated total memory (fallback): {total_kb} KB (used: {used_kb} + free: {free_kb})")
                    elif len(sorted_values) == 1:
                        # Only one value found - this might be total memory
                        largest_name, largest_value = sorted_values[0]
                        memory_raw_values['total'] = largest_value
                        logger.info(f"Found single memory value (fallback, assuming total): {largest_name} = {largest_value} KB")
                else:
                    logger.warning("No realistic memory values found. All values may be percentages or invalid.")
                
                # Calculate best memory percentage (only from actual percentage values)
                if memory_percentages:
                    best_memory_percent = max(memory_percentages)
                    logger.info(f"Best memory percentage: {best_memory_percent}%")
                else:
                    # If no percentage found, calculate from raw values
                    used_kb = memory_raw_values.get('used', 0)
                    total_kb = memory_raw_values.get('total', 0)
                    if used_kb > 0 and total_kb > 0:
                        best_memory_percent = round((used_kb / total_kb) * 100, 1)
                        logger.info(f"Calculated memory percentage from raw values: {best_memory_percent}%")
                    else:
                        best_memory_percent = 0
                
                # Calculate memory values in GB
                # Try to find used/free/total values
                used_kb = memory_raw_values.get('used', 0)
                free_kb = memory_raw_values.get('free', 0)
                total_kb = memory_raw_values.get('total', 0)
                available_kb = memory_raw_values.get('available', 0)
                
                # If we have total but no used/free, try to calculate
                if total_kb > 0:
                    if used_kb == 0 and free_kb > 0:
                        used_kb = total_kb - free_kb
                    elif free_kb == 0 and used_kb > 0:
                        free_kb = total_kb - used_kb
                    elif used_kb == 0 and free_kb == 0 and available_kb > 0:
                        used_kb = total_kb - available_kb
                        free_kb = available_kb
                
                # If we still don't have values, try to infer from system memory data first
                if used_kb == 0 and free_kb == 0 and total_kb == 0:
                    # Look for the largest system memory values that could be memory
                    if system_memory_values:
                        sorted_values = sorted(system_memory_values.items(), key=lambda x: x[1], reverse=True)
                        if len(sorted_values) >= 2:
                            # Assume the largest value is total, second largest is used
                            total_kb = sorted_values[0][1]
                            used_kb = sorted_values[1][1]
                            free_kb = total_kb - used_kb
                            logger.info(f"Inferred system memory values - Total: {total_kb}KB, Used: {used_kb}KB, Free: {free_kb}KB")
                    # Fallback to realistic memory values if no system memory
                    elif realistic_memory_values:
                        sorted_values = sorted(realistic_memory_values.items(), key=lambda x: x[1], reverse=True)
                        if len(sorted_values) >= 2:
                            # Assume the largest value is total, second largest is used
                            total_kb = sorted_values[0][1]
                            used_kb = sorted_values[1][1]
                            free_kb = total_kb - used_kb
                            logger.info(f"Inferred memory values (fallback) - Total: {total_kb}KB, Used: {used_kb}KB, Free: {free_kb}KB")
                
                # Convert KB to GB - simplified calculation
                if used_kb > 0:
                    memory_used_gb = round(used_kb / (1024 * 1024), 2)
                if free_kb > 0:
                    memory_free_gb = round(free_kb / (1024 * 1024), 2)
                if total_kb > 0:
                    memory_total_gb = round(total_kb / (1024 * 1024), 2)
                
                # Debug logging for variable assignment
                logger.info(f"Variable assignment - used_kb: {used_kb}, free_kb: {free_kb}, total_kb: {total_kb}")
                logger.info(f"Variable assignment - memory_used_gb: {memory_used_gb}, memory_free_gb: {memory_free_gb}, memory_total_gb: {memory_total_gb}")
                
                # Log the actual calculated values
                if used_kb > 0 or free_kb > 0 or total_kb > 0:
                    logger.info(f"Actual calculated values - memory_used_gb: {memory_used_gb}, memory_free_gb: {memory_free_gb}, memory_total_gb: {memory_total_gb}")
                
                # If we have percentage but no GB values, try to estimate
                if best_memory_percent > 0 and memory_total_gb == 0:
                    # Look for any realistic value that could be total memory
                    realistic_values = [v for v in realistic_memory_values.values() if 1000000 <= v <= 10000000]  # 1-10GB in KB
                    if realistic_values:
                        estimated_total_kb = max(realistic_values)
                        memory_total_gb = round(estimated_total_kb / (1024 * 1024), 2)
                        memory_used_gb = round((best_memory_percent / 100) * memory_total_gb, 2)
                        memory_free_gb = round(memory_total_gb - memory_used_gb, 2)
                        logger.info(f"Estimated memory from percentage - Total: {memory_total_gb}GB, Used: {memory_used_gb}GB, Free: {memory_free_gb}GB")
                
                logger.info(f"Memory calculation - Used: {memory_used_gb}GB, Free: {memory_free_gb}GB, Total: {memory_total_gb}GB, Percent: {best_memory_percent}%")
                logger.info(f"Raw memory values: {memory_raw_values}")
                logger.info(f"Realistic memory values: {realistic_memory_values}")
                
                # Ensure variables are properly assigned to outer scope
                logger.info(f"Final memory variables - memory_used_gb: {memory_used_gb}, memory_free_gb: {memory_free_gb}, memory_total_gb: {memory_total_gb}")

            # Process temperature data
            best_temperature = 0
            if temperature_data:
                temp_values = [safe_temp_compare(val) for val in temperature_data.values()]
                best_temperature = max(temp_values) if temp_values else 0

            # Process power data
            best_power = 0
            if power_data:
                power_values = [safe_power_compare(val) for val in power_data.values()]
                best_power = max(power_values) if power_values else 0

            # Process fan data
            best_fan = 0
            if fan_data:
                fan_values = [safe_fan_compare(val) for val in fan_data.values()]
                best_fan = max(fan_values) if fan_values else 0

            logger.info(f"Health data: CPU={best_cpu:.1f}%, Memory={best_memory_percent:.1f}%, Temperature={best_temperature:.1f}°C, Power={best_power:.1f}W, Fan={best_fan:.1f}RPM")
            logger.info(f"CPU details: {cpu_data}")
            logger.info(f"Memory details: {memory_data}")
            logger.info(f"Temperature details: {temperature_data}")
            logger.info(f"Power details: {power_data}")
            logger.info(f"Fan details: {fan_data}")
            
            # Debug logging for return values
            logger.info(f"Returning memory values - memory_used_gb: {memory_used_gb}, memory_free_gb: {memory_free_gb}, memory_total_gb: {memory_total_gb}")
            
            # Create the return dictionary
            return_dict = {
                'cpu_usage': best_cpu,
                'memory_usage': best_memory_percent,
                'memory_used_gb': memory_used_gb,
                'memory_free_gb': memory_free_gb,
                'memory_total_gb': memory_total_gb,
                'temperature': best_temperature,
                'power_consumption': best_power,
                'fan_speed': best_fan,
                'cpu_details': cpu_data,
                'memory_details': memory_data,
                'temperature_details': temperature_data,
                'power_details': power_data or {},
                'fan_details': fan_data or {}
            }
            
            # Debug logging for the actual return dictionary
            logger.info(f"Return dictionary memory values - memory_used_gb: {return_dict['memory_used_gb']}, memory_free_gb: {return_dict['memory_free_gb']}, memory_total_gb: {return_dict['memory_total_gb']}")
            
            return return_dict

        except Exception as e:
            logger.error(f"Error processing health data: {e}")
            return {
                'cpu_usage': 0,
                'memory_usage': 0,
                'memory_used_gb': 0,
                'memory_free_gb': 0,
                'memory_total_gb': 0,
                'temperature': 0,
                'power_consumption': 0,
                'fan_speed': 0,
                'cpu_details': cpu_data or {},
                'memory_details': memory_data or {},
                'temperature_details': temperature_data or {},
                'power_details': power_data or {},
                'fan_details': fan_data or {}
            }

    def discover_topology(self, network_id: int, db: Session) -> Dict:
        """Discover network topology using SNMP."""
        try:
            # Get all devices in the network
            devices = db.query(Device).filter(Device.network_id == network_id).all()
            if not devices:
                return {"nodes": [], "edges": []}

            nodes = []
            edges = []
            device_map = {}  # Map device names to their data

            # First pass: Get basic device info and interfaces
            for device in devices:
                try:
                    if not device.snmp_status:
                        logger.warning(f"Device {device.name} has SNMP disabled")
                        continue

                    # Get device info
                    device_info = self.get_basic_device_info(device.ip)
                    if not device_info:
                        logger.warning(f"Could not get device info for {device.name}")
                        continue

                    # Get interfaces
                    interfaces = self.get_interfaces(device.ip)  # Changed from get_interface_info to get_interfaces
                    if not interfaces:
                        logger.warning(f"Could not get interfaces for {device.name}")
                        continue

                    # Add device to nodes
                    node_data = {
                        "id": device.name,
                        "label": device.name,
                        "type": "device",
                        "ip": device.ip,
                        "model": device_info.get("model", "Unknown"),
                        "os_version": device_info.get("os_version", "Unknown"),
                        "interfaces": interfaces
                    }
                    nodes.append(node_data)
                    device_map[device.name] = node_data

                except Exception as e:
                    logger.error(f"Error discovering topology for device {device.name}: {str(e)}")
                    continue

            # Second pass: Get CDP neighbors and create edges
            for device in devices:
                try:
                    if not device.snmp_status or device.name not in device_map:
                        continue

                    # Get CDP neighbors
                    neighbors = self.get_cdp_neighbors(device.ip)
                    if not neighbors:
                        continue

                    # Process each neighbor
                    for neighbor in neighbors:
                        neighbor_id = neighbor.get("device_id", "")
                        if not neighbor_id or neighbor_id not in device_map:
                            continue

                        # Get interface info
                        local_if_index = neighbor.get("local_port", "")
                        remote_if_name = neighbor.get("remote_port", "")

                        # Find local interface name
                        local_if_name = ""
                        for interface in device_map[device.name]["interfaces"]:
                            if interface.get("ifIndex") == local_if_index:
                                local_if_name = interface.get("ifDescr", "")
                                break

                        # Create edge
                        edge = {
                            "id": f"{device.name}-{neighbor_id}",
                            "source": device.name,
                            "target": neighbor_id,
                            "label": f"{local_if_name} - {remote_if_name}",
                            "type": "connection"
                        }
                        edges.append(edge)

                except Exception as e:
                    logger.error(f"Error processing CDP neighbors for device {device.name}: {str(e)}")
                    continue

            return {
                "nodes": nodes,
                "edges": edges
            }

        except Exception as e:
            logger.error(f"Error discovering topology: {str(e)}")
            return {"nodes": [], "edges": []}

    def get_temperature_data(self, ip_address: str, db_session: Session = None, device_id: int = None) -> dict:
        """Get temperature data from device via enhanced monitoring with SNMP and SSH fallback"""
        try:
            logger.info(f"Attempting to get enhanced temperature data for {ip_address}")
            
            # Use the enhanced temperature monitor
            temp_monitor = EnhancedTemperatureMonitor(self, db_session)
            temperature_data = temp_monitor.get_temperature_data(ip_address, device_id)
            
            if temperature_data:
                logger.info(f"Enhanced temperature monitor found data for {ip_address}: {temperature_data}")
                return temperature_data
            else:
                logger.warning(f"No temperature data found via enhanced monitoring for {ip_address}")
                return {}
            
        except Exception as e:
            logger.error(f"Error getting enhanced temperature data for {ip_address}: {e}")
            return {}

    def get_cpu_data(self, ip_address: str, db_session: Session = None) -> dict:
        """Get CPU data from device via SNMP using smart discovery"""
        try:
            logger.info(f"Attempting to get CPU data for {ip_address}")
            
            # Use the universal smart discovery system for CPU data
            smart_discovery = SmartSNMPDiscovery(self.community, db_session)
            discovered_data = smart_discovery.discover_data(ip_address, "cpu")
            
            if discovered_data:
                logger.info(f"Smart discovery found CPU data for {ip_address}: {discovered_data}")
                return discovered_data
            else:
                logger.warning(f"No CPU data discovered for {ip_address}")
                return {}
            
        except Exception as e:
            logger.error(f"Error getting CPU data for {ip_address}: {e}")
            return {}

    def get_memory_data(self, ip_address: str, db_session: Session = None) -> dict:
        """Get memory data from device via SNMP using smart discovery"""
        try:
            logger.info(f"Attempting to get memory data for {ip_address}")
            
            # Use the universal smart discovery system for memory data
            smart_discovery = SmartSNMPDiscovery(self.community, db_session)
            discovered_data = smart_discovery.discover_data(ip_address, "memory")
            
            if discovered_data:
                logger.info(f"Smart discovery found memory data for {ip_address}: {discovered_data}")
                return discovered_data
            else:
                logger.warning(f"No memory data discovered for {ip_address}")
                return {}
            
        except Exception as e:
            logger.error(f"Error getting memory data for {ip_address}: {e}")
            return {}

    def clear_health_cache(self, host: str = None):
        """Clear health cache for a specific host or all hosts"""
        if host:
            if host in SNMPPoller.health_cache:
                del SNMPPoller.health_cache[host]
                logger.info(f"Cleared health cache for {host}")
        else:
            SNMPPoller.health_cache.clear()
            logger.info("Cleared all health cache")
    
    def get_cache_info(self) -> Dict:
        """Get information about the health cache"""
        current_time = time.time()
        cache_info = {
            'total_entries': len(SNMPPoller.health_cache),
            'cache_timeout': SNMPPoller.cache_timeout,
            'entries': {}
        }
        
        for host, entry in SNMPPoller.health_cache.items():
            age = current_time - entry['timestamp']
            cache_info['entries'][host] = {
                'age_seconds': round(age, 1),
                'method': entry['method'],
                'expired': age >= SNMPPoller.cache_timeout
            }
        
        return cache_info
    
    def cleanup_expired_cache(self):
        """Remove expired cache entries"""
        current_time = time.time()
        expired_hosts = []
        
        for host, entry in SNMPPoller.health_cache.items():
            if current_time - entry['timestamp'] >= SNMPPoller.cache_timeout:
                expired_hosts.append(host)
        
        for host in expired_hosts:
            del SNMPPoller.health_cache[host]
        
        if expired_hosts:
            logger.info(f"Cleaned up {len(expired_hosts)} expired cache entries")


class SmartSNMPDiscovery:
    """Universal smart SNMP discovery system for any type of device data"""
    
    # Class-level storage for OID mappings (persistent across instances)
    oid_mappings = {}
    
    def __init__(self, snmp_community: str, db_session: Session = None):
        self.snmp_community = snmp_community
        self.device_profiles = {}  # Cache device capabilities
        self.oid_patterns = {}     # Discovered OID patterns
        self.discovery_cache = {}  # Cache successful discoveries
        
        # Initialize learning engine with error handling
        self.db_session = db_session
        self.learning_engine = None
        try:
            # Initialize without database session for file-based storage
            self.learning_engine = AdaptiveLearningEngine()
            logger.info("Learning engine initialized successfully")
        except Exception as e:
            logger.warning(f"Learning engine initialization failed: {e}. Continuing without learning capabilities.")
            self.learning_engine = None
    
    def discover_data(self, ip_address: str, data_category: str) -> dict:
        """Discover any type of SNMP data using intelligent methods"""
        start_time = time.time()
        
        try:
            logger.info(f"Smart discovery for {data_category} on {ip_address}")
            
            # 1. Check cache first
            cache_key = f"{ip_address}_{data_category}"
            if cache_key in self.discovery_cache:
                logger.info(f"Using cached discovery for {cache_key}")
                return self.discovery_cache[cache_key]
            
            # 2. Get device profile
            device_profile = self._get_device_profile(ip_address)
            
            # 3. Get optimized strategy from learning engine (if available)
            best_strategy = 'snmp_walk'
            preferred_oids = []
            
            if self.learning_engine:
                try:
                    best_strategy, preferred_oids = self.learning_engine.get_optimized_discovery_strategy(
                        device_profile, data_category
                    )
                    logger.info(f"Learning engine suggests strategy: {best_strategy} with {len(preferred_oids)} preferred OIDs")
                except Exception as e:
                    logger.warning(f"Learning engine strategy selection failed: {e}. Using default strategy.")
                    best_strategy = 'snmp_walk'
                    preferred_oids = []
            
            # 4. Try multiple discovery methods with optimization
            discovered_data = {}
            oids_tried = []
            
            # For memory, always try SNMP walk first to get all memory OIDs
            if data_category == "memory":
                logger.info(f"Forcing SNMP walk for memory discovery on {ip_address}")
                walk_data = self._snmp_walk_discovery(ip_address, data_category, device_profile)
                if walk_data:
                    discovered_data.update(walk_data)
                    logger.info(f"SNMP walk discovered {len(walk_data)} {data_category} sensors")
                
                # Also try pattern-based discovery for memory to ensure we get all OIDs
                pattern_data = self._pattern_based_discovery(ip_address, data_category, device_profile)
                if pattern_data:
                    discovered_data.update(pattern_data)
                    logger.info(f"Pattern discovery found {len(pattern_data)} {data_category} sensors")
            else:
                # Method 1: Try preferred OIDs first (if available)
                if preferred_oids and best_strategy == 'preferred_oids':
                    try:
                        preferred_data = self._try_preferred_oids(ip_address, data_category, preferred_oids)
                        if preferred_data:
                            discovered_data.update(preferred_data)
                            oids_tried.extend(preferred_oids)
                            logger.info(f"Preferred OIDs discovered {len(preferred_data)} {data_category} sensors")
                    except Exception as e:
                        logger.warning(f"Preferred OIDs discovery failed: {e}")
                
                # Method 2: SNMP Walk Discovery
                if not discovered_data or best_strategy == 'snmp_walk':
                    walk_data = self._snmp_walk_discovery(ip_address, data_category, device_profile)
                    if walk_data:
                        discovered_data.update(walk_data)
                        logger.info(f"SNMP walk discovered {len(walk_data)} {data_category} sensors")
                
                # Method 3: Pattern-Based Discovery
                if not discovered_data or best_strategy == 'pattern':
                    pattern_data = self._pattern_based_discovery(ip_address, data_category, device_profile)
                    if pattern_data:
                        discovered_data.update(pattern_data)
                        logger.info(f"Pattern discovery found {len(pattern_data)} {data_category} sensors")
                
                # Method 4: MIB-Based Discovery
                if not discovered_data or best_strategy == 'mib':
                    mib_data = self._mib_based_discovery(ip_address, data_category, device_profile)
                    if mib_data:
                        discovered_data.update(mib_data)
                        logger.info(f"MIB discovery found {len(mib_data)} {data_category} sensors")
            
            # 5. Filter and validate data
            validated_data = self._validate_discovered_data(discovered_data, data_category)
            
            # 6. Learn from discovery (if learning engine is available)
            discovery_time = time.time() - start_time
            if self.learning_engine and validated_data:
                try:
                    self.learning_engine.learn_from_discovery(
                        device_profile, data_category, validated_data, 
                        best_strategy, discovery_time, oids_tried
                    )
                    logger.info(f"Learning engine updated with {data_category} discovery results")
                except Exception as e:
                    logger.warning(f"Learning engine update failed: {e}")
            
            # 7. Cache successful discovery
            if validated_data:
                self.discovery_cache[cache_key] = validated_data
                self._learn_from_discovery(ip_address, data_category, validated_data, device_profile)
            
            return validated_data
            
        except Exception as e:
            logger.error(f"Error in smart discovery for {data_category} on {ip_address}: {e}")
            return {}
    
    def _try_preferred_oids(self, ip_address: str, data_category: str, preferred_oids: List[str]) -> dict:
        """Try discovery using learned preferred OIDs"""
        try:
            discovered_data = {}
            
            for oid in preferred_oids:
                try:
                    value = self._get_snmp_value(ip_address, oid)
                    if value and self._is_relevant_data(oid, value, data_category):
                        sensor_name = self._generate_sensor_name(oid, value, data_category)
                        discovered_data[sensor_name] = value
                        logger.info(f"Preferred OID {oid} discovered: {sensor_name} = {value}")
                except Exception as e:
                    logger.debug(f"Preferred OID {oid} failed: {e}")
                    continue
            
            return discovered_data
            
        except Exception as e:
            logger.error(f"Error trying preferred OIDs: {e}")
            return {}
    
    def _get_device_profile(self, ip_address: str) -> dict:
        """Get or create device profile for intelligent discovery"""
        if ip_address in self.device_profiles:
            return self.device_profiles[ip_address]
        
        try:
            # Get basic device info
            snmp_poller = SNMPPoller(self.snmp_community)
            device_info = snmp_poller.get_basic_device_info(ip_address)
            
            profile = {
                'ip_address': ip_address,
                'sys_descr': device_info.get('sysDescr', ''),
                'sys_object_id': device_info.get('sysObjectID', ''),
                'vendor': self._identify_vendor(device_info.get('sysObjectID', '')),
                'model': self._extract_model(device_info.get('sysDescr', '')),
                'capabilities': {},
                'discovered_oids': {}
            }
            
            self.device_profiles[ip_address] = profile
            logger.info(f"Created device profile for {ip_address}: {profile['model']} ({profile['vendor']})")
            return profile
            
        except Exception as e:
            logger.error(f"Error creating device profile for {ip_address}: {e}")
            return {'ip_address': ip_address, 'vendor': 'unknown', 'model': 'unknown'}
    
    def _identify_vendor(self, sys_object_id: str) -> str:
        """Identify vendor from sysObjectID"""
        if not sys_object_id:
            return 'unknown'
        
        vendor_patterns = {
            'cisco': ['1.3.6.1.4.1.9.', 'cisco'],
            'juniper': ['1.3.6.1.4.1.2636.', 'juniper'],
            'hp': ['1.3.6.1.4.1.11.', 'hp'],
            'arista': ['1.3.6.1.4.1.30065.', 'arista'],
            'brocade': ['1.3.6.1.4.1.1588.', 'brocade']
        }
        
        for vendor, patterns in vendor_patterns.items():
            if any(pattern in sys_object_id.lower() for pattern in patterns):
                return vendor
        
        return 'unknown'
    
    def _extract_model(self, sys_descr: str) -> str:
        """Extract device model from system description"""
        if not sys_descr:
            return 'unknown'
        
        # Common model patterns
        model_patterns = [
            r'WS-C\d+',  # Cisco Catalyst
            r'C\d+',     # Cisco models
            r'ASR\d+',   # Cisco ASR
            r'ISR\d+',   # Cisco ISR
            r'MX\d+',    # Juniper MX
            r'EX\d+',    # Juniper EX
        ]
        
        for pattern in model_patterns:
            match = re.search(pattern, sys_descr, re.IGNORECASE)
            if match:
                return match.group()
        
        return 'unknown'
    
    def _snmp_walk_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using SNMP walk through relevant OID trees"""
        try:
            discovered_data = {}
            
            # Define OID trees to walk based on data category
            oid_trees = self._get_oid_trees_for_category(data_category, device_profile)
            
            for tree_name, base_oid in oid_trees.items():
                try:
                    logger.info(f"Walking OID tree {tree_name} ({base_oid}) for {data_category}")
                    
                    snmp_engine = SnmpEngine()
                    auth_data = CommunityData(self.snmp_community, mpModel=1)
                    target = UdpTransportTarget((ip_address, 161), timeout=3, retries=1)
                    context = ContextData()
                    
                    for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                        snmp_engine, auth_data, target, context,
                        ObjectType(ObjectIdentity(base_oid)),
                        lexicographicMode=False, maxRows=100
                    ):
                        if errorIndication:
                            logger.debug(f"SNMP walk error in {tree_name}: {errorIndication}")
                            break
                        elif errorStatus:
                            logger.debug(f"SNMP walk error in {tree_name}: {errorStatus.prettyPrint()}")
                            break
                        else:
                            for varBind in varBinds:
                                oid = str(varBind[0])
                                value = str(varBind[1])
                                
                                # Validate if this is relevant data
                                if self._is_relevant_data(oid, value, data_category):
                                    sensor_name = self._generate_sensor_name(oid, value, data_category)
                                    discovered_data[sensor_name] = value
                                    logger.info(f"Discovered {data_category} sensor {sensor_name}: {value} (OID: {oid})")
                
                except Exception as e:
                    logger.debug(f"Error walking OID tree {tree_name}: {e}")
                    continue
            
            return discovered_data
            
        except Exception as e:
            logger.error(f"Error in SNMP walk discovery for {data_category}: {e}")
            return {}
    
    def _get_oid_trees_for_category(self, data_category: str, device_profile: dict) -> dict:
        """Get relevant OID trees for specific data category"""
        trees = {}
        
        if data_category == "temperature":
            trees = {
                'cisco_env_mon': '1.3.6.1.4.1.9.9.13.1.3',  # Cisco environmental monitoring
                'cisco_temp': '1.3.6.1.4.1.9.9.13.1.3.1',   # Cisco temperature sensors
                'standard_env': '1.3.6.1.2.1.99.1.1',       # Standard environmental MIB
                'vendor_specific': '1.3.6.1.4.1.9.9.13',    # Cisco vendor-specific
            }
        elif data_category == "fan":
            trees = {
                'cisco_fan': '1.3.6.1.4.1.9.9.13.1.4',     # Cisco fan monitoring
                'standard_fan': '1.3.6.1.2.1.99.1.2',      # Standard fan MIB
            }
        elif data_category == "power":
            trees = {
                'cisco_power': '1.3.6.1.4.1.9.9.13.1.5',   # Cisco power monitoring
                'standard_power': '1.3.6.1.2.1.99.1.3',    # Standard power MIB
            }
        elif data_category == "cpu":
            trees = {
                'cisco_cpu': '1.3.6.1.4.1.9.9.109',        # Cisco CPU monitoring
                'cisco_cpu_detail': '1.3.6.1.4.1.9.9.109.1.1.1.1',  # Cisco CPU detailed
                'standard_cpu': '1.3.6.1.2.1.25.3.3',      # Standard CPU MIB
                'standard_cpu_detail': '1.3.6.1.2.1.25.3.3.1',      # Standard CPU detailed
                'vendor_specific_cpu': '1.3.6.1.4.1.9.9.109.1.1.1', # Cisco vendor-specific CPU
            }
        elif data_category == "memory":
            trees = {
                'cisco_memory': '1.3.6.1.4.1.9.9.48',      # Cisco memory monitoring
                'cisco_memory_detail': '1.3.6.1.4.1.9.9.48.1.1.1',  # Cisco memory detailed
                'standard_memory': '1.3.6.1.2.1.25.2.3',   # Standard memory MIB
                'standard_memory_detail': '1.3.6.1.2.1.25.2.3.1',   # Standard memory detailed
                'vendor_specific_memory': '1.3.6.1.4.1.9.9.48.1.1', # Cisco vendor-specific memory
            }
        
        return trees
    
    def _is_relevant_data(self, oid: str, value: str, data_category: str) -> bool:
        """Validate if discovered data is relevant for the category"""
        if not value or value.strip() == '' or value == 'No Such Object currently exists at this OID':
            return False
        
        try:
            # Try to convert to numeric value
            numeric_value = float(value)
            
            # Validate based on data category
            if data_category == "temperature":
                return 0 <= numeric_value <= 100  # Reasonable temperature range
            elif data_category == "fan":
                return 0 <= numeric_value <= 10000  # Fan RPM range
            elif data_category == "power":
                return 0 <= numeric_value <= 10000  # Power consumption range
            elif data_category == "cpu":
                return 0 <= numeric_value <= 100  # CPU percentage
            elif data_category == "memory":
                # Memory can be percentage (0-100) or raw values (KB/bytes)
                # Allow both percentage and realistic memory values
                if 0 <= numeric_value <= 100:
                    return True  # Percentage value
                elif 1000 <= numeric_value <= 50000000000:  # 1MB to 50GB in bytes/KB
                    return True  # Raw memory value
                else:
                    return False  # Out of reasonable range
            
            return True
            
        except ValueError:
            # Non-numeric value, check if it's a relevant description
            relevant_keywords = {
                "temperature": ["temp", "thermal", "heat", "celsius", "fahrenheit"],
                "fan": ["fan", "rpm", "cooling"],
                "power": ["power", "watt", "voltage", "current"],
                "cpu": ["cpu", "processor", "utilization"],
                "memory": ["memory", "ram", "utilization", "processor"]  # Added "processor" for Cisco memory pools
            }
            
            keywords = relevant_keywords.get(data_category, [])
            return any(keyword in value.lower() for keyword in keywords)
    
    def _generate_sensor_name(self, oid: str, value: str, data_category: str) -> str:
        """Generate meaningful sensor name from OID and value"""
        try:
            # Try to get description from nearby OID
            desc_oid = self._get_description_oid(oid)
            if desc_oid:
                desc_value = self._get_snmp_value(oid.split(':')[0], desc_oid)
                if desc_value and desc_value.strip():
                    return f"{data_category}_{desc_value.strip()}"
            
            # Generate name from OID parts
            oid_parts = oid.split('.')
            if len(oid_parts) >= 2:
                last_part = oid_parts[-1]
                return f"{data_category}_sensor_{last_part}"
            
            return f"{data_category}_sensor_{hash(oid) % 1000}"
            
        except Exception:
            return f"{data_category}_sensor_{hash(oid) % 1000}"
    
    def _get_description_oid(self, oid: str) -> str:
        """Get description OID for a given sensor OID"""
        # This is a simplified approach - in practice, you'd parse MIB files
        oid_parts = oid.split('.')
        if len(oid_parts) >= 2:
            # Try common description OID patterns
            base_oid = '.'.join(oid_parts[:-1])
            return f"{base_oid}.1.{oid_parts[-1]}"  # Common pattern for descriptions
        return None
    
    def _get_snmp_value(self, ip_address: str, oid: str) -> str:
        """Get single SNMP value"""
        try:
            snmp_engine = SnmpEngine()
            auth_data = CommunityData(self.snmp_community, mpModel=1)
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
    
    def _pattern_based_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using pattern matching and intelligent OID generation"""
        try:
            discovered_data = {}
            
            # Generate OID patterns based on device profile and category
            oid_patterns = self._generate_oid_patterns(data_category, device_profile)
            
            for pattern_name, oid_pattern in oid_patterns.items():
                try:
                    result = self._get_snmp_value(ip_address, oid_pattern)
                    if result and self._is_relevant_data(oid_pattern, result, data_category):
                        discovered_data[pattern_name] = result
                        logger.info(f"Pattern discovery found {pattern_name}: {result} (OID: {oid_pattern})")
                except Exception:
                    continue
            
            return discovered_data
            
        except Exception as e:
            logger.error(f"Error in pattern-based discovery: {e}")
            return {}
    
    def _generate_oid_patterns(self, data_category: str, device_profile: dict) -> dict:
        """Generate OID patterns based on device profile and category"""
        patterns = {}
        vendor = device_profile.get('vendor', 'unknown')
        
        if data_category == "temperature":
            if vendor == "cisco":
                # Cisco temperature OID patterns
                base_patterns = [
                    '1.3.6.1.4.1.9.9.13.1.3.1.1.1',  # System temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.2.1',  # Inlet temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.3.1',  # Hotspot temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.4.1',  # Threshold 1
                    '1.3.6.1.4.1.9.9.13.1.3.1.5.1',  # Threshold 2
                    '1.3.6.1.4.1.9.9.13.1.3.1.6.1',  # CPU temperature
                    '1.3.6.1.4.1.9.9.13.1.3.1.7.1',  # Board temperature
                ]
                
                for i, pattern in enumerate(base_patterns):
                    patterns[f"cisco_temp_{i+1}"] = pattern
                
                # Try different index values
                for index in range(1, 10):
                    patterns[f"cisco_temp_index_{index}"] = f"1.3.6.1.4.1.9.9.13.1.3.1.2.{index}"
            
            # Add vendor-agnostic patterns
            patterns.update({
                'standard_temp': '1.3.6.1.2.1.99.1.1.1.1.1',
                'env_temp': '1.3.6.1.2.1.99.1.1.1.2.1',
            })
        
        elif data_category == "cpu":
            if vendor == "cisco":
                # Cisco CPU OID patterns
                cisco_cpu_patterns = [
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.3.1',  # CPU 5-minute average
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.4.1',  # CPU 1-minute average
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.5.1',  # CPU 5-second average
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.6.1',  # CPU utilization
                    '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',  # CPU load
                ]
                
                for i, pattern in enumerate(cisco_cpu_patterns):
                    patterns[f"cisco_cpu_{i+1}"] = pattern
                
                # Try different CPU indices
                for cpu_index in range(1, 5):  # Try up to 4 CPUs
                    patterns[f"cisco_cpu_5min_{cpu_index}"] = f"1.3.6.1.4.1.9.9.109.1.1.1.1.3.{cpu_index}"
                    patterns[f"cisco_cpu_1min_{cpu_index}"] = f"1.3.6.1.4.1.9.9.109.1.1.1.1.4.{cpu_index}"
                    patterns[f"cisco_cpu_5sec_{cpu_index}"] = f"1.3.6.1.4.1.9.9.109.1.1.1.1.5.{cpu_index}"
            
            # Standard CPU OIDs
            patterns.update({
                'standard_cpu_5min': '1.3.6.1.2.1.25.3.3.1.2.1',  # Standard CPU 5-min
                'standard_cpu_1min': '1.3.6.1.2.1.25.3.3.1.2.2',  # Standard CPU 1-min
                'standard_cpu_util': '1.3.6.1.2.1.25.3.3.1.2.3',  # Standard CPU utilization
            })
            
            # Vendor-agnostic CPU patterns
            patterns.update({
                'generic_cpu_load': '1.3.6.1.2.1.25.3.3.1.2.1',
                'generic_cpu_util': '1.3.6.1.2.1.25.3.3.1.2.2',
            })
        
        elif data_category == "memory":
            if vendor == "cisco":
                # Cisco Memory OID patterns - try multiple memory pools
                cisco_memory_patterns = [
                    '1.3.6.1.4.1.9.9.48.1.1.1.6.1',  # Memory used
                    '1.3.6.1.4.1.9.9.48.1.1.1.5.1',  # Memory free
                    '1.3.6.1.4.1.9.9.48.1.1.1.4.1',  # Memory total
                    '1.3.6.1.4.1.9.9.48.1.1.1.7.1',  # Memory utilization
                    '1.3.6.1.4.1.9.9.48.1.1.1.8.1',  # Memory available
                ]
                
                for i, pattern in enumerate(cisco_memory_patterns):
                    patterns[f"cisco_memory_{i+1}"] = pattern
                
                # Try different memory pool indices (1-10) - many Cisco devices use different indices
                for pool_index in range(1, 11):  # Try up to 10 memory pools
                    patterns[f"cisco_memory_used_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.6.{pool_index}"
                    patterns[f"cisco_memory_free_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.5.{pool_index}"
                    patterns[f"cisco_memory_total_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.4.{pool_index}"
                    patterns[f"cisco_memory_util_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.7.{pool_index}"
                    patterns[f"cisco_memory_avail_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.8.{pool_index}"
                
                # Also try the memory pool name OID to identify which pool is the main memory
                for pool_index in range(1, 11):
                    patterns[f"cisco_memory_name_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.2.{pool_index}"
                    patterns[f"cisco_memory_type_{pool_index}"] = f"1.3.6.1.4.1.9.9.48.1.1.1.3.{pool_index}"
                
                # Add additional system memory OIDs that might be available
                patterns.update({
                    'cisco_system_memory_total': '1.3.6.1.4.1.9.9.48.1.1.1.4.1',  # System memory total
                    'cisco_system_memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.6.1',   # System memory used
                    'cisco_system_memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.5.1',   # System memory free
                    'cisco_processor_memory_total': '1.3.6.1.4.1.9.9.48.1.1.1.4.2',  # Processor memory total
                    'cisco_processor_memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.6.2',   # Processor memory used
                    'cisco_processor_memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.5.2',   # Processor memory free
                })
            
            # Standard Memory OIDs
            patterns.update({
                'standard_memory_total': '1.3.6.1.2.1.25.2.3.1.5.1',  # Total memory
                'standard_memory_used': '1.3.6.1.2.1.25.2.3.1.6.1',   # Used memory
                'standard_memory_free': '1.3.6.1.2.1.25.2.3.1.7.1',   # Free memory
            })
            
            # Vendor-agnostic memory patterns
            patterns.update({
                'generic_memory_total': '1.3.6.1.2.1.25.2.3.1.5.1',
                'generic_memory_used': '1.3.6.1.2.1.25.2.3.1.6.1',
                'generic_memory_free': '1.3.6.1.2.1.25.2.3.1.7.1',
            })
        
        return patterns
    
    def _mib_based_discovery(self, ip_address: str, data_category: str, device_profile: dict) -> dict:
        """Discover data using MIB-based approach (simplified)"""
        # This is a placeholder for MIB-based discovery
        # In a full implementation, you would:
        # 1. Download and parse MIB files
        # 2. Extract OIDs for the specific data category
        # 3. Query those OIDs on the device
        return {}
    
    def _validate_discovered_data(self, discovered_data: dict, data_category: str) -> dict:
        """Validate and clean discovered data"""
        validated_data = {}
        
        for sensor_name, value in discovered_data.items():
            if self._is_relevant_data("", value, data_category):
                # Add units based on category
                if data_category == "temperature":
                    validated_data[sensor_name] = f"{value}°C"
                elif data_category == "fan":
                    validated_data[sensor_name] = f"{value} RPM"
                elif data_category == "power":
                    validated_data[sensor_name] = f"{value}W"
                elif data_category == "cpu":
                    validated_data[sensor_name] = f"{value}%"
                elif data_category == "memory":
                    # Don't add % to memory values - let the processing logic determine if it's a percentage
                    validated_data[sensor_name] = value
                else:
                    validated_data[sensor_name] = value
        
        return validated_data
    
    def _learn_from_discovery(self, ip_address: str, data_category: str, discovered_data: dict, device_profile: dict):
        """Learn from successful discovery and store OID mappings"""
        try:
            # Store OID mappings for learning (using class-level storage)
            mapping_key = f"{ip_address}_{data_category}"
            if mapping_key not in SmartSNMPDiscovery.oid_mappings:
                SmartSNMPDiscovery.oid_mappings[mapping_key] = {}
            
            # Store ALL discovered data, not just sensor names
            for sensor_name, value in discovered_data.items():
                # Store all discovered mappings for fast-path retrieval
                SmartSNMPDiscovery.oid_mappings[mapping_key][sensor_name] = {
                    'value': value,
                    'discovered_at': datetime.utcnow().isoformat()
                }
            
            logger.info(f"Stored {len(discovered_data)} {data_category} mappings for {ip_address}")
            
        except Exception as e:
            logger.error(f"Error learning from discovery: {e}")
    
    def _get_learned_oids_for_category(self, ip_address: str, data_category: str) -> List[str]:
        """Get learned OIDs for a specific category"""
        try:
            mapping_key = f"{ip_address}_{data_category}"
            if mapping_key in SmartSNMPDiscovery.oid_mappings:
                # Return the sensor names that can be used for fast-path
                return list(SmartSNMPDiscovery.oid_mappings[mapping_key].keys())
            
            return []
            
        except Exception as e:
            logger.error(f"Error getting learned OIDs: {e}")
            return []


class EnhancedTemperatureMonitor:
    """Enhanced temperature monitoring with SNMP and SSH fallback"""
    
    def __init__(self, snmp_poller: 'SNMPPoller', db_session: Session = None):
        self.snmp_poller = snmp_poller
        self.db_session = db_session
        
        # Comprehensive temperature OIDs for different vendors
        self.temperature_oids = {
            'cisco': {
                'system_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.1',  # System temperature
                'inlet_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.2',   # Inlet temperature
                'hotspot_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.3', # Hotspot temperature
                'cpu_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.4',     # CPU temperature
                'board_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.5',   # Board temperature
                'ambient_temp': '1.3.6.1.4.1.9.9.13.1.3.1.2.6', # Ambient temperature
                'threshold_yellow': '1.3.6.1.4.1.9.9.13.1.3.1.3.1',  # Yellow threshold
                'threshold_red': '1.3.6.1.4.1.9.9.13.1.3.1.4.1',     # Red threshold
                'temp_status': '1.3.6.1.4.1.9.9.13.1.3.1.5.1',       # Temperature status
            },
            'juniper': {
                'system_temp': '1.3.6.1.4.1.2636.3.1.8.1.5.1.1.1',  # System temperature
                'cpu_temp': '1.3.6.1.4.1.2636.3.1.8.1.5.1.2.1',     # CPU temperature
                'ambient_temp': '1.3.6.1.4.1.2636.3.1.8.1.5.1.3.1', # Ambient temperature
            },
            'arista': {
                'system_temp': '1.3.6.1.4.1.30065.3.1.1.1.1.1',     # System temperature
                'cpu_temp': '1.3.6.1.4.1.30065.3.1.1.1.2.1',        # CPU temperature
            },
            'hp': {
                'system_temp': '1.3.6.1.4.1.11.2.14.11.1.2.1.1.1.1', # System temperature
                'cpu_temp': '1.3.6.1.4.1.11.2.14.11.1.2.1.1.1.2',    # CPU temperature
            },
            'generic': {
                'env_temp': '1.3.6.1.2.1.99.1.1.1.1.1',             # Standard environmental MIB
                'temp_sensor': '1.3.6.1.2.1.99.1.1.1.2.1',          # Temperature sensor
            }
        }
        
        # CLI commands for different vendors
        self.temperature_commands = {
            'cisco_ios': ['show environment temperature', 'show environment all', 'show temperature'],
            'cisco_ios_xe': ['show environment temperature', 'show environment all', 'show temperature'],
            'cisco_nx_os': ['show environment temperature', 'show environment all'],
            'juniper': ['show chassis temperature', 'show chassis environment'],
            'arista': ['show environment temperature', 'show environment all'],
            'hp': ['show environment temperature', 'show environment all'],
            'generic': ['show environment', 'show temperature', 'show system environment']
        }
    
    def get_temperature_data(self, ip_address: str, device_id: int = None) -> Dict:
        """Get temperature data with SNMP first, SSH fallback"""
        try:
            # Try SNMP first
            snmp_data = self._get_temperature_snmp(ip_address)
            if snmp_data and self._validate_temperature_data(snmp_data):
                logger.info(f"SNMP temperature data retrieved for {ip_address}: {snmp_data}")
                return snmp_data
            
            # Fallback to SSH
            logger.info(f"SNMP failed for {ip_address}, trying SSH fallback")
            ssh_data = self._get_temperature_ssh(ip_address, device_id)
            if ssh_data and self._validate_temperature_data(ssh_data):
                logger.info(f"SSH temperature data retrieved for {ip_address}: {ssh_data}")
                return ssh_data
            
            logger.warning(f"No valid temperature data found for {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error getting temperature data for {ip_address}: {e}")
            return {}
    
    def _get_temperature_snmp(self, ip_address: str) -> Dict:
        """Get temperature data via SNMP with comprehensive OID coverage"""
        try:
            temperature_data = {}
            
            # Get device profile to determine vendor
            device_profile = self._get_device_profile(ip_address)
            vendor = device_profile.get('vendor', 'generic')
            
            # Try vendor-specific OIDs first
            vendor_oids = self.temperature_oids.get(vendor, self.temperature_oids['generic'])
            
            for temp_type, oid in vendor_oids.items():
                try:
                    value = self._get_snmp_value(ip_address, oid)
                    if value and self._is_valid_temperature(value):
                        temperature_data[temp_type] = value
                        logger.debug(f"SNMP temperature {temp_type}: {value}°C")
                except Exception as e:
                    logger.debug(f"Failed to get {temp_type} via SNMP: {e}")
                    continue
            
            # Try additional OID patterns for better coverage
            additional_oids = self._generate_additional_temperature_oids(vendor)
            for temp_type, oid in additional_oids.items():
                if temp_type not in temperature_data:  # Don't overwrite existing data
                    try:
                        value = self._get_snmp_value(ip_address, oid)
                        if value and self._is_valid_temperature(value):
                            temperature_data[temp_type] = value
                            logger.debug(f"Additional SNMP temperature {temp_type}: {value}°C")
                    except Exception:
                        continue
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error in SNMP temperature retrieval: {e}")
            return {}
    
    def _get_temperature_ssh(self, ip_address: str, device_id: int = None) -> Dict:
        """Get temperature data via SSH CLI commands"""
        try:
            # Get device credentials from database
            credentials = self._get_device_credentials(ip_address, device_id)
            if not credentials:
                logger.error(f"No SSH credentials found for {ip_address}")
                return {}
            
            username = credentials['username']
            password = credentials['password']
            platform = credentials.get('platform', 'cisco_ios')
            
            # Get appropriate commands for the platform
            commands = self.temperature_commands.get(platform, self.temperature_commands['generic'])
            
            for command in commands:
                try:
                    output = run_show_command(ip_address, username, password, command)
                    if output and not output.startswith('❌'):
                        parsed_data = self._parse_temperature_cli(output, platform)
                        if parsed_data:
                            logger.info(f"SSH temperature data parsed for {ip_address}: {parsed_data}")
                            return parsed_data
                except Exception as e:
                    logger.debug(f"SSH command '{command}' failed: {e}")
                    continue
            
            logger.warning(f"No valid SSH temperature data found for {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error in SSH temperature retrieval: {e}")
            return {}
    
    def _get_device_credentials(self, ip_address: str, device_id: int = None) -> Dict:
        """Get device SSH credentials from database"""
        try:
            if not self.db_session:
                logger.error("No database session available")
                return {}
            
            # Try to find device by IP or ID
            device = None
            if device_id:
                device = self.db_session.query(BaseDevice).filter(BaseDevice.id == device_id).first()
            else:
                device = self.db_session.query(BaseDevice).filter(BaseDevice.ip == ip_address).first()
            
            if device and device.username and device.password:
                return {
                    'username': device.username,
                    'password': device.password,
                    'platform': device.platform or 'cisco_ios'
                }
            
            logger.warning(f"No credentials found for device {ip_address}")
            return {}
            
        except Exception as e:
            logger.error(f"Error getting device credentials: {e}")
            return {}
    
    def _parse_temperature_cli(self, output: str, platform: str) -> Dict:
        """Parse temperature data from CLI output for different platforms"""
        try:
            temperature_data = {}
            
            if platform.startswith('cisco'):
                return self._parse_cisco_temperature(output)
            elif platform.startswith('juniper'):
                return self._parse_juniper_temperature(output)
            elif platform.startswith('arista'):
                return self._parse_arista_temperature(output)
            elif platform.startswith('hp'):
                return self._parse_hp_temperature(output)
            else:
                return self._parse_generic_temperature(output)
                
        except Exception as e:
            logger.error(f"Error parsing CLI temperature output: {e}")
            return {}
    
    def _parse_cisco_temperature(self, output: str) -> Dict:
        """Parse Cisco temperature CLI output"""
        temperature_data = {}
        
        try:
            # Parse inlet temperature
            inlet_match = re.search(r'Inlet Temperature Value:\s*(\d+)\s*Degree Celsius', output, re.IGNORECASE)
            if inlet_match:
                temperature_data['inlet_temp'] = inlet_match.group(1)
            
            # Parse hotspot temperature
            hotspot_match = re.search(r'Hotspot Temperature Value:\s*(\d+)\s*Degree Celsius', output, re.IGNORECASE)
            if hotspot_match:
                temperature_data['hotspot_temp'] = hotspot_match.group(1)
            
            # Parse system temperature
            system_match = re.search(r'SYSTEM TEMPERATURE is OK', output, re.IGNORECASE)
            if system_match:
                temperature_data['system_status'] = 'OK'
            
            # Parse yellow threshold
            yellow_match = re.search(r'Yellow Threshold\s*:\s*(\d+)\s*Degree Celsius', output, re.IGNORECASE)
            if yellow_match:
                temperature_data['threshold_yellow'] = yellow_match.group(1)
            
            # Parse red threshold
            red_match = re.search(r'Red Threshold\s*:\s*(\d+)\s*Degree Celsius', output, re.IGNORECASE)
            if red_match:
                temperature_data['threshold_red'] = red_match.group(1)
            
            # Parse temperature state
            state_match = re.search(r'Temperature State:\s*(\w+)', output, re.IGNORECASE)
            if state_match:
                temperature_data['temp_status'] = state_match.group(1)
            
            # Try alternative patterns
            if not temperature_data:
                # Look for any temperature values in the output
                temp_matches = re.findall(r'(\d+)\s*[Dd]egree[s]?\s*[Cc]elsius', output)
                if temp_matches:
                    temperature_data['ambient_temp'] = temp_matches[0]
                    if len(temp_matches) > 1:
                        temperature_data['system_temp'] = temp_matches[1]
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Cisco temperature output: {e}")
            return {}
    
    def _parse_juniper_temperature(self, output: str) -> Dict:
        """Parse Juniper temperature CLI output"""
        temperature_data = {}
        
        try:
            # Parse temperature values
            temp_matches = re.findall(r'(\d+)\s*C', output)
            if temp_matches:
                temperature_data['system_temp'] = temp_matches[0]
                if len(temp_matches) > 1:
                    temperature_data['cpu_temp'] = temp_matches[1]
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Juniper temperature output: {e}")
            return {}
    
    def _parse_arista_temperature(self, output: str) -> Dict:
        """Parse Arista temperature CLI output"""
        temperature_data = {}
        
        try:
            # Parse temperature values
            temp_matches = re.findall(r'(\d+)\s*C', output)
            if temp_matches:
                temperature_data['system_temp'] = temp_matches[0]
                if len(temp_matches) > 1:
                    temperature_data['cpu_temp'] = temp_matches[1]
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing Arista temperature output: {e}")
            return {}
    
    def _parse_hp_temperature(self, output: str) -> Dict:
        """Parse HP temperature CLI output"""
        temperature_data = {}
        
        try:
            # Parse temperature values
            temp_matches = re.findall(r'(\d+)\s*C', output)
            if temp_matches:
                temperature_data['system_temp'] = temp_matches[0]
                if len(temp_matches) > 1:
                    temperature_data['cpu_temp'] = temp_matches[1]
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing HP temperature output: {e}")
            return {}
    
    def _parse_generic_temperature(self, output: str) -> Dict:
        """Parse generic temperature CLI output"""
        temperature_data = {}
        
        try:
            # Look for any temperature patterns
            temp_matches = re.findall(r'(\d+)\s*[Cc]elsius', output)
            if temp_matches:
                temperature_data['ambient_temp'] = temp_matches[0]
            
            # Look for Fahrenheit and convert
            fahrenheit_matches = re.findall(r'(\d+)\s*[Ff]ahrenheit', output)
            if fahrenheit_matches:
                fahrenheit = int(fahrenheit_matches[0])
                celsius = round((fahrenheit - 32) * 5/9)
                temperature_data['ambient_temp'] = str(celsius)
            
            return temperature_data
            
        except Exception as e:
            logger.error(f"Error parsing generic temperature output: {e}")
            return {}
    
    def _get_device_profile(self, ip_address: str) -> Dict:
        """Get device profile for vendor identification"""
        try:
            # Use the existing smart discovery to get device profile
            smart_discovery = SmartSNMPDiscovery(self.snmp_poller.community, self.db_session)
            return smart_discovery._get_device_profile(ip_address)
        except Exception as e:
            logger.error(f"Error getting device profile: {e}")
            return {'vendor': 'generic'}
    
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
    
    def _generate_additional_temperature_oids(self, vendor: str) -> Dict:
        """Generate additional temperature OIDs for better coverage"""
        additional_oids = {}
        
        if vendor == 'cisco':
            # Try different index values for Cisco
            for index in range(1, 20):
                additional_oids[f'cisco_temp_index_{index}'] = f'1.3.6.1.4.1.9.9.13.1.3.1.2.{index}'
                additional_oids[f'cisco_threshold_yellow_{index}'] = f'1.3.6.1.4.1.9.9.13.1.3.1.3.{index}'
                additional_oids[f'cisco_threshold_red_{index}'] = f'1.3.6.1.4.1.9.9.13.1.3.1.4.{index}'
        
        return additional_oids
    
    def _is_valid_temperature(self, value: str) -> bool:
        """Validate if a temperature value is reasonable"""
        try:
            temp = float(value)
            return -10 <= temp <= 100  # Reasonable temperature range
        except (ValueError, TypeError):
            return False
    
    def _validate_temperature_data(self, data: Dict) -> bool:
        """Validate temperature data quality"""
        if not data:
            return False
        
        # Check if we have at least one valid temperature reading
        for key, value in data.items():
            if 'temp' in key.lower() and self._is_valid_temperature(value):
                return True
        
        return False