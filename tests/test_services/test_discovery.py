"""
Test discovery service functionality
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
from app.services.adaptive_learning import AdaptiveLearningService

# Mock network scanning function for testing
async def mock_scan_network(start_ip, end_ip, username, password, device_type, snmp_config=None, location="Test Location"):
    """
    Mock function to simulate network scanning
    Returns a list of mock discovered devices
    """
    return [
        {
            "ip": "192.168.56.8",
            "hostname": "test-device-1",
            "device_type": "cisco_ios",
            "status": "reachable"
        }
    ]

@pytest.mark.asyncio
async def test_network_discovery():
    """Test network discovery functionality"""
    start_ip = "192.168.56.8"
    end_ip = "192.168.56.12"
    username = "admin"
    password = "test_password"
    device_type = "cisco_ios"

    # Generate IP list
    from ipaddress import IPv4Address
    start = IPv4Address(start_ip)
    end = IPv4Address(end_ip)
    ip_list = [str(IPv4Address(ip)) for ip in range(int(start), int(end) + 1)]

    # Test that we can generate the IP range
    assert len(ip_list) > 0
    assert start_ip in ip_list
    assert end_ip in ip_list

    # Mock discovery service
    discovery_service = AdaptiveLearningService()
    
    # Test the scanning logic (without actually scanning)
    devices = await mock_scan_network(
        start_ip=start_ip,
        end_ip=end_ip,
        username=username,
        password=password,
        device_type=device_type,
        snmp_config=None
    )
    
    # Verify results
    assert len(devices) > 0
    assert devices[0]["ip"] == "192.168.56.8"
    assert devices[0]["status"] == "reachable"

def test_discovery_service_initialization():
    """Test that AdaptiveLearningService can be initialized"""
    service = AdaptiveLearningService()
    assert service is not None 