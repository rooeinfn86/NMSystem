"""
Direct API test functionality
"""

import asyncio
import os
from app.core.snmp_poller_refactored import scan_single_device

async def test_direct_scan():
    """Test direct device scanning functionality"""
    
    # Test configuration from environment variables
    test_ip = os.getenv("TEST_DEVICE_IP", "192.168.56.8")
    username = os.getenv("TEST_USERNAME", "admin")
    password = os.getenv("TEST_PASSWORD", "test_password")
    device_type = "cisco_ios"
    network_id = 14
    company_id = 63
    
    print(f"Testing direct scan for IP: {test_ip}")
    print(f"Username: {username}")
    print(f"Device type: {device_type}")
    
    try:
        result = await scan_single_device(
            ip_address=test_ip,
            username=username,
            password=password,
            network_id=network_id,
            company_id=company_id,
            device_type=device_type
        )
        
        print(f"✅ Scan completed successfully")
        print(f"Result: {result}")
        
    except Exception as e:
        print(f"❌ Scan failed: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_direct_scan()) 