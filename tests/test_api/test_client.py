"""
Test API client functionality
"""

import asyncio
import httpx
import pytest
import os

# Test configuration
BASE_URL = "http://localhost:8000"
TEST_USERNAME = os.getenv("TEST_USERNAME", "testuser")
TEST_PASSWORD = os.getenv("TEST_PASSWORD", "test_password")

async def test_api_client():
    """Test basic API client functionality"""
    
    async with httpx.AsyncClient() as client:
        
        # Test health endpoint
        health_response = await client.get(f"{BASE_URL}/health")
        print(f"Health check status: {health_response.status_code}")
        
        if health_response.status_code == 200:
            print("✅ API is healthy")
        else:
            print("❌ API health check failed")
            return
        
        # Test login endpoint
        login_data = {
            "username": TEST_USERNAME,
            "password": TEST_PASSWORD,
        }
        
        login_response = await client.post(
            f"{BASE_URL}/api/v1/auth/login",
            json=login_data
        )
        
        print(f"Login status: {login_response.status_code}")
        
        if login_response.status_code == 200:
            token_data = login_response.json()
            access_token = token_data.get("access_token")
            print("✅ Login successful")
            print(f"Token type: {token_data.get('token_type')}")
            
            # Test authenticated endpoint
            headers = {"Authorization": f"Bearer {access_token}"}
            
            profile_response = await client.get(
                f"{BASE_URL}/api/v1/users/me",
                headers=headers
            )
            
            print(f"Profile status: {profile_response.status_code}")
            
            if profile_response.status_code == 200:
                print("✅ Authenticated request successful")
                user_data = profile_response.json()
                print(f"User: {user_data.get('username')}")
            else:
                print("❌ Authenticated request failed")
        else:
            print("❌ Login failed")
            print(f"Response: {login_response.text}")

if __name__ == "__main__":
    asyncio.run(test_api_client()) 