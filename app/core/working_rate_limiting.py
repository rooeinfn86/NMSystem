"""
Working Rate Limiting Implementation
Uses FastAPI's dependency injection system properly
"""

import time
import logging
from typing import Dict, Any
from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

# Simple in-memory rate limiting storage
rate_limit_storage = defaultdict(list)
rate_limit_lock = threading.Lock()

# Rate limiting configuration
RATE_LIMITS = {
    "auth": {
        "login": {"requests": 5, "window": 60},  # 5 requests per minute
        "register": {"requests": 3, "window": 3600},  # 3 requests per hour
    },
    "api": {
        "ai_commands": {"requests": 20, "window": 60},  # 20 requests per minute
        "device_commands": {"requests": 30, "window": 60},  # 30 requests per minute
        "config_operations": {"requests": 15, "window": 60},  # 15 requests per minute
        "rollback_operations": {"requests": 10, "window": 60},  # 10 requests per minute
        "snapshot_operations": {"requests": 10, "window": 60},  # 10 requests per minute
    }
}

def get_client_ip(request: Request) -> str:
    """Get client IP address"""
    # Get the real IP from headers (for proxy/load balancer scenarios)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Fallback to direct IP
    return request.client.host if request.client else "unknown"

def check_rate_limit(client_ip: str, endpoint_type: str, endpoint_name: str) -> bool:
    """
    Check if request is within rate limit
    
    Returns:
        True if request is allowed, False if rate limited
    """
    with rate_limit_lock:
        # Get rate limit configuration
        limits = RATE_LIMITS.get(endpoint_type, {}).get(endpoint_name, {"requests": 100, "window": 60})
        max_requests = limits["requests"]
        window_seconds = limits["window"]
        
        # Create key for this client and endpoint
        key = f"{client_ip}:{endpoint_type}:{endpoint_name}"
        
        # Get current timestamp
        current_time = time.time()
        
        # Clean old entries (older than window)
        if key in rate_limit_storage:
            rate_limit_storage[key] = [
                timestamp for timestamp in rate_limit_storage[key]
                if current_time - timestamp < window_seconds
            ]
        
        # Check if we're at the limit
        if len(rate_limit_storage[key]) >= max_requests:
            return False
        
        # Add current request
        rate_limit_storage[key].append(current_time)
        return True

def rate_limit_dependency(endpoint_type: str, endpoint_name: str = "default"):
    """
    Rate limiting dependency that can be used with FastAPI's Depends()
    
    Args:
        endpoint_type: Type of endpoint (auth, api, admin, websocket, health)
        endpoint_name: Specific endpoint name
    """
    def dependency(request: Request):
        # Get client IP
        client_ip = get_client_ip(request)
        
        # Check rate limit
        if not check_rate_limit(client_ip, endpoint_type, endpoint_name):
            # Rate limit exceeded
            limits = RATE_LIMITS.get(endpoint_type, {}).get(endpoint_name, {"requests": 100, "window": 60})
            
            logger.warning(
                f"Rate limit exceeded for {client_ip} on {endpoint_type}/{endpoint_name}: "
                f"{limits['requests']} requests per {limits['window']} seconds"
            )
            
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Limit: {limits['requests']} requests per {limits['window']} seconds"
            )
        
        # Log successful request
        logger.info(f"Rate limit check passed for {client_ip} on {endpoint_type}/{endpoint_name}")
        return True
    
    return dependency

def get_rate_limit_stats_working(client_ip: str) -> Dict[str, Any]:
    """Get rate limiting statistics"""
    with rate_limit_lock:
        stats = {
            "client_ip": client_ip,
            "active_limits": 0,
            "limits": {}
        }
        
        # Count active limits for this client
        for key, timestamps in rate_limit_storage.items():
            if key.startswith(f"{client_ip}:"):
                stats["active_limits"] += 1
                endpoint = key.split(":", 2)[2]  # Get endpoint name
                stats["limits"][endpoint] = len(timestamps)
        
        return stats

def cleanup_old_entries():
    """Clean up old rate limit entries"""
    with rate_limit_lock:
        current_time = time.time()
        for key in list(rate_limit_storage.keys()):
            # Keep only entries from the last hour
            rate_limit_storage[key] = [
                timestamp for timestamp in rate_limit_storage[key]
                if current_time - timestamp < 3600
            ]
            # Remove empty entries
            if not rate_limit_storage[key]:
                del rate_limit_storage[key]

# Export for use in other modules
__all__ = [
    "rate_limit_dependency",
    "get_rate_limit_stats_working",
    "RATE_LIMITS",
    "cleanup_old_entries"
] 