"""
Rate Limiting Configuration
Centralized configuration for rate limiting settings
"""

import os
from typing import Dict, Any

# Redis configuration
REDIS_CONFIG = {
    "host": os.getenv("REDIS_HOST", "localhost"),
    "port": int(os.getenv("REDIS_PORT", "6379")),
    "db": int(os.getenv("REDIS_DB", "0")),
    "password": os.getenv("REDIS_PASSWORD", None),
    "decode_responses": True,
    "socket_connect_timeout": 1,
    "socket_timeout": 1,
    "retry_on_timeout": True
}

# Rate limiting configuration for different endpoint types
RATE_LIMIT_CONFIG = {
    # Authentication endpoints - strict limits to prevent brute force
    "auth": {
        "login": "5 per minute",           # 5 login attempts per minute
        "register": "3 per hour",          # 3 registrations per hour
        "password_reset": "3 per hour",    # 3 password resets per hour
        "token_refresh": "10 per minute"   # 10 token refreshes per minute
    },
    
    # API endpoints - moderate limits
    "api": {
        "default": "100 per minute",       # 100 requests per minute
        "ai_commands": "20 per minute",    # 20 AI commands per minute
        "device_commands": "30 per minute", # 30 device commands per minute
        "config_operations": "15 per minute", # 15 config operations per minute
        "rollback_operations": "10 per minute", # 10 rollback operations per minute
        "snapshot_operations": "10 per minute"  # 10 snapshot operations per minute
    },
    
    # Admin endpoints - higher limits for admin users
    "admin": {
        "default": "200 per minute",       # 200 requests per minute for admins
        "user_management": "50 per minute", # 50 user management operations per minute
        "system_operations": "30 per minute" # 30 system operations per minute
    },
    
    # WebSocket endpoints - higher limits for real-time communication
    "websocket": {
        "default": "100 per minute",       # 100 WebSocket connections per minute
        "agent_websocket": "50 per minute" # 50 agent WebSocket connections per minute
    },
    
    # Health and monitoring endpoints - very high limits
    "health": {
        "default": "1000 per minute"       # 1000 health checks per minute
    }
}

# Adaptive rate limiting multipliers for different user roles
ADAPTIVE_RATE_LIMITS = {
    "superadmin": {
        "api": 3.0,    # 3x higher limits for superadmin
        "admin": 2.5,  # 2.5x higher limits for superadmin
        "auth": 1.5    # 1.5x higher limits for superadmin
    },
    "admin": {
        "api": 2.0,    # 2x higher limits for admin
        "admin": 2.0,  # 2x higher limits for admin
        "auth": 1.2    # 1.2x higher limits for admin
    },
    "company_admin": {
        "api": 1.5,    # 1.5x higher limits for company admin
        "admin": 1.5,  # 1.5x higher limits for company admin
        "auth": 1.1    # 1.1x higher limits for company admin
    }
}

# Rate limiting behavior configuration
RATE_LIMIT_BEHAVIOR = {
    "enable_adaptive_limits": True,        # Enable adaptive limits based on user role
    "enable_redis": True,                  # Enable Redis for distributed rate limiting
    "enable_logging": True,                # Enable rate limit event logging
    "enable_monitoring": True,             # Enable rate limit monitoring endpoints
    "block_on_exceed": True,              # Block requests when rate limit exceeded
    "retry_after_seconds": 60,            # Retry after 60 seconds when rate limited
    "max_retry_attempts": 3,              # Maximum retry attempts for failed requests
}

# Rate limiting monitoring configuration
MONITORING_CONFIG = {
    "enable_stats_endpoint": True,         # Enable /rate-limit-stats endpoint
    "enable_detailed_logging": True,      # Enable detailed rate limit logging
    "log_successful_requests": False,      # Log successful requests (can be verbose)
    "log_exceeded_requests": True,        # Log rate limit exceeded requests
    "alert_threshold": 0.8,               # Alert when 80% of rate limit is reached
}

# Security configuration for rate limiting
SECURITY_CONFIG = {
    "trust_proxy_headers": True,           # Trust X-Forwarded-For headers
    "use_real_ip": True,                  # Use real IP address for rate limiting
    "whitelist_ips": [],                  # IP addresses to whitelist (exempt from rate limiting)
    "blacklist_ips": [],                  # IP addresses to blacklist (always rate limited)
    "enable_ip_geolocation": False,       # Enable IP geolocation for advanced rate limiting
}

def get_rate_limit_config() -> Dict[str, Any]:
    """Get complete rate limiting configuration"""
    return {
        "redis": REDIS_CONFIG,
        "limits": RATE_LIMIT_CONFIG,
        "adaptive": ADAPTIVE_RATE_LIMITS,
        "behavior": RATE_LIMIT_BEHAVIOR,
        "monitoring": MONITORING_CONFIG,
        "security": SECURITY_CONFIG
    }

def validate_rate_limit_config() -> bool:
    """Validate rate limiting configuration"""
    try:
        # Validate Redis configuration
        if RATE_LIMIT_BEHAVIOR["enable_redis"]:
            if not REDIS_CONFIG["host"]:
                return False
        
        # Validate rate limit formats
        for endpoint_type, limits in RATE_LIMIT_CONFIG.items():
            for endpoint_name, limit_str in limits.items():
                if not isinstance(limit_str, str):
                    return False
                # Basic format validation: "number per time_unit"
                parts = limit_str.split(" per ")
                if len(parts) != 2:
                    return False
                try:
                    int(parts[0])
                except ValueError:
                    return False
        
        return True
    except Exception:
        return False

def get_environment_specific_config() -> Dict[str, Any]:
    """Get environment-specific rate limiting configuration"""
    env = os.getenv("ENVIRONMENT", "development")
    
    if env == "production":
        # Stricter limits in production
        return {
            "auth": {
                "login": "3 per minute",      # Stricter login limits
                "register": "1 per hour",     # Stricter registration limits
            },
            "api": {
                "default": "50 per minute",   # Stricter API limits
                "ai_commands": "10 per minute", # Stricter AI command limits
            }
        }
    elif env == "staging":
        # Moderate limits in staging
        return {
            "auth": {
                "login": "10 per minute",     # More lenient for testing
                "register": "5 per hour",     # More lenient for testing
            },
            "api": {
                "default": "200 per minute",  # More lenient for testing
                "ai_commands": "50 per minute", # More lenient for testing
            }
        }
    else:
        # Development environment - very lenient
        return {
            "auth": {
                "login": "100 per minute",    # Very lenient for development
                "register": "50 per hour",    # Very lenient for development
            },
            "api": {
                "default": "1000 per minute", # Very lenient for development
                "ai_commands": "200 per minute", # Very lenient for development
            }
        } 