from fastapi import HTTPException, status, Depends
from typing import Dict, Optional
from app.models.base import User, Device
from sqlalchemy.orm import Session
from app.core.dependencies import get_current_user

def check_permission(user: Dict, required_roles: list) -> bool:
    """Check if user has one of the required roles."""
    # Full Control users have access to everything except team management
    if user["role"] == "full_control":
        if "company_admin" in required_roles and "team_management" in required_roles:
            return False
        return True
    return user["role"] in required_roles

def check_organization_access(user: Dict, db: Session, organization_id: int) -> bool:
    """Check if user has access to an organization."""
    # Full Control users have access to all organizations
    if user["role"] == "full_control":
        return True
    
    if user["role"] in ["superadmin", "company_admin"]:
        return True
    
    # For engineers and viewers, check explicit access
    user_obj = db.query(User).filter(User.id == user["user_id"]).first()
    if not user_obj:
        return False
        
    return any(access.organization_id == organization_id for access in user_obj.org_access)

def check_network_access(user: Dict, db: Session, network_id: int) -> bool:
    """Check if user has access to a network."""
    # Full Control users have access to all networks
    if user["role"] == "full_control":
        return True
    
    if user["role"] in ["superadmin", "company_admin"]:
        return True
    
    # For engineers and viewers, check explicit access
    user_obj = db.query(User).filter(User.id == user["user_id"]).first()
    if not user_obj:
        return False
        
    return any(access.network_id == network_id for access in user_obj.net_access)

def check_device_access(user: Dict, db: Session, device_id: int) -> bool:
    """Check if user has access to a device."""
    # Full Control users have access to all devices
    if user["role"] == "full_control":
        return True
    
    if user["role"] in ["superadmin", "company_admin"]:
        return True
    
    # For engineers and viewers, check network access
    user_obj = db.query(User).filter(User.id == user["user_id"]).first()
    if not user_obj:
        return False
        
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        return False
        
    return any(access.network_id == device.network_id for access in user_obj.net_access)

def check_feature_access(user: Dict, feature_name: str) -> bool:
    """Check if user has access to a feature."""
    # Full Control role has access to all features except team management
    if user["role"] == "full_control":
        if feature_name == "team_management":
            return False
        return True
        
    # Company admin has access to all features
    if user["role"] == "company_admin":
        return True
        
    # Superadmin has access to everything
    if user["role"] == "superadmin":
        return True
        
    # For other roles, check explicit feature access
    user_obj = db.query(User).filter(User.id == user["user_id"]).first()
    if not user_obj:
        return False
        
    return any(access.feature_name == feature_name for access in user_obj.feature_access)

def require_roles(roles: list):
    """Decorator to require specific roles for an endpoint."""
    def decorator(func):
        async def wrapper(*args, current_user: Dict = Depends(get_current_user), **kwargs):
            if not check_permission(current_user, roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You don't have permission to perform this action"
                )
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator 