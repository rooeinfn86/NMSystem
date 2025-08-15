"""
Secure request models with comprehensive input validation.
"""
from pydantic import BaseModel, validator, Field
from typing import Optional
from app.utils.sanitizer import (
    validate_ip_address, 
    validate_username, 
    validate_password, 
    validate_command, 
    validate_config,
    sanitize_input
)
import logging

logger = logging.getLogger(__name__)

class SecureCommandRequest(BaseModel):
    """Secure command request with validation."""
    text: str = Field(..., min_length=1, max_length=1000, description="Command text")
    
    @validator('text')
    def validate_text(cls, v):
        if not v or not v.strip():
            raise ValueError("Command text cannot be empty")
        
        # Sanitize input
        sanitized = sanitize_input(v, max_length=1000)
        if sanitized != v:
            logger.warning(f"Command text was sanitized: {v} -> {sanitized}")
        
        return sanitized

class SecureApplyConfigRequest(BaseModel):
    """Secure configuration application request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    password: str = Field(..., min_length=1, max_length=100, description="SSH password")
    config: str = Field(..., min_length=1, max_length=2000, description="Configuration commands")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, error_msg = validate_password(v)
        if not is_valid:
            raise ValueError(f"Invalid password: {error_msg}")
        return v
    
    @validator('config')
    def validate_config(cls, v):
        is_valid, error_msg = validate_config(v)
        if not is_valid:
            raise ValueError(f"Invalid configuration: {error_msg}")
        return sanitize_input(v, max_length=2000)

class SecureSnapshotRequest(BaseModel):
    """Secure snapshot request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    config: str = Field(..., min_length=1, max_length=2000, description="Configuration to snapshot")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)
    
    @validator('config')
    def validate_config(cls, v):
        is_valid, error_msg = validate_config(v)
        if not is_valid:
            raise ValueError(f"Invalid configuration: {error_msg}")
        return sanitize_input(v, max_length=2000)

class SecurePreviewRequest(BaseModel):
    """Secure preview request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)

class SecureRollbackRequest(BaseModel):
    """Secure rollback request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    password: str = Field(..., min_length=1, max_length=100, description="SSH password")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, error_msg = validate_password(v)
        if not is_valid:
            raise ValueError(f"Invalid password: {error_msg}")
        return v

class SecureShowCommandRequest(BaseModel):
    """Secure show command request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    password: str = Field(..., min_length=1, max_length=100, description="SSH password")
    command: str = Field(..., min_length=1, max_length=500, description="Show command to execute")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, error_msg = validate_password(v)
        if not is_valid:
            raise ValueError(f"Invalid password: {error_msg}")
        return v
    
    @validator('command')
    def validate_command(cls, v):
        is_valid, error_msg = validate_command(v)
        if not is_valid:
            raise ValueError(f"Invalid command: {error_msg}")
        return sanitize_input(v, max_length=500)

class SecureAskAIShowRequest(BaseModel):
    """Secure AI show command request with validation."""
    ip: str = Field(..., description="Device IP address")
    username: str = Field(..., min_length=1, max_length=50, description="SSH username")
    password: str = Field(..., min_length=1, max_length=100, description="SSH password")
    question: str = Field(..., min_length=1, max_length=500, description="Question for AI")
    
    @validator('ip')
    def validate_ip(cls, v):
        is_valid, error_msg = validate_ip_address(v)
        if not is_valid:
            raise ValueError(f"Invalid IP address: {error_msg}")
        return v
    
    @validator('username')
    def validate_username(cls, v):
        is_valid, error_msg = validate_username(v)
        if not is_valid:
            raise ValueError(f"Invalid username: {error_msg}")
        return sanitize_input(v, max_length=50)
    
    @validator('password')
    def validate_password(cls, v):
        is_valid, error_msg = validate_password(v)
        if not is_valid:
            raise ValueError(f"Invalid password: {error_msg}")
        return v
    
    @validator('question')
    def validate_question(cls, v):
        if not v or not v.strip():
            raise ValueError("Question cannot be empty")
        
        # Sanitize input
        sanitized = sanitize_input(v, max_length=500)
        if sanitized != v:
            logger.warning(f"Question was sanitized: {v} -> {sanitized}")
        
        return sanitized 