"""
Security Middleware
Enforces secure defaults and headers for all responses
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from typing import Callable
import re
import logging
from .secure_config import secure_settings
from pathlib import Path

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware that enforces security headers and other security measures"""
    
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.secure_settings = secure_settings
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        try:
            # Pre-process request
            if not self._is_request_secure(request):
                return Response(
                    content="Insecure request blocked",
                    status_code=400
                )
            
            # Call the next middleware/route handler
            response = await call_next(request)
            
            # Add security headers
            self._add_security_headers(response)
            
            # Validate response
            self._validate_response(response)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            return Response(
                content="Internal server error",
                status_code=500
            )
    
    def _is_request_secure(self, request: Request) -> bool:
        """Validate request security"""
        
        # Validate request size
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > secure_settings.upload.MAX_UPLOAD_SIZE:
            logger.warning(f"Request too large: {content_length} bytes")
            return False
        
        # Validate file uploads
        if request.headers.get("content-type", "").startswith("multipart/form-data"):
            return self._validate_file_upload(request)
        
        # Validate origin for CORS requests
        origin = request.headers.get("origin")
        if origin and not self._is_valid_origin(origin):
            logger.warning(f"Invalid origin: {origin}")
            return False
        
        return True
    
    def _validate_file_upload(self, request: Request) -> bool:
        """Validate file upload requests"""
        
        content_type = request.headers.get("content-type", "")
        if not content_type.startswith("multipart/form-data"):
            return True  # Not a file upload
        
        # Additional file upload validations will be done in the route handler
        # This is just a basic check
        return True
    
    def _is_valid_origin(self, origin: str) -> bool:
        """Validate CORS origin"""
        if not origin:
            return True
        
        allowed_origins = secure_settings.BACKEND_CORS_ORIGINS
        if not allowed_origins:
            return True  # No restrictions configured
        
        return origin in allowed_origins
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response"""
        
        # Get security headers from config
        security_headers = secure_settings.get_security_headers()
        
        # Add headers to response
        for header, value in security_headers.items():
            response.headers[header] = value
    
    def _validate_response(self, response: Response):
        """Validate response security"""
        
        # Check for sensitive data in response
        if not secure_settings.LOG_SENSITIVE_DATA:
            self._check_sensitive_data(response)
        
        # Validate content type
        content_type = response.headers.get("content-type", "")
        if not content_type:
            response.headers["content-type"] = "application/json; charset=utf-8"
    
    def _check_sensitive_data(self, response: Response):
        """Check for sensitive data in response"""
        
        # List of patterns that might indicate sensitive data
        sensitive_patterns = [
            r"password",
            r"secret",
            r"token",
            r"key",
            r"auth",
            r"credit_card",
            r"ssn",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # email
            r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b",  # SSN
            r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",  # credit card
        ]
        
        # Check response content
        try:
            body = response.body.decode() if hasattr(response, "body") else ""
            for pattern in sensitive_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    logger.warning(f"Possible sensitive data in response: {pattern}")
                    # You might want to redact or handle this differently
        except Exception as e:
            logger.error(f"Error checking response for sensitive data: {e}")

def create_security_middleware():
    """Create security middleware instance"""
    return SecurityMiddleware 