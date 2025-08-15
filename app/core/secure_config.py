"""
Secure Configuration Settings
Implements secure defaults and validation for all configuration settings
"""

from pydantic_settings import BaseSettings
from typing import List, Optional, Set, ClassVar
from pydantic import validator, Field, model_validator
import os
from dotenv import load_dotenv
from .secret_manager import get_secret_with_fallback
import re
import ssl

load_dotenv()

env_db_url = os.getenv("DATABASE_URL") or os.getenv("DATABASE_PUBLIC_URL")

class SecurityHeaders:
    """Security headers configuration with secure defaults"""
    
    # HSTS: Enforce HTTPS
    SECURE_HSTS_SECONDS = 31536000  # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # XSS Protection
    SECURE_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    
    # Content Security Policy
    CSP_DEFAULT_SRC = ["'self'"]
    CSP_SCRIPT_SRC = ["'self'"]
    CSP_STYLE_SRC = ["'self'"]
    CSP_IMG_SRC = ["'self'", "data:", "https:"]
    CSP_FONT_SRC = ["'self'", "https:", "data:"]
    CSP_CONNECT_SRC = ["'self'", "https://cisco-ai-backend-production.up.railway.app", "wss://cisco-ai-backend-production.up.railway.app"]
    
    # Frame Options
    SECURE_FRAME_DENY = True
    X_FRAME_OPTIONS = "DENY"
    
    # SSL/TLS
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

class DatabaseSettings:
    """Database configuration with secure defaults"""
    
    # Connection Settings
    MIN_CONNECTIONS = 5
    MAX_CONNECTIONS = 20
    CONNECTION_TIMEOUT = 30
    POOL_RECYCLE = 3600  # 1 hour
    
    # SSL/TLS
    SSL_MODE = "prefer"  # Use SSL if available, fall back to non-SSL
    
    # Query Settings
    STATEMENT_TIMEOUT = 30000  # 30 seconds
    POOL_PRE_PING = True

class UploadSettings:
    """File upload configuration with secure defaults"""
    
    # Basic Settings
    MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10MB
    ALLOWED_EXTENSIONS = {".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"}
    UPLOAD_DIR = "secure_uploads"
    
    # Security
    SCAN_UPLOADS = True
    MAX_FILENAME_LENGTH = 255
    SANITIZE_FILENAMES = True
    
    # Content Type Validation
    CONTENT_TYPE_WHITELIST = {
        "text/plain": [".txt"],
        "application/pdf": [".pdf"],
        "application/msword": [".doc"],
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [".docx"],
        "application/vnd.ms-excel": [".xls"],
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [".xlsx"],
        "text/csv": [".csv"]
    }

class SecureSettings(BaseSettings):
    """Main configuration with secure defaults"""
    
    PROJECT_NAME: str = "Cisco Config Assistant"
    API_V1_STR: str = "/api/v1"
    
    # Security Keys - Use Secret Manager with environment variable fallback
    SECRET_KEY: str = get_secret_with_fallback("backend-secret-key", "SECRET_KEY", "cisco-ai-super-secret-key-2024-production")
    
    # JWT Settings
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # 30 minutes
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_ALGORITHM: str = "HS256"
    
    # CORS Settings
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",  # Development frontend
        "http://localhost:3001",  # Alternative development port
        "http://127.0.0.1:3000",  # Development frontend (alternative)
        "http://127.0.0.1:3001",  # Alternative development port
        "http://localhost:3000",  # Chrome localhost
        "http://127.0.0.1:3000",  # Chrome 127.0.0.1
        "https://cisco-config-ui-650612333424.us-central1.run.app",  # Production frontend
        "https://my-frontend-650612333424.us-central1.run.app",  # Alternative production frontend
        "https://cisco-config-ui.onrender.com",  # Render deployment
        "https://cisco-config-ui.vercel.app",  # Vercel deployment
        "https://cisco-config-ui.netlify.app",  # Netlify deployment
    ]
    CORS_ALLOW_CREDENTIALS: bool = True
    CORS_ALLOW_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
    CORS_ALLOW_HEADERS: List[str] = [
        "Accept", "Accept-Language", "Content-Language", "Content-Type",
        "Authorization", "X-Requested-With", "Origin", "Access-Control-Request-Method",
        "Access-Control-Request-Headers", "Cache-Control", "Pragma"
    ]
    
    # Database URL - Prefer env DATABASE_URL/DATABASE_PUBLIC_URL, then Secret Manager, then local default
    DATABASE_URL: str = env_db_url or get_secret_with_fallback(
        "database-url", 
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:REDACTED@localhost:5432/cisco_ai"
    )
    
    # Individual database components for better security
    DB_USERNAME: str = get_secret_with_fallback("database-username", "DB_USERNAME", "postgres")
    DB_PASSWORD: str = get_secret_with_fallback("database-password", "DB_PASSWORD", "REDACTED")
    DB_HOST: str = get_secret_with_fallback("database-host", "DB_HOST", "localhost")
    DB_PORT: str = get_secret_with_fallback("database-port", "DB_PORT", "5432")
    DB_NAME: str = get_secret_with_fallback("database-name", "DB_NAME", "cisco_ai")
    
    # Construct database URL from components
    @property
    def DATABASE_URL_FROM_COMPONENTS(self) -> str:
        return f"postgresql+psycopg2://{self.DB_USERNAME}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
    
    # OpenAI Configuration - Use Secret Manager with environment variable fallback
    OPENAI_API_KEY: str = get_secret_with_fallback("openai-api-key", "OPENAI_API_KEY", "")
    
    # SSH Configuration
    SSH_TIMEOUT: int = 10  # 10 seconds
    SSH_PORT: int = 22
    SSH_KEY_PATH: Optional[str] = None
    SSH_STRICT_HOST_KEY_CHECKING: bool = True
    
    # Application Settings
    DEBUG: bool = os.getenv("DEBUG", "False").lower() == "true"  # Default to False for security
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: str = "app.log"
    SECURE_LOGS: bool = True
    LOG_SENSITIVE_DATA: bool = False
    
    # Import configurations as ClassVar to prevent Pydantic from treating them as fields
    security: ClassVar[SecurityHeaders] = SecurityHeaders()
    database: ClassVar[DatabaseSettings] = DatabaseSettings()
    upload: ClassVar[UploadSettings] = UploadSettings()
    
    # Additional fields that might come from environment variables
    ALGORITHM: Optional[str] = None
    UPLOAD_DIR: Optional[str] = None
    MAX_UPLOAD_SIZE: Optional[int] = None
    
    @model_validator(mode='before')
    @classmethod
    def validate_model(cls, values):
        """Validate and set additional fields"""
        # Set values from environment variables if not already set
        values['ALGORITHM'] = values.get('ALGORITHM', 'HS256')
        values['UPLOAD_DIR'] = values.get('UPLOAD_DIR', 'uploads')
        values['MAX_UPLOAD_SIZE'] = values.get('MAX_UPLOAD_SIZE', 10485760)
        return values
    
    @validator("BACKEND_CORS_ORIGINS")
    def validate_cors_origins(cls, v):
        """Validate CORS origins"""
        if not v:
            return []
        
        validated = []
        for origin in v:
            # Ensure origin is a valid URL
            if not re.match(r"^https?://[\w\-\.]+(:\d+)?$", origin):
                raise ValueError(f"Invalid CORS origin: {origin}")
            validated.append(origin)
        return validated
    
    @validator("DATABASE_URL")
    def validate_database_url(cls, v):
        """Validate database URL"""
        if "postgresql" not in v:
            raise ValueError("Only PostgreSQL databases are supported")
        return v
    
    @validator("SSH_PORT")
    def validate_ssh_port(cls, v):
        """Validate SSH port"""
        if not 1 <= v <= 65535:
            raise ValueError("SSH port must be between 1 and 65535")
        return v
    
    def get_database_args(self) -> dict:
        """Get secure database connection arguments"""
        return {
            "min_size": self.database.MIN_CONNECTIONS,
            "max_size": self.database.MAX_CONNECTIONS,
            "pool_recycle": self.database.POOL_RECYCLE,
            "pool_pre_ping": self.database.POOL_PRE_PING,
            "connect_args": {
                "sslmode": self.database.SSL_MODE,
                "options": f"-c statement_timeout={self.database.STATEMENT_TIMEOUT}"
            }
        }
    
    def get_security_headers(self) -> dict:
        """Get security headers for responses"""
        return {
            "Strict-Transport-Security": f"max-age={self.security.SECURE_HSTS_SECONDS}; includeSubDomains; preload",
            "X-Frame-Options": self.security.X_FRAME_OPTIONS,
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Content-Security-Policy": self._build_csp_header(),
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
    
    def _build_csp_header(self) -> str:
        """Build Content Security Policy header"""
        csp_parts = [
            f"default-src {' '.join(self.security.CSP_DEFAULT_SRC)}",
            f"script-src {' '.join(self.security.CSP_SCRIPT_SRC)}",
            f"style-src {' '.join(self.security.CSP_STYLE_SRC)}",
            f"img-src {' '.join(self.security.CSP_IMG_SRC)}",
            f"font-src {' '.join(self.security.CSP_FONT_SRC)}",
            f"connect-src {' '.join(self.security.CSP_CONNECT_SRC)}",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'"
        ]
        return "; ".join(csp_parts)
    
    class Config:
        env_file = ".env"
        case_sensitive = True

# Create settings instance
secure_settings = SecureSettings() 