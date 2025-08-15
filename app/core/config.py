from pydantic_settings import BaseSettings
from typing import List, Optional
import os
from dotenv import load_dotenv
from .secret_manager import get_secret_with_fallback

load_dotenv()

class Settings(BaseSettings):
    PROJECT_NAME: str = "Cisco Config Assistant"
    API_V1_STR: str = "/api/v1"
    
    # Use Secret Manager with environment variable fallback
    SECRET_KEY: str = get_secret_with_fallback(
        "backend-secret-key", "SECRET_KEY", "change-this-secret-in-production"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",  # Development frontend
        "http://localhost:3001",  # Alternative development port
        "https://cisco-config-ui-650612333424.us-central1.run.app",  # Production frontend (if deployed)
        "https://my-frontend-650612333424.us-central1.run.app",  # Alternative production frontend
    ]

    # Database settings - prefer Railway's DATABASE_URL or DATABASE_PUBLIC_URL
    DATABASE_URL: str = (
        os.getenv("DATABASE_URL")
        or os.getenv("DATABASE_PUBLIC_URL")
        or "postgresql+psycopg2://postgres:REDACTED@localhost:5432/cisco_ai"
    )
    
    # Security
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    
    # OpenAI Configuration - use Secret Manager with env fallback
    OPENAI_API_KEY: str = get_secret_with_fallback("openai-api-key", "OPENAI_API_KEY", "")
    
    # SSH Configuration
    SSH_TIMEOUT: int = int(os.getenv("SSH_TIMEOUT", "30"))
    SSH_PORT: int = int(os.getenv("SSH_PORT", "22"))
    
    # File Upload Configuration
    UPLOAD_DIR: str = os.getenv("UPLOAD_DIR", "uploads")
    MAX_UPLOAD_SIZE: int = int(os.getenv("MAX_UPLOAD_SIZE", "10485760"))
    
    # Application Settings
    DEBUG: bool = os.getenv("DEBUG", "True").lower() == "true"
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "app.log")

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings() 