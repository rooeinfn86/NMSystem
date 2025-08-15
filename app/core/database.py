# database.py
from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from .secure_config import secure_settings as settings
import logging

logger = logging.getLogger(__name__)

# Create engine with secure configuration
try:
    # Use DATABASE_URL from environment/secure settings (prefer Railway-provided URL)
    database_url = settings.DATABASE_URL
    logger.info("🔍 Using DATABASE_URL from environment/secure settings")
    
    engine = create_engine(
        database_url,
        pool_pre_ping=True,  # Basic connection health check
        pool_size=settings.database.MIN_CONNECTIONS,
        max_overflow=settings.database.MAX_CONNECTIONS - settings.database.MIN_CONNECTIONS,
        pool_recycle=settings.database.POOL_RECYCLE,
        connect_args={
            "connect_timeout": settings.database.CONNECTION_TIMEOUT,
            "sslmode": settings.database.SSL_MODE,
            "options": f"-c statement_timeout={settings.database.STATEMENT_TIMEOUT}"
        }
    )
    logger.info("✅ Database engine created with secure configuration")
except Exception as e:
    logger.error(f"❌ Failed to create database engine: {e}")
    raise

# Create session factory with secure defaults
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()

def get_db():
    """Get database session with proper error handling"""
    db = SessionLocal()
    try:
        # Test connection
        db.execute(text("SELECT 1"))
        yield db
    except Exception as e:
        logger.error(f"❌ Database connection error: {e}")
        raise
    finally:
        db.close()
