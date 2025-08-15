from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Text, Boolean
from sqlalchemy.sql import func
from datetime import datetime
from app.core.database import Base


class LearnedPatterns(Base):
    """Store learned SNMP patterns for different device types"""
    __tablename__ = "learned_patterns"
    
    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String(50), nullable=False, index=True)
    model = Column(String(100), nullable=False, index=True)
    data_category = Column(String(50), nullable=False, index=True)  # cpu, memory, temperature
    successful_oids = Column(JSON, nullable=False)  # List of successful OIDs
    oid_patterns = Column(JSON, nullable=True)  # Regex patterns that worked
    success_rate = Column(Float, default=0.0)  # Success rate percentage
    discovery_count = Column(Integer, default=0)  # Number of times this pattern was used
    last_successful = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    is_active = Column(Boolean, default=True)


class DiscoveryStrategies(Base):
    """Track performance of different discovery strategies per vendor"""
    __tablename__ = "discovery_strategies"
    
    id = Column(Integer, primary_key=True, index=True)
    vendor = Column(String(50), nullable=False, index=True)
    model = Column(String(100), nullable=True, index=True)
    strategy_name = Column(String(50), nullable=False, index=True)  # snmp_walk, pattern, mib
    data_category = Column(String(50), nullable=False, index=True)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    avg_discovery_time = Column(Float, default=0.0)  # Average time in seconds
    last_used = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    is_preferred = Column(Boolean, default=False)  # Mark as preferred strategy


class DeviceCapabilities(Base):
    """Store discovered device capabilities and sensor information"""
    __tablename__ = "device_capabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    device_ip = Column(String(45), nullable=False, index=True)
    vendor = Column(String(50), nullable=False, index=True)
    model = Column(String(100), nullable=False, index=True)
    sys_object_id = Column(String(200), nullable=True)
    sys_descr = Column(Text, nullable=True)
    capabilities = Column(JSON, nullable=False)  # Available sensors and features
    discovered_sensors = Column(JSON, nullable=True)  # Detailed sensor information
    last_discovery = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())


class DiscoveryHistory(Base):
    """Track discovery attempts and results for analysis"""
    __tablename__ = "discovery_history"
    
    id = Column(Integer, primary_key=True, index=True)
    device_ip = Column(String(45), nullable=False, index=True)
    vendor = Column(String(50), nullable=False, index=True)
    model = Column(String(100), nullable=False, index=True)
    data_category = Column(String(50), nullable=False, index=True)
    strategy_used = Column(String(50), nullable=False)
    oids_tried = Column(JSON, nullable=True)  # List of OIDs attempted
    successful_oids = Column(JSON, nullable=True)  # List of successful OIDs
    discovery_time = Column(Float, nullable=True)  # Time taken in seconds
    success = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    discovered_at = Column(DateTime, default=func.now())


class AdaptiveLearningConfig(Base):
    """Configuration for the adaptive learning system"""
    __tablename__ = "adaptive_learning_config"
    
    id = Column(Integer, primary_key=True, index=True)
    config_key = Column(String(100), nullable=False, unique=True, index=True)
    config_value = Column(JSON, nullable=False)
    description = Column(Text, nullable=True)
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now()) 