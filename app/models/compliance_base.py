from sqlalchemy import Column, Integer, String, DateTime, Float, Text, Boolean
from sqlalchemy.orm import relationship
from ..core.database import Base
from datetime import datetime
import pytz

def get_current_time():
    # Get current time in local timezone
    local_tz = pytz.timezone('America/Los_Angeles')
    local_now = datetime.now(local_tz)
    return local_now

def convert_to_local_time(utc_time):
    # Convert UTC to local time (PST/PDT)
    local_tz = pytz.timezone('America/Los_Angeles')
    if utc_time.tzinfo is None:
        utc_time = pytz.UTC.localize(utc_time)
    return utc_time.astimezone(local_tz)

class BaseComplianceReport(Base):
    __abstract__ = True
    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    report_name = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_type = Column(String(50), nullable=False)
    status = Column(String(50), nullable=False, default="Processing")
    framework_type = Column(String(50), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time)

    def get_local_created_at(self):
        return convert_to_local_time(self.created_at)

    def get_local_updated_at(self):
        return convert_to_local_time(self.updated_at)

class BaseComplianceFinding(Base):
    __abstract__ = True
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, nullable=False)
    benchmark_id = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False)
    confidence_score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time)

class BaseBenchmark(Base):
    __abstract__ = True
    id = Column(Integer, primary_key=True, index=True)
    benchmark_id = Column(String(50), nullable=False, unique=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time) 