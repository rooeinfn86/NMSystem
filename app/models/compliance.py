from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean
from sqlalchemy.orm import relationship
from app.core.database import Base
from .compliance_base import get_current_time

class ComplianceScan(Base):
    __tablename__ = "compliance_scans"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    network_id = Column(Integer, ForeignKey("networks.id"), nullable=False)
    compliance_type = Column(String)  # e.g., "NIST", "CIS"
    status = Column(String, default="pending")  # e.g., "pending", "completed", "failed"
    total_findings = Column(Integer, default=0)
    compliant = Column(Integer, default=0)  # Keep old column for backward compatibility
    non_compliant = Column(Integer, default=0)  # Keep old column for backward compatibility
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time, nullable=True)

    findings = relationship("ComplianceFinding", back_populates="scan", cascade="all, delete-orphan")
    files = relationship("ComplianceFile", back_populates="scan", cascade="all, delete-orphan")
    network = relationship("Network", back_populates="compliance_scans", lazy="joined")

    @property
    def compliant_findings(self):
        return self.compliant

    @compliant_findings.setter
    def compliant_findings(self, value):
        self.compliant = value

    @property
    def non_compliant_findings(self):
        return self.non_compliant

    @non_compliant_findings.setter
    def non_compliant_findings(self, value):
        self.non_compliant = value

class ComplianceFinding(Base):
    __tablename__ = "compliance_findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("compliance_scans.id"))
    file_id = Column(Integer, ForeignKey("compliance_files.id"), nullable=True)
    control_id = Column(String, index=True)
    status = Column(String)  # e.g., "compliant", "non_compliant", "not_applicable", "not_assessed"
    description = Column(Text)
    recommendation = Column(Text)
    confidence = Column(Float)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time, nullable=True)

    scan = relationship("ComplianceScan", back_populates="findings")
    file = relationship("ComplianceFile", back_populates="findings")

class ComplianceFile(Base):
    __tablename__ = "compliance_files"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("compliance_scans.id"))
    filename = Column(String)
    file_path = Column(String)
    file_type = Column(String)  # e.g., "pdf", "docx", "txt"
    is_analyzed = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time, nullable=True)

    scan = relationship("ComplianceScan", back_populates="files")
    findings = relationship("ComplianceFinding", back_populates="file") 