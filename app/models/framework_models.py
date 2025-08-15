from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from app.core.database import Base
from datetime import datetime
from .compliance_base import BaseComplianceReport, BaseComplianceFinding, get_current_time

class BaseBenchmark:
    id = Column(Integer, primary_key=True, index=True)
    benchmark_id = Column(String(50), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    recommendation = Column(Text)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time)

class NISTBenchmark(BaseBenchmark, Base):
    __tablename__ = "nist_benchmarks"
    control_statement = Column(Text)
    control_family = Column(String(100))
    control_number = Column(String(50))
    control_enhancement = Column(String(50))
    supplemental_guidance = Column(Text)
    severity = Column(String(50))

class ISO27001Benchmark(BaseBenchmark, Base):
    __tablename__ = "iso27001_benchmarks"
    control_statement = Column(Text)
    control_family = Column(String(100))
    control_number = Column(String(50))
    version = Column(String(20))

class PCIDSSBenchmark(BaseBenchmark, Base):
    __tablename__ = "pci_dss_benchmarks"
    control_statement = Column(Text)
    control_family = Column(String(100))
    control_number = Column(String(50))
    version = Column(String(20))

class NISTComplianceReport(Base):
    __tablename__ = "nist_compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    report_name = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_type = Column(String(255), nullable=False)
    status = Column(String(50), nullable=False, default="Processing")
    framework_type = Column(String(50), nullable=False)
    compliance_type = Column(String(50), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time)

    findings = relationship("NISTComplianceFinding", back_populates="report")

class ISO27001ComplianceReport(BaseComplianceReport, Base):
    __tablename__ = "iso27001_compliance_reports"
    findings = relationship("ISO27001ComplianceFinding", back_populates="report", foreign_keys="[ISO27001ComplianceFinding.report_id]")

class PCIDSSComplianceReport(BaseComplianceReport, Base):
    __tablename__ = "pci_dss_compliance_reports"
    compliance_type = Column(String(50), nullable=False, default="PCIDSS")
    findings = relationship("PCIDSSComplianceFinding", back_populates="report", foreign_keys="[PCIDSSComplianceFinding.report_id]")

class NISTComplianceFinding(Base):
    __tablename__ = "nist_compliance_findings"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("nist_compliance_reports.id"), nullable=False)
    benchmark_id = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False)
    confidence_score = Column(Float, nullable=True)
    details = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=get_current_time)
    updated_at = Column(DateTime(timezone=True), default=get_current_time, onupdate=get_current_time)

    report = relationship("NISTComplianceReport", back_populates="findings")

class ISO27001ComplianceFinding(BaseComplianceFinding, Base):
    __tablename__ = "iso27001_compliance_findings"
    report_id = Column(Integer, ForeignKey("iso27001_compliance_reports.id"))
    report = relationship("ISO27001ComplianceReport", back_populates="findings")

class PCIDSSComplianceFinding(BaseComplianceFinding, Base):
    __tablename__ = "pci_dss_compliance_findings"
    report_id = Column(Integer, ForeignKey("pci_dss_compliance_reports.id"))
    report = relationship("PCIDSSComplianceReport", back_populates="findings") 