from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

# Base schemas
class BaseComplianceReport(BaseModel):
    company_id: int
    user_id: int
    report_name: str
    original_filename: str
    file_path: str
    file_type: str
    status: str = "Processing"
    framework_type: str
    compliance_type: str
    version: int = 1
    is_deleted: bool = False
    created_at: datetime = datetime.utcnow()
    updated_at: datetime = datetime.utcnow()

class BaseComplianceReportResponse(BaseComplianceReport):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# NIST schemas
class NISTComplianceReportCreate(BaseComplianceReport):
    pass

class NISTComplianceReportResponse(BaseModel):
    id: int
    report_name: str
    compliance_type: str
    total_benchmarks: int
    compliant_count: int
    non_compliant_count: int
    not_applicable_count: int
    created_at: datetime
    status: str

class NISTComplianceFinding(BaseModel):
    id: int
    report_id: int
    benchmark_id: int
    status: str
    confidence_score: float
    details: str
    recommendation: str
    created_at: datetime

    class Config:
        orm_mode = True

# ISO 27001 schemas
class ISO27001ComplianceReportCreate(BaseComplianceReport):
    pass

class ISO27001ComplianceReportResponse(BaseComplianceReportResponse):
    pass

class ISO27001ComplianceFinding(BaseModel):
    id: int
    report_id: int
    benchmark_id: int
    status: str
    confidence_score: float
    details: str
    recommendation: str
    created_at: datetime

    class Config:
        orm_mode = True

# PCI DSS schemas
class PCIDSSComplianceReportCreate(BaseComplianceReport):
    pass

class PCIDSSComplianceReportResponse(BaseComplianceReportResponse):
    pass

class PCIDSSComplianceFinding(BaseModel):
    id: int
    report_id: int
    benchmark_id: int
    status: str
    confidence_score: float
    details: str
    recommendation: str
    created_at: datetime

    class Config:
        orm_mode = True

class ComplianceReportResponse(BaseModel):
    id: int
    report_name: str
    compliance_type: str
    total_benchmarks: int
    compliant_count: int
    non_compliant_count: int
    not_applicable_count: int
    status: str
    created_at: datetime

    class Config:
        orm_mode = True

class ComplianceFileBase(BaseModel):
    filename: str
    file_type: str
    file_path: str

class ComplianceFileCreate(ComplianceFileBase):
    pass

class ComplianceFile(ComplianceFileBase):
    id: int
    scan_id: int
    created_at: datetime

    class Config:
        from_attributes = True

class ComplianceFindingBase(BaseModel):
    control_id: str
    status: str
    description: Optional[str] = None
    recommendation: Optional[str] = None

class ComplianceFindingCreate(ComplianceFindingBase):
    pass

class ComplianceFinding(ComplianceFindingBase):
    id: int
    scan_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ComplianceScanBase(BaseModel):
    name: str
    network_id: int
    compliance_type: str

class ComplianceScanCreate(ComplianceScanBase):
    pass

class ComplianceScan(ComplianceScanBase):
    id: int
    organization_id: int
    status: str
    total_findings: int
    compliant: int
    non_compliant: int
    created_at: datetime
    updated_at: Optional[datetime]
    findings: List[ComplianceFinding] = []
    files: List[ComplianceFile] = []

    class Config:
        orm_mode = True

class ComplianceScanUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    total_findings: Optional[int] = None
    compliant: Optional[int] = None
    non_compliant: Optional[int] = None 