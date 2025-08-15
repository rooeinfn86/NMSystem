from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.compliance import ComplianceScan, ComplianceFinding, ComplianceFile
from app.models.base import UserOrganizationAccess
from app.schemas.compliance import (
    ComplianceScanCreate,
    ComplianceScanUpdate,
    ComplianceFindingCreate,
    ComplianceFileCreate
)

def verify_user_access(db: Session, user_id: int, organization_id: int) -> bool:
    """
    Verify if a user has access to an organization.
    """
    return db.query(UserOrganizationAccess).filter(
        UserOrganizationAccess.user_id == user_id,
        UserOrganizationAccess.organization_id == organization_id
    ).first() is not None

def create_compliance_scan(db: Session, scan: ComplianceScanCreate) -> ComplianceScan:
    db_scan = ComplianceScan(
        name=scan.name,
        compliance_type=scan.compliance_type,
        organization_id=scan.organization_id,
        status="pending"
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)
    return db_scan

def get_compliance_scan(db: Session, scan_id: int) -> Optional[ComplianceScan]:
    return db.query(ComplianceScan).filter(ComplianceScan.id == scan_id).first()

def get_compliance_scans(
    db: Session,
    organization_id: int,
    skip: int = 0,
    limit: int = 100
) -> List[ComplianceScan]:
    return (
        db.query(ComplianceScan)
        .filter(ComplianceScan.organization_id == organization_id)
        .offset(skip)
        .limit(limit)
        .all()
    )

def update_compliance_scan(
    db: Session,
    scan_id: int,
    scan: ComplianceScanUpdate
) -> Optional[ComplianceScan]:
    db_scan = get_compliance_scan(db, scan_id)
    if db_scan:
        for field, value in scan.dict(exclude_unset=True).items():
            setattr(db_scan, field, value)
        db.commit()
        db.refresh(db_scan)
    return db_scan

def delete_compliance_scan(db: Session, scan_id: int) -> bool:
    db_scan = get_compliance_scan(db, scan_id)
    if db_scan:
        db.delete(db_scan)
        db.commit()
        return True
    return False

def create_compliance_finding(
    db: Session,
    finding: ComplianceFindingCreate,
    scan_id: int
) -> ComplianceFinding:
    db_finding = ComplianceFinding(
        scan_id=scan_id,
        control_id=finding.control_id,
        status=finding.status,
        description=finding.description,
        recommendation=finding.recommendation
    )
    db.add(db_finding)
    db.commit()
    db.refresh(db_finding)
    return db_finding

def get_compliance_findings(
    db: Session,
    scan_id: int,
    skip: int = 0,
    limit: int = 100
) -> List[ComplianceFinding]:
    return (
        db.query(ComplianceFinding)
        .filter(ComplianceFinding.scan_id == scan_id)
        .offset(skip)
        .limit(limit)
        .all()
    )

def create_compliance_file(
    db: Session,
    file: ComplianceFileCreate,
    scan_id: int
) -> ComplianceFile:
    db_file = ComplianceFile(
        scan_id=scan_id,
        filename=file.filename,
        file_type=file.file_type,
        file_path=file.file_path
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    return db_file

def get_compliance_files(
    db: Session,
    scan_id: int,
    skip: int = 0,
    limit: int = 100
) -> List[ComplianceFile]:
    return (
        db.query(ComplianceFile)
        .filter(ComplianceFile.scan_id == scan_id)
        .offset(skip)
        .limit(limit)
        .all()
    )

def update_scan_metrics(db: Session, scan_id: int) -> Optional[ComplianceScan]:
    """
    Update scan metrics based on findings.
    """
    db_scan = get_compliance_scan(db, scan_id)
    if db_scan:
        findings = get_compliance_findings(db, scan_id)
        total_findings = len(findings)
        compliant = sum(1 for f in findings if f.status.lower() == "compliant")
        non_compliant = sum(1 for f in findings if f.status.lower() in ["non-compliant", "non_compliant"])
        
        db_scan.total_findings = total_findings
        db_scan.compliant = compliant
        db_scan.non_compliant = non_compliant
        db_scan.status = "completed"
        
        db.commit()
        db.refresh(db_scan)
    return db_scan 