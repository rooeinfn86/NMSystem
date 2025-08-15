from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user
from app.schemas.user import User
from app.schemas.compliance import (
    ComplianceScan,
    ComplianceFinding,
    ComplianceFile
)
from app.crud import compliance as crud
from app.services.nist_engine.report_generator import ReportGenerator
from app.services.nist_engine.dashboard_service import DashboardService
from pathlib import Path
import os

router = APIRouter()

# Create reports directory if it doesn't exist
REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)

@router.get("/scans/{scan_id}/report/pdf")
async def generate_pdf_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a PDF report for a compliance scan.
    """
    # Get scan and verify access
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=scan.organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # Get findings
    findings = crud.get_compliance_findings(db=db, scan_id=scan_id)
    
    # Convert findings to dict format
    findings_data = []
    for finding in findings:
        findings_data.append({
            "control_id": finding.control_id,
            "status": finding.status,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence
        })
    
    # Generate report
    report_generator = ReportGenerator()
    report_path = report_generator.generate_pdf_report(
        scan_id=scan.id,
        scan_name=scan.name,
        findings=findings_data,
        metrics={
            "total_controls": scan.total_controls,
            "compliant": scan.compliant_controls,
            "non_compliant": scan.non_compliant_controls,
            "not_applicable": scan.not_applicable_controls,
            "not_assessed": scan.not_assessed_controls
        },
        output_path=str(REPORTS_DIR)
    )
    
    return {"report_path": report_path}

@router.get("/scans/{scan_id}/report/excel")
async def generate_excel_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate an Excel report for a compliance scan.
    """
    # Get scan and verify access
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=scan.organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # Get findings
    findings = crud.get_compliance_findings(db=db, scan_id=scan_id)
    
    # Convert findings to dict format
    findings_data = []
    for finding in findings:
        findings_data.append({
            "control_id": finding.control_id,
            "status": finding.status,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence
        })
    
    # Generate report
    report_generator = ReportGenerator()
    report_path = report_generator.generate_excel_report(
        scan_id=scan.id,
        scan_name=scan.name,
        findings=findings_data,
        metrics={
            "total_controls": scan.total_controls,
            "compliant": scan.compliant_controls,
            "non_compliant": scan.non_compliant_controls,
            "not_applicable": scan.not_applicable_controls,
            "not_assessed": scan.not_assessed_controls
        },
        output_path=str(REPORTS_DIR)
    )
    
    return {"report_path": report_path}

@router.get("/scans/{scan_id}/report/json")
async def generate_json_report(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a JSON report for a compliance scan.
    """
    # Get scan and verify access
    scan = crud.get_compliance_scan(db=db, scan_id=scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=scan.organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    # Get findings
    findings = crud.get_compliance_findings(db=db, scan_id=scan_id)
    
    # Convert findings to dict format
    findings_data = []
    for finding in findings:
        findings_data.append({
            "control_id": finding.control_id,
            "status": finding.status,
            "description": finding.description,
            "recommendation": finding.recommendation,
            "confidence": finding.confidence
        })
    
    # Generate report
    report_generator = ReportGenerator()
    report_path = report_generator.generate_json_report(
        scan_id=scan.id,
        scan_name=scan.name,
        findings=findings_data,
        metrics={
            "total_controls": scan.total_controls,
            "compliant": scan.compliant_controls,
            "non_compliant": scan.non_compliant_controls,
            "not_applicable": scan.not_applicable_controls,
            "not_assessed": scan.not_assessed_controls
        },
        output_path=str(REPORTS_DIR)
    )
    
    return {"report_path": report_path}

@router.get("/dashboard/metrics")
async def get_dashboard_metrics(
    organization_id: int,
    days: Optional[int] = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get dashboard metrics for an organization.
    """
    # Verify access
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this organization")
    
    # Get metrics
    dashboard_service = DashboardService(db=db)
    metrics = dashboard_service.get_organization_metrics(
        organization_id=organization_id,
        days=days
    )
    
    return metrics

@router.get("/dashboard/trends")
async def get_dashboard_trends(
    organization_id: int,
    days: Optional[int] = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get compliance trends for an organization.
    """
    # Verify access
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this organization")
    
    # Get trends
    dashboard_service = DashboardService(db=db)
    trends = dashboard_service.get_trend_analysis(
        organization_id=organization_id,
        days=days
    )
    
    return trends

@router.get("/dashboard/controls")
async def get_dashboard_controls(
    organization_id: int,
    days: Optional[int] = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get control analysis for an organization.
    """
    # Verify access
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this organization")
    
    # Get control analysis
    dashboard_service = DashboardService(db=db)
    controls = dashboard_service.get_control_analysis(
        organization_id=organization_id,
        days=days
    )
    
    return controls

@router.get("/dashboard/risks")
async def get_dashboard_risks(
    organization_id: int,
    days: Optional[int] = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get risk analysis for an organization.
    """
    # Verify access
    if not crud.verify_user_access(db=db, user_id=current_user.id, organization_id=organization_id):
        raise HTTPException(status_code=403, detail="Not authorized to access this organization")
    
    # Get risk analysis
    dashboard_service = DashboardService(db=db)
    risks = dashboard_service.get_risk_analysis(
        organization_id=organization_id,
        days=days
    )
    
    return risks 