from typing import List, Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import pandas as pd
from sqlalchemy.orm import Session
from app.crud import compliance as crud
from app.schemas.compliance import ComplianceScan, ComplianceFinding

class DashboardService:
    def __init__(self, db: Session):
        self.db = db

    def get_organization_metrics(
        self,
        organization_id: int,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get compliance metrics for an organization.
        
        Args:
            organization_id: The organization ID
            days: Number of days to look back
            
        Returns:
            Dictionary of organization metrics
        """
        # Get scans for the organization
        scans = crud.get_compliance_scans(
            db=self.db,
            organization_id=organization_id
        )
        
        # Calculate metrics
        total_scans = len(scans)
        total_findings = 0
        compliant_findings = 0
        non_compliant_findings = 0
        
        for scan in scans:
            findings = crud.get_compliance_findings(
                db=self.db,
                scan_id=scan.id
            )
            total_findings += len(findings)
            compliant_findings += sum(1 for f in findings if f.status == "compliant")
            non_compliant_findings += sum(1 for f in findings if f.status == "non_compliant")
        
        # Calculate compliance score
        compliance_score = (
            (compliant_findings / total_findings * 100)
            if total_findings > 0 else 0
        )
        
        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "compliant_findings": compliant_findings,
            "non_compliant_findings": non_compliant_findings,
            "compliance_score": f"{compliance_score:.2f}%"
        }

    def get_trend_analysis(
        self,
        organization_id: int,
        days: int = 30
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get compliance trends over time.
        
        Args:
            organization_id: The organization ID
            days: Number of days to look back
            
        Returns:
            Dictionary of trend data
        """
        # Get scans for the organization
        scans = crud.get_compliance_scans(
            db=self.db,
            organization_id=organization_id
        )
        
        # Group scans by date
        daily_metrics = defaultdict(lambda: {
            "scans": 0,
            "findings": 0,
            "compliant": 0,
            "non_compliant": 0
        })
        
        for scan in scans:
            date = scan.created_at.date()
            findings = crud.get_compliance_findings(
                db=self.db,
                scan_id=scan.id
            )
            
            daily_metrics[date]["scans"] += 1
            daily_metrics[date]["findings"] += len(findings)
            daily_metrics[date]["compliant"] += sum(
                1 for f in findings if f.status == "compliant"
            )
            daily_metrics[date]["non_compliant"] += sum(
                1 for f in findings if f.status == "non_compliant"
            )
        
        # Convert to list format
        trend_data = []
        for date, metrics in sorted(daily_metrics.items()):
            trend_data.append({
                "date": date.isoformat(),
                "scans": metrics["scans"],
                "findings": metrics["findings"],
                "compliant": metrics["compliant"],
                "non_compliant": metrics["non_compliant"],
                "compliance_score": (
                    f"{metrics['compliant'] / metrics['findings'] * 100:.2f}%"
                    if metrics["findings"] > 0 else "0%"
                )
            })
        
        return {"trends": trend_data}

    def get_control_analysis(
        self,
        organization_id: int,
        days: int = 30
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get analysis of NIST controls.
        
        Args:
            organization_id: The organization ID
            days: Number of days to look back
            
        Returns:
            Dictionary of control analysis
        """
        # Get all findings for the organization
        scans = crud.get_compliance_scans(
            db=self.db,
            organization_id=organization_id
        )
        
        # Group findings by control
        control_metrics = defaultdict(lambda: {
            "total": 0,
            "compliant": 0,
            "non_compliant": 0,
            "not_applicable": 0,
            "not_assessed": 0
        })
        
        for scan in scans:
            findings = crud.get_compliance_findings(
                db=self.db,
                scan_id=scan.id
            )
            
            for finding in findings:
                control_metrics[finding.control_id]["total"] += 1
                control_metrics[finding.control_id][finding.status] += 1
        
        # Convert to list format
        control_data = []
        for control_id, metrics in control_metrics.items():
            control_data.append({
                "control_id": control_id,
                "total": metrics["total"],
                "compliant": metrics["compliant"],
                "non_compliant": metrics["non_compliant"],
                "not_applicable": metrics["not_applicable"],
                "not_assessed": metrics["not_assessed"],
                "compliance_rate": (
                    f"{metrics['compliant'] / metrics['total'] * 100:.2f}%"
                    if metrics["total"] > 0 else "0%"
                )
            })
        
        return {"controls": control_data}

    def get_risk_analysis(
        self,
        organization_id: int,
        days: int = 30
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get risk analysis based on compliance findings.
        
        Args:
            organization_id: The organization ID
            days: Number of days to look back
            
        Returns:
            Dictionary of risk analysis
        """
        # Get all findings for the organization
        scans = crud.get_compliance_scans(
            db=self.db,
            organization_id=organization_id
        )
        
        # Group findings by risk level
        risk_metrics = defaultdict(lambda: {
            "total": 0,
            "open": 0,
            "resolved": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        })
        
        for scan in scans:
            findings = crud.get_compliance_findings(
                db=self.db,
                scan_id=scan.id
            )
            
            for finding in findings:
                if finding.status == "non_compliant":
                    risk_metrics[scan.compliance_type]["total"] += 1
                    risk_metrics[scan.compliance_type]["open"] += 1
                    
                    # Determine risk level based on control ID
                    if finding.control_id.startswith("AC") or finding.control_id.startswith("IA"):
                        risk_metrics[scan.compliance_type]["critical"] += 1
                    elif finding.control_id.startswith("SC") or finding.control_id.startswith("SI"):
                        risk_metrics[scan.compliance_type]["high"] += 1
                    elif finding.control_id.startswith("CM") or finding.control_id.startswith("CP"):
                        risk_metrics[scan.compliance_type]["medium"] += 1
                    else:
                        risk_metrics[scan.compliance_type]["low"] += 1
        
        # Convert to list format
        risk_data = []
        for compliance_type, metrics in risk_metrics.items():
            risk_data.append({
                "compliance_type": compliance_type,
                "total_risks": metrics["total"],
                "open_risks": metrics["open"],
                "resolved_risks": metrics["resolved"],
                "critical_risks": metrics["critical"],
                "high_risks": metrics["high"],
                "medium_risks": metrics["medium"],
                "low_risks": metrics["low"],
                "risk_score": (
                    (metrics["critical"] * 4 + metrics["high"] * 3 +
                     metrics["medium"] * 2 + metrics["low"]) / metrics["total"]
                    if metrics["total"] > 0 else 0
                )
            })
        
        return {"risks": risk_data} 