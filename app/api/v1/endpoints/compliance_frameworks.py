from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.core.dependencies import get_current_user
from app.core.database import get_db
from app.schemas.compliance import ComplianceReportResponse
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

@router.get("/reports", response_model=List[ComplianceReportResponse])
async def get_reports(db: Session = Depends(get_db)):
    """Get all compliance reports"""
    try:
        # Get reports
        reports = []

        # Sort reports by creation date (newest first)
        reports.sort(key=lambda x: x["created_at"], reverse=True)
        
        return reports

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 