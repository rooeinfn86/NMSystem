import secrets
import string
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.orm import Session
from sqlalchemy import and_

from app.core.dependencies import get_current_user
from app.api.deps import get_db
from app.models.base import (
    User, Company, CompanyAPIToken
)
from app.schemas.base import (
    CompanyAPITokenCreate, CompanyAPITokenUpdate, 
    CompanyAPITokenResponse, CompanyTokenValidation
)

logger = logging.getLogger(__name__)

router = APIRouter()


def generate_random_token(length: int = 32) -> str:
    """Generate a secure random token for company authentication."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_token(token: str) -> str:
    """Hash the token for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def validate_company_token(token: str, db: Session) -> Optional[CompanyAPIToken]:
    """Validate a company API token and return the token record."""
    token_hash = hash_token(token)
    
    token_record = db.query(CompanyAPIToken).filter(
        and_(
            CompanyAPIToken.token_hash == token_hash,
            CompanyAPIToken.is_active == True
        )
    ).first()
    
    if not token_record:
        return None
    
    # Check if token is expired
    if token_record.expires_at and token_record.expires_at < datetime.utcnow():
        return None
    
    # Update last used timestamp
    token_record.last_used = datetime.utcnow()
    db.commit()
    
    return token_record


@router.post("/generate", response_model=CompanyAPITokenResponse)
async def generate_company_token(
    token_data: CompanyAPITokenCreate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Generate a new company API token."""
    try:
        # Get user from database using the user_id from token
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can generate tokens
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company admins and full control users can generate API tokens"
            )
        
        # Generate secure token
        token = generate_random_token()
        token_hash = hash_token(token)
        
        # Create token record
        token_record = CompanyAPIToken(
            company_id=user.company_id,
            token_hash=token_hash,
            name=token_data.name,
            created_by=user.id,
            is_active=True
        )
        
        db.add(token_record)
        db.commit()
        db.refresh(token_record)
        
        # Return token with the plain text token (only shown once)
        response = CompanyAPITokenResponse.model_validate(token_record)
        response.token = token
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Error generating company token: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error generating token: {str(e)}")


@router.get("/", response_model=List[CompanyAPITokenResponse])
async def list_company_tokens(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List all API tokens for the user's company."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can view tokens
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company admins and full control users can view API tokens"
            )
        
        tokens = db.query(CompanyAPIToken).filter(
            CompanyAPIToken.company_id == user.company_id
        ).all()
        
        return tokens
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching tokens: {str(e)}")


@router.get("/{token_id}", response_model=CompanyAPITokenResponse)
async def get_company_token(
    token_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific company API token details."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can view tokens
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company admins and full control users can view API tokens"
            )
        
        token = db.query(CompanyAPIToken).filter(
            and_(
                CompanyAPIToken.id == token_id,
                CompanyAPIToken.company_id == user.company_id
            )
        ).first()
        
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        return token
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching token: {str(e)}")


@router.put("/{token_id}", response_model=CompanyAPITokenResponse)
async def update_company_token(
    token_id: int,
    token_data: CompanyAPITokenUpdate,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update company API token."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can update tokens
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company admins and full control users can update API tokens"
            )
        
        token = db.query(CompanyAPIToken).filter(
            and_(
                CompanyAPIToken.id == token_id,
                CompanyAPIToken.company_id == user.company_id
            )
        ).first()
        
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        # Update fields
        if token_data.name is not None:
            token.name = token_data.name
        if token_data.is_active is not None:
            token.is_active = token_data.is_active
        if token_data.expires_at is not None:
            token.expires_at = token_data.expires_at
        
        db.commit()
        db.refresh(token)
        
        return token
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating token: {str(e)}")


@router.delete("/{token_id}", status_code=204)
async def revoke_company_token(
    token_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a company API token."""
    try:
        user = db.query(User).filter(User.id == current_user["user_id"]).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Only company_admin and full_control users can revoke tokens
        if user.role not in ["company_admin", "full_control"]:
            raise HTTPException(
                status_code=403,
                detail="Only company admins and full control users can revoke API tokens"
            )
        
        token = db.query(CompanyAPIToken).filter(
            and_(
                CompanyAPIToken.id == token_id,
                CompanyAPIToken.company_id == user.company_id
            )
        ).first()
        
        if not token:
            raise HTTPException(status_code=404, detail="Token not found")
        
        db.delete(token)
        db.commit()
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error revoking token: {str(e)}")


@router.post("/validate")
async def validate_token(
    token_data: CompanyTokenValidation,
    db: Session = Depends(get_db)
):
    """Validate a company API token and return company info."""
    try:
        token_record = validate_company_token(token_data.token, db)
        
        if not token_record:
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token"
            )
        
        # Get company info
        company = db.query(Company).filter(Company.id == token_record.company_id).first()
        
        return {
            "valid": True,
            "company_id": token_record.company_id,
            "company_name": company.name if company else "Unknown",
            "token_name": token_record.name,
            "expires_at": token_record.expires_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error validating token: {str(e)}") 