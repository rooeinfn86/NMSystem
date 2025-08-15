from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_db, get_current_user, get_organization_admin
from app.schemas.user import User
from app.schemas.organization import (
    Organization,
    OrganizationCreate,
    OrganizationUpdate
)
from app.crud import organization as crud

router = APIRouter()

@router.post("/", response_model=Organization)
def create_organization(
    organization: OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Create a new organization.
    Only super admins can create organizations.
    """
    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Not authorized to create organizations")
    
    return crud.create_organization(db=db, organization=organization)

@router.get("/", response_model=List[Organization])
def read_organizations(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get all organizations.
    Super admins can see all organizations.
    Organization admins can see their own organization.
    """
    if current_user.role == "super_admin":
        return crud.get_organizations(db=db, skip=skip, limit=limit)
    else:
        return [crud.get_organization(db=db, organization_id=current_user.organization_id)]

@router.get("/{organization_id}", response_model=Organization)
def read_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Get a specific organization.
    """
    organization = crud.get_organization(db=db, organization_id=organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if current_user.role != "super_admin" and current_user.organization_id != organization_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this organization")
    
    return organization

@router.put("/{organization_id}", response_model=Organization)
def update_organization(
    organization_id: int,
    organization: OrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_organization_admin)
):
    """
    Update an organization.
    Only super admins and organization admins can update organizations.
    """
    db_organization = crud.get_organization(db=db, organization_id=organization_id)
    if not db_organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    if current_user.role != "super_admin" and current_user.organization_id != organization_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this organization")
    
    return crud.update_organization(db=db, organization_id=organization_id, organization=organization)

@router.delete("/{organization_id}")
def delete_organization(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete an organization.
    Only super admins can delete organizations.
    """
    if current_user.role != "super_admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete organizations")
    
    organization = crud.get_organization(db=db, organization_id=organization_id)
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")
    
    crud.delete_organization(db=db, organization_id=organization_id)
    return {"message": "Organization deleted successfully"} 