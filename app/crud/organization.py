from typing import List, Optional
from sqlalchemy.orm import Session
from app.models.base import Organization
from app.schemas.organization import OrganizationCreate, OrganizationUpdate
from datetime import datetime

def create_organization(db: Session, organization: OrganizationCreate) -> Organization:
    db_organization = Organization(
        name=organization.name,
        description=organization.description,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(db_organization)
    db.commit()
    db.refresh(db_organization)
    return db_organization

def get_organizations(
    db: Session,
    skip: int = 0,
    limit: int = 100
) -> List[Organization]:
    return db.query(Organization).offset(skip).limit(limit).all()

def get_organization(db: Session, organization_id: int) -> Optional[Organization]:
    return db.query(Organization).filter(Organization.id == organization_id).first()

def update_organization(
    db: Session,
    organization_id: int,
    organization: OrganizationUpdate
) -> Optional[Organization]:
    db_organization = get_organization(db=db, organization_id=organization_id)
    if not db_organization:
        return None
    
    update_data = organization.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_organization, field, value)
    
    db_organization.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(db_organization)
    return db_organization

def delete_organization(db: Session, organization_id: int) -> bool:
    db_organization = get_organization(db=db, organization_id=organization_id)
    if not db_organization:
        return False
    
    db.delete(db_organization)
    db.commit()
    return True 