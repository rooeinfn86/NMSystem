from typing import Generator, Optional
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.core.security import get_current_user
from app.schemas.user import User
from app.crud import compliance as crud

def get_db() -> Generator[Session, None, None]:
    """
    Get database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    db: Session = Depends(get_db),
    token: str = Depends(get_current_user)
) -> User:
    """
    Get current authenticated user.
    """
    return token

def verify_user_access(
    db: Session,
    user_id: int,
    organization_id: int
) -> bool:
    """
    Verify if user has access to the organization.
    """
    return crud.verify_user_access(db=db, user_id=user_id, organization_id=organization_id)

def get_organization_admin(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current user and verify if they are an organization admin.
    """
    if current_user.role not in ["organization_admin", "super_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user

def get_super_admin(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Get current user and verify if they are a super admin.
    """
    if current_user.role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user 