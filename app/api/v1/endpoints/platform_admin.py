from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.base import Company, User, Feature, CompanyFeature
from app.schemas.base import UserCreate, Company as CompanySchema
from app.core.security import get_password_hash
from typing import List
from app.core import crud

router = APIRouter(
    prefix="/platform-admin",
    tags=["Platform Admin"]
)


@router.post("/create-company", response_model=CompanySchema)
def create_company_with_admin(
    company_name: str,
    admin_username: str,
    admin_password: str,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only platform admins can create companies")

    # Create company
    company = Company(name=company_name)
    db.add(company)
    db.commit()
    db.refresh(company)

    # Create admin user for the company
    hashed_pw = get_password_hash(admin_password)
    admin_user = User(
        username=admin_username,
        hashed_password=hashed_pw,
        role="company_admin",
        company_id=company.id
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    # Enable all existing features by default (can later customize)
    all_features = db.query(Feature).all()
    for feature in all_features:
        db.add(CompanyFeature(company_id=company.id, feature_id=feature.id, enabled=True))
    db.commit()

    return company


@router.get("/companies", response_model=List[CompanySchema])
def list_companies(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only platform admins can list companies")

    return db.query(Company).all()


@router.get("/features")
def list_all_features(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only platform admins can view features")

    return db.query(Feature).all()


@router.put("/companies/{company_id}/features")
def update_company_features(
    company_id: int,
    enabled_feature_names: List[str],
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only platform admins can update features")

    company = db.query(Company).filter_by(id=company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    all_features = db.query(Feature).all()
    feature_map = {f.name: f.id for f in all_features}

    for fname in enabled_feature_names:
        if fname not in feature_map:
            raise HTTPException(status_code=400, detail=f"Unknown feature: {fname}")

    # Disable all first
    db.query(CompanyFeature).filter_by(company_id=company_id).update({"enabled": False})
    db.commit()

    # Re-enable selected
    for fname in enabled_feature_names:
        fid = feature_map[fname]
        record = db.query(CompanyFeature).filter_by(company_id=company_id, feature_id=fid).first()
        if record:
            record.enabled = True
        else:
            db.add(CompanyFeature(company_id=company_id, feature_id=fid, enabled=True))
    db.commit()

    return {"success": True, "enabled_features": enabled_feature_names}
