from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session, selectinload
from app.schemas.base import UserCreate, User, Company, TeamMemberCreate, TeamMemberAccess, FeatureAccessResponse
from app.core.database import get_db
from app.core import crud
from app.core.security import verify_password, create_access_token, get_password_hash
from app.core.dependencies import get_current_user
from app.models.base import User as UserModel, Company as CompanyModel, CompanyFeature, Feature, UserOrganizationAccess, UserNetworkAccess, UserFeatureAccess, Organization as OrganizationModel, Network
from typing import List, Optional
from pydantic import BaseModel
from app.core.working_rate_limiting import rate_limit_dependency

router = APIRouter(prefix="/users", tags=["Users"])

class LoginRequest(BaseModel):
    username: str
    password: str
    company_name: Optional[str] = None

@router.post("/register", response_model=User)
async def register(
    user: UserCreate, 
    db: Session = Depends(get_db),
    rate_limit: bool = Depends(rate_limit_dependency("auth", "register"))
):
    existing_user = crud.get_user_by_username(db, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db, user)

@router.post("/login")
async def login(
    payload: LoginRequest, 
    db: Session = Depends(get_db),
    rate_limit: bool = Depends(rate_limit_dependency("auth", "login"))
):
    username = payload.username
    password = payload.password
    company_name = payload.company_name

    user = db.query(UserModel).filter(UserModel.username == username).first()

    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    if user.role == "superadmin":
        access_token = create_access_token(data={
            "sub": str(user.id),
            "username": user.username,
            "user_id": user.id,
            "role": user.role,
            "company_id": None
        })
        return {
            "access_token": access_token, 
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role,
                "engineer_tier": user.engineer_tier,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "position": user.position,
                "email": user.email,
                "telephone": user.telephone,
                "address": user.address,
                "company_id": None
            }
        }

    if not company_name:
        raise HTTPException(status_code=400, detail="Company name is required")

    company = db.query(CompanyModel).filter(CompanyModel.name == company_name).first()
    if not company or user.company_id != company.id:
        raise HTTPException(status_code=404, detail="Company not found or user not in company")

    access_token = create_access_token(data={
        "sub": str(user.id),
        "username": user.username,
        "user_id": user.id,
        "role": user.role,
        "company_id": user.company_id
    })
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "engineer_tier": user.engineer_tier,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "position": user.position,
            "email": user.email,
            "telephone": user.telephone,
            "address": user.address,
            "company_id": user.company_id
        }
    }

@router.get("/test-auth")
def test_auth(current_user: dict = Depends(get_current_user)):
    return {
        "message": "✅ Token is valid",
        "current_user": current_user
    }

@router.post("/company-admin-create", response_model=User)
def create_company_admin(user: UserCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create company admins")

    existing = crud.get_user_by_username(db, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    db_user = UserModel(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        role="company_admin"
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    company = CompanyModel(name=f"{user.username}'s Company")
    db.add(company)
    db.commit()
    db.refresh(company)

    db_user.company_id = company.id
    db.commit()

    return db_user

@router.post("/team-member-create", response_model=User)
def create_team_member(user: TeamMemberCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Only company admins can create team members")

    existing = crud.get_user_by_username(db, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Validate role and engineer tier
    if user.role == "engineer" and not user.engineer_tier:
        raise HTTPException(status_code=400, detail="Engineer tier is required for engineer role")
    
    if user.role == "engineer" and user.engineer_tier not in [1, 2, 3]:
        raise HTTPException(status_code=400, detail="Engineer tier must be 1, 2, or 3")
    
    if user.role == "full_control":
        # Full control users automatically get access to all organizations and networks
        # except team management
        company = db.query(CompanyModel).filter(CompanyModel.id == current_user.get("company_id")).first()
        if not company:
            raise HTTPException(status_code=404, detail="Company not found")
            
        # Get all organizations for the company
        organizations = db.query(OrganizationModel)\
            .join(UserModel, OrganizationModel.owner_id == UserModel.id)\
            .filter(UserModel.company_id == company.id)\
            .all()
            
        user.organization_ids = [org.id for org in organizations]
        
        # Get all networks for these organizations
        networks = db.query(Network)\
            .filter(Network.organization_id.in_([org.id for org in organizations]))\
            .all()
            
        user.network_ids = [net.id for net in networks]
        
        # Add all features except team management
        user.feature_names = ["config_assistant", "verification", "compliance"]

    # Create a UserCreate object with all necessary fields
    user_create = UserCreate(
        username=user.username,
        password=user.password,
        role=user.role,
        company_id=current_user.get("company_id"),
        engineer_tier=user.engineer_tier if user.role == "engineer" else None
    )

    db_user = crud.create_user(db, user_create)

    crud.assign_user_access(
        db,
        user_id=db_user.id,
        organization_ids=user.organization_ids or [],
        network_ids=user.network_ids or [],
        feature_names=user.feature_names or []
    )

    # Refresh user with all relationships
    db_user = db.query(UserModel)\
        .options(
            selectinload(UserModel.org_access).selectinload(UserOrganizationAccess.organization),
            selectinload(UserModel.net_access).selectinload(UserNetworkAccess.network),
            selectinload(UserModel.feature_access)
        )\
        .filter(UserModel.id == db_user.id)\
        .first()

    # Set the relationships for the response
    organizations = []
    for access in db_user.org_access:
        if access.organization:
            organizations.append({
                "id": access.organization.id,
                "name": access.organization.name
            })
    db_user.organizations = organizations

    networks = []
    for access in db_user.net_access:
        if access.network:
            networks.append({
                "id": access.network.id,
                "name": access.network.name,
                "organization_id": access.network.organization_id
            })
    db_user.networks = networks

    db_user.feature_access_display = [{"feature_name": access.feature_name} for access in db_user.feature_access]

    return db_user

@router.put("/{user_id}", response_model=User)
def update_user(user_id: int, user: TeamMemberCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    db_user = crud.update_user_basic_info(db, user_id, user)
    crud.assign_user_access(
        db,
        user_id=user_id,
        organization_ids=user.organization_ids or [],
        network_ids=user.network_ids or [],
        feature_names=user.feature_names or []
    )
    return db_user

@router.get("/{user_id}/access", response_model=TeamMemberAccess)
def get_user_access(user_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    org_ids = [access.organization_id for access in db.query(UserOrganizationAccess).filter_by(user_id=user_id).all()]
    net_ids = [access.network_id for access in db.query(UserNetworkAccess).filter_by(user_id=user_id).all()]
    feature_names = [f.feature_name for f in db.query(UserFeatureAccess).filter_by(user_id=user_id).all()]

    return TeamMemberAccess(user_id=user_id, organization_ids=org_ids, network_ids=net_ids, feature_names=feature_names)

@router.get("/features", response_model=FeatureAccessResponse)
def get_feature_access(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    """Get feature access for the current user."""
    company_id = current_user.get("company_id")
    role = current_user.get("role")
    user_id = current_user.get("user_id")
    
    if not company_id:
        raise HTTPException(status_code=404, detail="Company not found")

    # Get company's enabled features
    from app.core.crud import get_enabled_features_for_company
    company_features = get_enabled_features_for_company(db, company_id)
    company_feature_names = {cf.feature.name for cf in company_features if cf.enabled}

    # Company admin and full_control users get access to company-enabled features
    if role in ("company_admin", "full_control"):
        return {
            "company_id": company_id,
            "config_assistant_enabled": "config_assistant" in company_feature_names,
            "verification_enabled": "verification" in company_feature_names,
            "compliance_enabled": "compliance" in company_feature_names
        }

    # For other users, check their specific feature access (but still limited by company settings)
    user_features = db.query(UserFeatureAccess).filter(
        UserFeatureAccess.user_id == user_id
    ).all()
    
    user_feature_names = {f.feature_name for f in user_features}

    return {
        "company_id": company_id,
        "config_assistant_enabled": "config_assistant" in user_feature_names and "config_assistant" in company_feature_names,
        "verification_enabled": "verification" in user_feature_names and "verification" in company_feature_names,
        "compliance_enabled": "compliance" in user_feature_names and "compliance" in company_feature_names
    }

@router.get("/by-company", response_model=List[User])
def get_users_by_company(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    company_id = current_user.get("company_id")
    if not company_id:
        raise HTTPException(status_code=400, detail="User not assigned to a company")

    users = db.query(UserModel)\
        .options(
            selectinload(UserModel.org_access).selectinload(UserOrganizationAccess.organization),
            selectinload(UserModel.net_access).selectinload(UserNetworkAccess.network),
            selectinload(UserModel.feature_access)
        )\
        .filter(UserModel.company_id == company_id).all()
    for user in users:
        user.organizations = [access.organization for access in getattr(user, 'org_access', []) if access.organization]
        user.networks = [access.network for access in getattr(user, 'net_access', []) if access.network]
    return users

@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Only company admins can delete users")

    user = db.query(UserModel).filter(
        UserModel.id == user_id,
        UserModel.company_id == current_user["company_id"]
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # First, handle organizations owned by this user
    owned_orgs = db.query(OrganizationModel).filter(OrganizationModel.owner_id == user_id).all()
    if owned_orgs:
        # Get another user from the same company to transfer ownership
        new_owner = db.query(UserModel).filter(
            UserModel.company_id == current_user["company_id"],
            UserModel.id != user_id,
            UserModel.role.in_(["company_admin", "engineer"])
        ).first()
        
        if not new_owner:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete user: they own organizations and there is no other user to transfer ownership to"
            )
        
        # Transfer ownership of all organizations to the new owner
        for org in owned_orgs:
            org.owner_id = new_owner.id

    # Delete all organization access records
    db.query(UserOrganizationAccess).filter(UserOrganizationAccess.user_id == user_id).delete()
    
    # Delete all network access records
    db.query(UserNetworkAccess).filter(UserNetworkAccess.user_id == user_id).delete()
    
    # Delete all feature access records
    db.query(UserFeatureAccess).filter(UserFeatureAccess.user_id == user_id).delete()
    
    # Delete the user
    db.delete(user)
    db.commit()
    return

@router.get("/me/users", response_model=List[User])
def get_team_members(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Only company admins can view team members")

    users = db.query(UserModel)\
        .options(
            selectinload(UserModel.org_access).selectinload(UserOrganizationAccess.organization),
            selectinload(UserModel.net_access).selectinload(UserNetworkAccess.network),
            selectinload(UserModel.feature_access)
        )\
        .filter(UserModel.company_id == current_user["company_id"])\
        .all()
    
    for user in users:
        # Get organizations through org_access
        organizations = []
        for access in user.org_access:
            if access.organization:
                organizations.append({
                    "id": access.organization.id,
                    "name": access.organization.name
                })
        user.organizations = organizations

        # Get networks through net_access
        networks = []
        for access in user.net_access:
            if access.network:
                networks.append({
                    "id": access.network.id,
                    "name": access.network.name,
                    "organization_id": access.network.organization_id
                })
        user.networks = networks

        # Get feature access
        user.feature_access_display = [{"feature_name": access.feature_name} for access in user.feature_access]
    
    return users

