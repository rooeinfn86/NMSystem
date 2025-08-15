from fastapi import APIRouter, Depends, HTTPException, status, Body, Query, Response
from sqlalchemy.orm import Session, selectinload
from app.schemas.base import UserCreate, User as UserSchema, Company, FeatureAccessResponse, CompanyCreate
from app.core.database import get_db
from app.core import crud
from app.core.security import verify_password, create_access_token, get_password_hash
from fastapi.security import OAuth2PasswordRequestForm
from app.core.dependencies import get_current_user
from app.models.base import User as UserModel, Company as CompanyModel, CompanyFeature, Feature, UserOrganizationAccess, UserNetworkAccess, Organization, UserFeatureAccess, Network, DeviceLog, Device
from typing import List

router = APIRouter(prefix="/companies", tags=["Companies"])

@router.post("/register", response_model=UserSchema)
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = crud.get_user_by_username(db, user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db, user)

@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    access_token = create_access_token(data={
        "sub": str(user.id),
        "username": user.username,
        "user_id": user.id,
        "role": user.role,
        "company_id": user.company_id
    })
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/test-auth")
def test_auth(current_user: dict = Depends(get_current_user)):
    return {
        "message": "✅ Token is valid",
        "current_user": current_user
    }

@router.post("/company-admin-create", response_model=UserSchema)
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

@router.post("/team-member-create", response_model=UserSchema)
def create_team_member(user: UserCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Only company admins can create team members")

    existing = crud.get_user_by_username(db, user.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")

    db_user = UserModel(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        role="engineer",
        company_id=current_user.get("company_id")
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.get("/features", response_model=FeatureAccessResponse)
def get_feature_access(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    company_id = current_user.get("company_id")
    if not company_id:
        raise HTTPException(status_code=404, detail="User is not assigned to any company")

    features = db.query(CompanyFeature).join(Feature).filter(
        CompanyFeature.company_id == company_id,
        CompanyFeature.enabled == True
    ).all()

    enabled_feature_names = {cf.feature.name for cf in features}

    return FeatureAccessResponse(
        company_id=company_id,
        config_assistant_enabled="config_assistant" in enabled_feature_names,
        verification_enabled="verification" in enabled_feature_names
    )

@router.get("/by-company", response_model=List[UserSchema])
def get_users_by_company(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user),
    company_id: int = Query(None)
):
    if current_user.get("role") in ["admin", "superadmin"]:
        if not company_id:
            raise HTTPException(status_code=400, detail="company_id is required for admin")
    else:
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
    # Attach organizations, networks, and features for API response
    company = db.query(CompanyModel).options(selectinload(CompanyModel.features)).filter(CompanyModel.id == company_id).first()
    enabled_company_features = [cf.feature.name for cf in company.features if cf.enabled and cf.feature]
    response = []
    for user in users:
        orgs = [access.organization for access in getattr(user, 'org_access', []) if access.organization]
        nets = [access.network for access in getattr(user, 'net_access', []) if access.network]
        if getattr(user, 'role', None) == 'company_admin':
            features = [{"feature_name": fname} for fname in enabled_company_features]
        else:
            features = [{"feature_name": f.feature_name} for f in getattr(user, 'feature_access', [])]
        # Use the Pydantic model to serialize, then update with our computed fields
        user_dict = UserSchema.from_orm(user).dict()
        user_dict.pop('feature_access', None)
        user_dict['organizations'] = orgs
        user_dict['networks'] = nets
        user_dict['feature_access_display'] = features
        response.append(user_dict)
    return response

# @router.get("/me/users", response_model=List[UserSchema])
# def list_team_members(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
#     if current_user.get("role") != "company_admin":
#         raise HTTPException(status_code=403, detail="Only company admins can view team members")

#     return db.query(UserModel).filter(UserModel.company_id == current_user["company_id"]).all()

@router.get("/", response_model=List[Company])
def get_all_companies(db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Only platform admins can view companies")
    companies = db.query(CompanyModel).options(selectinload(CompanyModel.users), selectinload(CompanyModel.features)).all()
    # Dynamically set feature flags
    result = []
    for company in companies:
        feature_names = [cf.feature.name for cf in company.features if cf.enabled]
        company.config_assistant_enabled = "config_assistant" in feature_names
        company.verification_enabled = "verification" in feature_names
        company.compliance_enabled = "compliance" in feature_names
        result.append(company)
    return result

@router.post("/", response_model=Company)
def create_company(company: CompanyCreate, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Only platform admins can create companies")

    # Check if username already exists
    existing_user = db.query(UserModel).filter(UserModel.username == company.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    # Check if company name already exists
    existing_company = db.query(CompanyModel).filter(CompanyModel.name == company.name).first()
    if existing_company:
        raise HTTPException(status_code=400, detail="Company name already exists")

    db_company = CompanyModel(name=company.name)
    db.add(db_company)
    db.commit()
    db.refresh(db_company)

    admin_user = UserModel(
        username=company.username,
        hashed_password=get_password_hash(company.password),
        role="company_admin",
        company_id=db_company.id,
        first_name=getattr(company, 'first_name', None),
        last_name=getattr(company, 'last_name', None),
        position=getattr(company, 'position', None),
        email=getattr(company, 'email', None),
        telephone=getattr(company, 'telephone', None),
        address=getattr(company, 'address', None)
    )
    db.add(admin_user)
    db.commit()

    selected_features = []
    if company.config_assistant_enabled:
        selected_features.append("config_assistant")
    if company.verification_enabled:
        selected_features.append("verification")
    if company.compliance_enabled:
        selected_features.append("compliance")

    for feature_name in selected_features:
        feature = db.query(Feature).filter(Feature.name == feature_name).first()
        if feature:
            db.add(CompanyFeature(company_id=db_company.id, feature_id=feature.id, enabled=True))

    db.commit()
    return db_company

@router.delete("/{company_id}", status_code=204)
def delete_company(company_id: int, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Only platform admins can delete companies")

    company = db.query(CompanyModel).filter(CompanyModel.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")

    try:
        # First get all users in the company
        users = db.query(UserModel).filter(UserModel.company_id == company_id).all()
        user_ids = [user.id for user in users]

        # Get all organizations owned by these users
        organizations = db.query(Organization).filter(Organization.owner_id.in_(user_ids)).all()
        org_ids = [org.id for org in organizations]

        # Get all networks in these organizations
        networks = db.query(Network).filter(Network.organization_id.in_(org_ids)).all()
        network_ids = [network.id for network in networks]


        # Delete device logs
        if network_ids:
            try:
                db.query(DeviceLog).filter(DeviceLog.network_id.in_(network_ids)).delete(synchronize_session=False)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting device logs: {str(e)}")

        # Delete devices
        if user_ids:
            try:
                db.query(Device).filter(Device.owner_id.in_(user_ids)).delete(synchronize_session=False)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting devices: {str(e)}")

        # Delete user network access records
        if network_ids:
            try:
                db.query(UserNetworkAccess).filter(UserNetworkAccess.network_id.in_(network_ids)).delete(synchronize_session=False)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting user network access records: {str(e)}")

        # Delete networks
        if networks:
            try:
                for network in networks:
                    db.delete(network)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting networks: {str(e)}")

        # Delete user organization access BEFORE organizations
        if org_ids:
            try:
                db.query(UserOrganizationAccess).filter(UserOrganizationAccess.organization_id.in_(org_ids)).delete(synchronize_session=False)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting user organization access: {str(e)}")

        # Now delete organizations
        if organizations:
            try:
                for org in organizations:
                    db.delete(org)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting organizations: {str(e)}")

        # Delete user feature access
        if user_ids:
            try:
                db.query(UserFeatureAccess).filter(UserFeatureAccess.user_id.in_(user_ids)).delete(synchronize_session=False)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting user feature access: {str(e)}")

        # Delete users
        if users:
            try:
                for user in users:
                    db.delete(user)
                db.commit()
            except Exception as e:
                db.rollback()
                raise HTTPException(status_code=500, detail=f"Error deleting users: {str(e)}")

        # Delete company features
        try:
            db.query(CompanyFeature).filter(CompanyFeature.company_id == company_id).delete(synchronize_session=False)
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Error deleting company features: {str(e)}")

        # Finally delete the company
        try:
            db.delete(company)
            db.commit()
        except Exception as e:
            db.rollback()
            raise HTTPException(status_code=500, detail=f"Error deleting company: {str(e)}")

        return Response(status_code=204)
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@router.patch("/{company_id}", response_model=Company)
def update_company(company_id: int, data: dict = Body(...), db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    if current_user.get("role") not in ["admin", "superadmin"]:
        raise HTTPException(status_code=403, detail="Only platform admins can update companies")
    company = db.query(CompanyModel).options(selectinload(CompanyModel.users), selectinload(CompanyModel.features)).filter(CompanyModel.id == company_id).first()
    if not company:
        raise HTTPException(status_code=404, detail="Company not found")
    # Update company name
    if "name" in data:
        company.name = data["name"]
    # Update admin user
    admin = next((u for u in company.users if u.role == "company_admin"), None)
    if admin:
        for field in ["username", "first_name", "last_name", "position", "email", "telephone", "address"]:
            if field in data:
                setattr(admin, field, data[field])
    # Update features
    feature_map = {
        "config_assistant_enabled": "config_assistant",
        "verification_enabled": "verification",
        "compliance_enabled": "compliance"
    }
    for flag, feature_name in feature_map.items():
        if flag in data:
            feature = db.query(Feature).filter(Feature.name == feature_name).first()
            if feature:
                cf = db.query(CompanyFeature).filter(CompanyFeature.company_id == company.id, CompanyFeature.feature_id == feature.id).first()
                if cf:
                    cf.enabled = bool(data[flag])
                else:
                    db.add(CompanyFeature(company_id=company.id, feature_id=feature.id, enabled=bool(data[flag])))
    db.commit()
    db.refresh(company)
    # Dynamically set feature flags for response
    feature_names = [cf.feature.name for cf in company.features if cf.enabled]
    company.config_assistant_enabled = "config_assistant" in feature_names
    company.verification_enabled = "verification" in feature_names
    company.compliance_enabled = "compliance" in feature_names
    return company


