from app.models.base import User, Company, Feature, CompanyFeature, UserOrganizationAccess, UserNetworkAccess, UserFeatureAccess
from app.schemas.base import UserCreate
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from app.core.security import get_password_hash, verify_password

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_user_by_username_and_company(db: Session, username: str, company_id: int):
    return db.query(User).filter(User.username == username, User.company_id == company_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()

def create_user(db: Session, user: UserCreate):
    # Use scoped username uniqueness if company_id is provided
    if user.company_id:
        existing_user = get_user_by_username_and_company(db, user.username, user.company_id)
        if existing_user:
            raise ValueError("Username already exists for this company")
    else:
        existing_user = get_user_by_username(db, user.username)
        if existing_user:
            raise ValueError("Username already exists")

    hashed_pw = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        hashed_password=hashed_pw,
        role=user.role,
        company_id=user.company_id,
        engineer_tier=getattr(user, 'engineer_tier', None)  # Safely get engineer_tier if it exists
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, username: str, password: str):
    user = get_user_by_username(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

def create_company(db: Session, name: str):
    new_company = Company(name=name)
    db.add(new_company)
    db.commit()
    db.refresh(new_company)
    assign_default_features_to_company(db, new_company.id)
    return new_company

def assign_default_features_to_company(db: Session, company_id: int):
    config_feature = create_feature_if_not_exists(db, "config_assistant")
    verification_feature = create_feature_if_not_exists(db, "verification")
    db.add(CompanyFeature(company_id=company_id, feature_id=config_feature.id, enabled=True))
    db.add(CompanyFeature(company_id=company_id, feature_id=verification_feature.id, enabled=True))
    db.commit()

def get_company_with_flattened_features(db: Session, company_id: int):
    company = db.query(Company).filter(Company.id == company_id).first()
    features = get_enabled_features_for_company(db, company_id)
    feature_flags = {f.feature.name: f.enabled for f in features}
    company.config_assistant_enabled = feature_flags.get("config_assistant", False)
    company.verification_enabled = feature_flags.get("verification", False)
    return company

def get_enabled_features_for_company(db: Session, company_id: int):
    return db.query(CompanyFeature).join(Feature).filter(
        CompanyFeature.company_id == company_id
    ).all()

def get_company_by_name(db: Session, name: str):
    return db.query(Company).filter(Company.name == name).first()

def create_feature_if_not_exists(db: Session, feature_name: str):
    existing = db.query(Feature).filter(Feature.name == feature_name).first()
    if not existing:
        new_feature = Feature(name=feature_name)
        db.add(new_feature)
        db.commit()
        db.refresh(new_feature)
        return new_feature
    return existing

# ✅ New functions for per-user access control

def assign_user_access(db: Session, user_id: int, organization_ids: list[int], network_ids: list[int], feature_names: list[str]):
    # Clear previous access
    db.query(UserOrganizationAccess).filter_by(user_id=user_id).delete()
    db.query(UserNetworkAccess).filter_by(user_id=user_id).delete()
    db.query(UserFeatureAccess).filter_by(user_id=user_id).delete()

    # Assign new access
    for org_id in organization_ids:
        db.add(UserOrganizationAccess(user_id=user_id, organization_id=org_id))
    for net_id in network_ids:
        db.add(UserNetworkAccess(user_id=user_id, network_id=net_id))
    for fname in feature_names:
        db.add(UserFeatureAccess(user_id=user_id, feature_name=fname))

    db.commit()

def get_user_access(db: Session, user_id: int):
    orgs = db.query(UserOrganizationAccess.organization_id).filter_by(user_id=user_id).all()
    nets = db.query(UserNetworkAccess.network_id).filter_by(user_id=user_id).all()
    feats = db.query(UserFeatureAccess.feature_name).filter_by(user_id=user_id).all()

    return {
        "organization_ids": [o[0] for o in orgs],
        "network_ids": [n[0] for n in nets],
        "feature_names": [f[0] for f in feats],
    }

def update_user_basic_info(db: Session, user_id: int, user_data):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise ValueError("User not found")

    # Update basic info
    db_user.username = user_data.username
    db_user.role = user_data.role
    
    # Only update engineer_tier if role is engineer and tier is provided
    if user_data.role == "engineer" and user_data.engineer_tier is not None:
        db_user.engineer_tier = user_data.engineer_tier
    elif user_data.role != "engineer":
        db_user.engineer_tier = None  # Clear tier if role is not engineer

    # Only update password if a new one is provided (not the placeholder)
    if user_data.password and user_data.password != "NO_PASSWORD_CHANGE":
        db_user.hashed_password = get_password_hash(user_data.password)

    db.commit()
    db.refresh(db_user)
    return db_user
