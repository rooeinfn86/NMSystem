from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models import base as models
from app.schemas import base as schemas
from app.core.dependencies import get_current_user
from typing import Optional

router = APIRouter(
    prefix="/org-network",
    tags=["Organization & Network"]
)

def check_engineer_permissions(current_user: dict, db: Session) -> Optional[models.User]:
    """Check engineer permissions based on their tier."""
    if current_user["role"] != "engineer":
        return None
        
    user = db.query(models.User).filter(models.User.id == current_user["user_id"]).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user

# ------------------ ORGANIZATION ROUTES ------------------

@router.post("/organizations/", response_model=schemas.Organization)
def create_organization(
    org: schemas.OrganizationCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new organization for the current user."""
    try:
        # Create the organization
        db_org = models.Organization(name=org.name, owner_id=current_user["user_id"])
        db.add(db_org)
        db.flush()  # Get the org ID without committing

        # Always create access record for the creator
        org_access = models.UserOrganizationAccess(
            user_id=current_user["user_id"],
            organization_id=db_org.id
        )
        db.add(org_access)

        # For full control users, we only need their own access
        if current_user["role"] == "full_control":
            db.commit()
            db.refresh(db_org)
            return db_org

        if current_user["role"] == "engineer":
            user = check_engineer_permissions(current_user, db)
            # Only Tier 3 engineers can create organizations
            if not user or user.engineer_tier != 3:
                db.rollback()
                raise HTTPException(
                    status_code=403,
                    detail="Only Tier 3 engineers can create organizations"
                )
            
            # If created by Tier 3 engineer, grant access to all engineers in their company
            if user.company_id:
                company_engineers = db.query(models.User).filter(
                    models.User.company_id == user.company_id,
                    models.User.role == "engineer",
                    models.User.id != current_user["user_id"]
                ).all()
                
                for engineer in company_engineers:
                    eng_access = models.UserOrganizationAccess(
                        user_id=engineer.id,
                        organization_id=db_org.id
                    )
                    db.add(eng_access)
                
                # Also grant access to the company admin
                company_admin = db.query(models.User).filter(
                    models.User.company_id == user.company_id,
                    models.User.role == "company_admin"
                ).first()
                
                if company_admin:
                    admin_access = models.UserOrganizationAccess(
                        user_id=company_admin.id,
                        organization_id=db_org.id
                    )
                    db.add(admin_access)

        # If created by company admin, grant access to all engineers in the company
        elif current_user["role"] == "company_admin":
            engineers = db.query(models.User).filter(
                models.User.company_id == current_user["company_id"],
                models.User.role == "engineer"
            ).all()
            
            for engineer in engineers:
                if engineer.id != current_user["user_id"]:
                    eng_access = models.UserOrganizationAccess(
                        user_id=engineer.id,
                        organization_id=db_org.id
                    )
                    db.add(eng_access)

        db.commit()
        db.refresh(db_org)
        return db_org

    except Exception as e:
        db.rollback()
        print(f"Error creating organization: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=400,
            detail=f"Failed to create organization: {str(e)}"
        )

@router.get("/organizations/", response_model=list[schemas.Organization])
def get_user_organizations(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get organizations the user has access to."""
    print(f"[GET ORGS] For user: {current_user}")
    
    # For company admins, get all orgs they own AND all orgs in their company
    if current_user["role"] == "company_admin":
        return db.query(models.Organization).join(
            models.User,
            models.Organization.owner_id == models.User.id
        ).filter(
            models.User.company_id == current_user["company_id"]
        ).all()
    
    # For engineers, get orgs they have access to
    access_records = db.query(models.UserOrganizationAccess).filter(
        models.UserOrganizationAccess.user_id == current_user["user_id"]
    ).all()
    
    org_ids = [record.organization_id for record in access_records]
    if not org_ids:
        return []
    
    return db.query(models.Organization).filter(
        models.Organization.id.in_(org_ids)
    ).all()

@router.delete("/organizations/{org_id}")
def delete_organization(
    org_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete an organization and all its associated networks and devices."""
    organization = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Allow Full Control users to delete organizations
    if current_user["role"] == "full_control":
        try:
            # Get all networks in the organization
            networks = db.query(models.Network).filter(models.Network.organization_id == org_id).all()
            
            # For each network, delete associated data in correct order
            for network in networks:
                # First delete device logs
                db.query(models.DeviceLog).filter(models.DeviceLog.network_id == network.id).delete()
                
                # Then delete devices
                db.query(models.Device).filter(models.Device.network_id == network.id).delete()
                
                # Delete network access records
                db.query(models.UserNetworkAccess).filter(models.UserNetworkAccess.network_id == network.id).delete()
            
            # Now delete all networks
            db.query(models.Network).filter(models.Network.organization_id == org_id).delete()
            
            # Delete organization access records
            db.query(models.UserOrganizationAccess).filter(models.UserOrganizationAccess.organization_id == org_id).delete()
            
            # Finally delete the organization
            db.delete(organization)
            db.commit()
            
            return {"message": "Organization and all associated data deleted successfully"}
        except Exception as e:
            db.rollback()
            print(f"Error deleting organization: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to delete organization: {str(e)}")

    # Engineers cannot delete organizations regardless of tier
    if current_user["role"] == "engineer":
        raise HTTPException(
            status_code=403,
            detail="Engineers cannot delete organizations"
        )

    # Only company admins or the organization owner can delete
    if current_user["role"] != "company_admin" and organization.owner_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete this organization")

    try:
        # Get all networks in the organization
        networks = db.query(models.Network).filter(models.Network.organization_id == org_id).all()
        
        # For each network, delete associated data in correct order
        for network in networks:
            # First delete device logs
            db.query(models.DeviceLog).filter(models.DeviceLog.network_id == network.id).delete()
            
            # Then delete devices
            db.query(models.Device).filter(models.Device.network_id == network.id).delete()
            
            # Delete network access records
            db.query(models.UserNetworkAccess).filter(models.UserNetworkAccess.network_id == network.id).delete()
        
        # Now delete all networks
        db.query(models.Network).filter(models.Network.organization_id == org_id).delete()
        
        # Delete organization access records
        db.query(models.UserOrganizationAccess).filter(models.UserOrganizationAccess.organization_id == org_id).delete()
        
        # Finally delete the organization
        db.delete(organization)
        db.commit()
        
        return {"message": "Organization and all associated data deleted successfully"}
    except Exception as e:
        db.rollback()
        print(f"Error deleting organization: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete organization: {str(e)}")

# ------------------ NETWORK ROUTES ------------------

@router.post("/networks/", response_model=schemas.Network)
def create_network(
    network: schemas.NetworkCreate,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Create a new network under a specific organization."""
    try:
        # Check if organization exists
        org = db.query(models.Organization).filter(
            models.Organization.id == network.organization_id
        ).first()

        if not org:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Create the network
        db_network = models.Network(
            name=network.name,
            organization_id=network.organization_id
        )
        db.add(db_network)
        db.flush()  # Get the network ID

        # Create access for the creator
        network_access = models.UserNetworkAccess(
            user_id=current_user["user_id"],
            network_id=db_network.id
        )
        db.add(network_access)

        # For full control users, we only need their own access
        if current_user["role"] == "full_control":
            db.commit()
            db.refresh(db_network)
            return db_network

        # For engineers, check tier level
        if current_user["role"] == "engineer":
            user = check_engineer_permissions(current_user, db)
            if not user or user.engineer_tier != 3:
                db.rollback()
                raise HTTPException(
                    status_code=403,
                    detail="Only Tier 3 engineers can create networks"
                )

        # Grant access to all users who have access to the parent organization
        org_access_records = db.query(models.UserOrganizationAccess).filter(
            models.UserOrganizationAccess.organization_id == org.id
        ).all()
        
        for record in org_access_records:
            if record.user_id != current_user["user_id"]:  # Skip creator as they already have access
                network_access = models.UserNetworkAccess(
                    user_id=record.user_id,
                    network_id=db_network.id
                )
                db.add(network_access)

        db.commit()
        db.refresh(db_network)
        return db_network

    except Exception as e:
        db.rollback()
        print(f"Error creating network: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=400,
            detail=f"Failed to create network: {str(e)}"
        )

@router.get("/networks/", response_model=list[schemas.Network])
def get_networks_for_org(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get networks for an organization that the user has access to."""
    # For company admins, get all networks in their company's organizations
    if current_user["role"] == "company_admin":
        return db.query(models.Network).join(
            models.Organization,
            models.Network.organization_id == models.Organization.id
        ).join(
            models.User,
            models.Organization.owner_id == models.User.id
        ).filter(
            models.User.company_id == current_user["company_id"],
            models.Network.organization_id == organization_id
        ).all()
    
    # For engineers, get networks they have access to
    access_records = db.query(models.UserNetworkAccess).filter(
        models.UserNetworkAccess.user_id == current_user["user_id"],
        models.UserNetworkAccess.network_id.in_(
            db.query(models.Network.id).filter(
                models.Network.organization_id == organization_id
            )
        )
    ).all()

    if not access_records:
        return []

    network_ids = [record.network_id for record in access_records]
    return db.query(models.Network).filter(
        models.Network.id.in_(network_ids)
    ).all()

# ✅ NEW: Get all networks user has access to under a specific org
@router.get("/my-networks", response_model=list[schemas.Network])
def get_user_networks_in_org(
    organization_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Return networks within a selected org that the current user has access to"""
    user_id = current_user.get("user_id")

    network_ids = [
        record.network_id
        for record in db.query(models.UserNetworkAccess)
        .join(models.Network)
        .filter(
            models.UserNetworkAccess.user_id == user_id,
            models.Network.organization_id == organization_id
        ).all()
    ]

    if not network_ids:
        return []

    return db.query(models.Network).filter(models.Network.id.in_(network_ids)).all()


# ✅ NEW: Get all networks user has access to across all orgs
@router.get("/all-networks", response_model=list[schemas.Network])
def get_all_accessible_networks(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Return all networks the user has access to regardless of organization."""
    user_id = current_user.get("user_id")
    access_records = db.query(models.UserNetworkAccess).filter_by(user_id=user_id).all()
    net_ids = [a.network_id for a in access_records]

    if not net_ids:
        return []

    return db.query(models.Network).filter(models.Network.id.in_(net_ids)).all()

@router.delete("/networks/{network_id}")
def delete_network(
    network_id: int,
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Delete a network and all its associated devices."""
    try:
        network = db.query(models.Network).filter(models.Network.id == network_id).first()
        if not network:
            raise HTTPException(status_code=404, detail="Network not found")

        # Allow Full Control users to delete networks
        if current_user["role"] == "full_control":
            # First delete device logs
            db.query(models.DeviceLog).filter(models.DeviceLog.network_id == network_id).delete()
            
            # Then delete devices
            db.query(models.Device).filter(models.Device.network_id == network_id).delete()
            
            # Delete network access records
            db.query(models.UserNetworkAccess).filter(models.UserNetworkAccess.network_id == network_id).delete()
            
            # Delete the network
            db.delete(network)
            db.commit()
            return {"message": "Network and all associated data deleted successfully"}

        # Check permissions for other roles
        if current_user["role"] == "engineer":
            user = check_engineer_permissions(current_user, db)
            if not user or user.engineer_tier != 3:
                raise HTTPException(
                    status_code=403,
                    detail="Only Tier 3 engineers can delete networks"
                )
        
        # Get the organization and check permissions
        organization = db.query(models.Organization).filter(
            models.Organization.id == network.organization_id
        ).first()

        if not organization:
            raise HTTPException(status_code=404, detail="Organization not found")

        # Only company admins or organization owners can delete networks
        if current_user["role"] != "company_admin" and organization.owner_id != current_user["user_id"]:
            raise HTTPException(status_code=403, detail="Not authorized to delete this network")

        # Delete in correct order
        # First delete device logs
        db.query(models.DeviceLog).filter(models.DeviceLog.network_id == network_id).delete()
        
        # Then delete devices
        db.query(models.Device).filter(models.Device.network_id == network_id).delete()
        
        # Delete network access records
        db.query(models.UserNetworkAccess).filter(models.UserNetworkAccess.network_id == network_id).delete()
        
        # Delete the network
        db.delete(network)
        db.commit()

        return {"message": "Network deleted successfully"}

    except Exception as e:
        db.rollback()
        print(f"Error deleting network: {str(e)}")
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete network: {str(e)}"
        )

# ------------------ ALIAS ROUTE FOR /orgs ------------------

@router.get("/orgs", response_model=list[schemas.Organization])
def alias_orgs(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Alias for /organizations to match frontend expectations."""
    return db.query(models.Organization).filter(
        models.Organization.owner_id == current_user["user_id"]
    ).all()

# ------------------ USER ACCESSIBLE ORGS ------------------

@router.get("/my-orgs", response_model=list[schemas.Organization])
def get_orgs_user_can_access(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all organizations the current user has access to."""
    user_id = current_user.get("user_id")
    access_records = db.query(models.UserOrganizationAccess).filter_by(user_id=user_id).all()
    org_ids = [access.organization_id for access in access_records]

    if not org_ids:
        return []

    return db.query(models.Organization).filter(models.Organization.id.in_(org_ids)).all()

@router.get("/company-networks", response_model=list[schemas.Network])
def get_company_networks(
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
):
    """Get all networks in the company for company admin."""
    if current_user.get("role") != "company_admin":
        raise HTTPException(status_code=403, detail="Only company admins can access this endpoint")

    # Get all organizations in the company
    organizations = db.query(models.Organization).join(
        models.User,
        models.Organization.owner_id == models.User.id
    ).filter(
        models.User.company_id == current_user["company_id"]
    ).all()

    org_ids = [org.id for org in organizations]
    if not org_ids:
        return []

    # Get all networks for these organizations
    networks = db.query(models.Network).filter(
        models.Network.organization_id.in_(org_ids)
    ).all()

    return networks
