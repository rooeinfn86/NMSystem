"""
Google Cloud Secret Manager integration for secure secret handling.
"""
import os
from typing import Optional
from google.cloud import secretmanager
from google.api_core import exceptions
import logging

logger = logging.getLogger(__name__)

# Initialize the Secret Manager client
try:
    client = secretmanager.SecretManagerServiceClient()
    logger.info("✅ Secret Manager client initialized")
except Exception as e:
    logger.warning(f"⚠️ Failed to initialize Secret Manager client: {e}")
    client = None

def get_secret(secret_id: str, project_id: Optional[str] = None) -> str:
    """
    Fetch a secret from Google Cloud Secret Manager.
    
    Args:
        secret_id: The name of the secret (e.g., 'backend-secret-key')
        project_id: Google Cloud project ID (optional, uses default if not provided)
    
    Returns:
        The secret value as a string
    
    Raises:
        Exception: If secret cannot be fetched
    """
    if not project_id:
        project_id = os.getenv('GOOGLE_CLOUD_PROJECT', 'vital-wavelet-465419-q9')
    
    # Build the resource name of the secret version
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    
    try:
        # Access the secret version
        response = client.access_secret_version(request={"name": name})
        secret_value = response.payload.data.decode("UTF-8").strip()
        logger.info(f"✅ Successfully fetched secret '{secret_id}'")
        return secret_value
    except exceptions.NotFound:
        raise Exception(f"Secret '{secret_id}' not found in project '{project_id}'")
    except exceptions.PermissionDenied:
        raise Exception(f"Permission denied accessing secret '{secret_id}'")
    except Exception as e:
        raise Exception(f"Error fetching secret '{secret_id}': {str(e)}")

def get_secret_with_fallback(secret_id: str, env_var: str, default_value: Optional[str] = None) -> str:
    """
    Fetch a secret from Secret Manager with fallback to environment variable and default value.
    
    Args:
        secret_id: The name of the secret in Secret Manager
        env_var: Environment variable name to use as fallback
        default_value: Default value to use if both Secret Manager and environment variable fail
    
    Returns:
        The secret value, either from Secret Manager, environment variable, or default
    """
    # Try Secret Manager first
    if client:
        try:
            return get_secret(secret_id)
        except Exception as e:
            logger.warning(f"⚠️ Failed to get secret '{secret_id}' from Secret Manager: {e}")
    else:
        logger.warning("⚠️ Secret Manager client not available")
    
    # Fallback to environment variable
    env_value = os.getenv(env_var)
    if env_value:
        logger.info(f"✅ Using environment variable {env_var}")
        return env_value
    
    # Use default value as last resort
    if default_value is not None:
        logger.warning(f"⚠️ Using default value for {secret_id}")
        return default_value
    
    raise Exception(f"No value available for secret '{secret_id}' (tried Secret Manager, {env_var}, and default)")

def is_secret_manager_available() -> bool:
    """Check if Secret Manager is available"""
    return client is not None 