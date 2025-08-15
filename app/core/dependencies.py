from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.core.security import SECRET_KEY, ALGORITHM
from typing import Dict
import logging

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def get_current_user(token: str = Depends(oauth2_scheme)) -> Dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="❌ Invalid or missing token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        logger.info(f"[AUTH DEBUG] Raw token: {token}")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        logger.info(f"JWT Payload: {payload}")
        return payload
    except JWTError as e:
        logger.error(f"[AUTH DEBUG] JWTError: {e}")
        raise credentials_exception
