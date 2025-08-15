from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime
import re

def validate_email(email: str) -> str:
    """Simple email validation"""
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        raise ValueError("Invalid email format")
    return email

class UserBase(BaseModel):
    email: str = Field(..., description="User's email address")
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: bool = True
    role: str = "user"

    @classmethod
    def validate_email(cls, v: str) -> str:
        return validate_email(v)

class UserCreate(UserBase):
    password: str

class UserUpdate(UserBase):
    password: Optional[str] = None

class UserInDBBase(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class User(UserInDBBase):
    pass

class UserInDB(UserInDBBase):
    hashed_password: str 