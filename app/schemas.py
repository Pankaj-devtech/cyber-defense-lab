"""Shared Pydantic schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.roles import Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    role: Role = Role.ANALYST


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    role: Role
    is_active: bool
    created_at: datetime


class AuditLogPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_user_id: int | None
    action: str
    resource: str
    detail: str | None
    ip_address: str | None
    success: bool
    created_at: datetime
