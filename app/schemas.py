"""Shared Pydantic schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.roles import Role
from app.scenarios import Scenario


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


class SimulateRequest(BaseModel):
    scenario: Scenario = Scenario.MIXED
    count: int = Field(default=12, ge=1, le=200)
    seed: int | None = None


class SimulatedEventPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scenario: str
    event_type: str
    source_ip: str
    dest_ip: str
    dest_port: int
    protocol: str
    summary: str
    is_malicious: bool
    created_by: int | None
    created_at: datetime


class DetectionPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int
    rule_id: str
    rule_name: str
    severity: str
    message: str
    mitre_technique: str | None
    created_at: datetime


class RulePublic(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str
    mitre_technique: str | None


class SimulateResponse(BaseModel):
    scenario: Scenario
    events_created: int
    detections_created: int
    events: list[SimulatedEventPublic]
    detections: list[DetectionPublic]
