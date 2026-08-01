"""Audit log routes."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import AdminUser
from app.models import AuditLog
from app.schemas import AuditLogPublic

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditLogPublic])
def list_audit_logs(
    _: AdminUser,
    db: Annotated[Session, Depends(get_db)],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[AuditLog]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    return list(db.scalars(stmt).all())
