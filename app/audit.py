"""Audit log helpers."""

from sqlalchemy.orm import Session

from app.models import AuditLog


def write_audit(
    db: Session,
    *,
    action: str,
    resource: str,
    actor_user_id: int | None = None,
    detail: str | None = None,
    ip_address: str | None = None,
    success: bool = True,
) -> AuditLog:
    entry = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        resource=resource,
        detail=detail,
        ip_address=ip_address,
        success=success,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
