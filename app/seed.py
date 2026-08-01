"""Seed a demo admin user when the users table is empty."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import get_settings
from app.models import User
from app.roles import Role
from app.security import hash_password

DEMO_ADMIN_EMAIL = "admin@example.com"
DEMO_ADMIN_PASSWORD = "admin123"


def seed_demo_admin(db: Session) -> User | None:
    """Create demo admin if no users exist. Returns the created user or None."""
    settings = get_settings()
    if settings.app_env == "production":
        return None

    existing = db.scalar(select(User).limit(1))
    if existing is not None:
        return None

    admin = User(
        email=DEMO_ADMIN_EMAIL,
        password_hash=hash_password(DEMO_ADMIN_PASSWORD),
        role=Role.ADMIN.value,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    write_audit(
        db,
        action="auth.seed",
        resource=f"user:{admin.id}",
        actor_user_id=admin.id,
        detail="demo admin created",
        success=True,
    )
    return admin
