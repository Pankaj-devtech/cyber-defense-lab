"""Role constants and helpers for RBAC."""

from enum import StrEnum


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


ROLE_RANK = {
    Role.VIEWER: 1,
    Role.ANALYST: 2,
    Role.ADMIN: 3,
}


def has_min_role(user_role: str, required: Role) -> bool:
    return ROLE_RANK.get(Role(user_role), 0) >= ROLE_RANK[required]
