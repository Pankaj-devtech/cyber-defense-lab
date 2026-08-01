"""FastAPI auth dependencies."""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import User
from app.roles import Role, has_min_role
from app.security import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
    except ValueError as exc:
        raise credentials_exception from exc

    subject = payload.get("sub")
    if subject is None:
        raise credentials_exception

    try:
        user_id = int(subject)
    except (TypeError, ValueError) as exc:
        raise credentials_exception from exc

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise credentials_exception
    return user


def require_min_role(min_role: Role) -> Callable[..., User]:
    def _dependency(user: Annotated[User, Depends(get_current_user)]) -> User:
        try:
            ok = has_min_role(user.role, min_role)
        except ValueError:
            ok = False
        if not ok:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient role",
            )
        return user

    return _dependency


CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_min_role(Role.ADMIN))]
AnalystUser = Annotated[User, Depends(require_min_role(Role.ANALYST))]
