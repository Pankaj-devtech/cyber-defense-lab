"""Authentication routes: register, login, me."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import write_audit
from app.config import get_settings
from app.db import get_db
from app.deps import CurrentUser
from app.models import User
from app.roles import Role
from app.schemas import TokenResponse, UserCreate, UserPublic
from app.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


def _client_ip(request: Request) -> str | None:
    if request.client:
        return request.client.host
    return None


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
) -> User:
    settings = get_settings()
    if not settings.allow_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is disabled",
        )

    existing = db.scalar(select(User).where(User.email == payload.email.lower()))
    if existing:
        write_audit(
            db,
            action="auth.register",
            resource=f"user:{payload.email.lower()}",
            detail="email already registered",
            ip_address=_client_ip(request),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Public registration cannot self-assign admin.
    role = payload.role if payload.role != Role.ADMIN else Role.ANALYST

    user = User(
        email=payload.email.lower(),
        password_hash=hash_password(payload.password),
        role=role.value,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit(
        db,
        action="auth.register",
        resource=f"user:{user.id}",
        actor_user_id=user.id,
        detail=f"role={user.role}",
        ip_address=_client_ip(request),
        success=True,
    )
    return user


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> TokenResponse:
    email = form_data.username.lower().strip()
    user = db.scalar(select(User).where(User.email == email))

    if user is None or not verify_password(form_data.password, user.password_hash):
        write_audit(
            db,
            action="auth.login",
            resource=f"user:{email}",
            detail="invalid credentials",
            ip_address=_client_ip(request),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        write_audit(
            db,
            action="auth.login",
            resource=f"user:{user.id}",
            actor_user_id=user.id,
            detail="inactive account",
            ip_address=_client_ip(request),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    token = create_access_token(
        subject=str(user.id),
        extra_claims={"role": user.role, "email": user.email},
    )
    write_audit(
        db,
        action="auth.login",
        resource=f"user:{user.id}",
        actor_user_id=user.id,
        detail="token issued",
        ip_address=_client_ip(request),
        success=True,
    )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserPublic)
def me(user: CurrentUser) -> User:
    return user
