from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_token
from app.db.session import get_db
from app.models.token_revocation import TokenRevocation
from app.models.user import User

DbSession = Annotated[Session, Depends(get_db)]


def extract_access_token(request: Request) -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.removeprefix("Bearer ").strip()
    cookie_token = request.cookies.get(settings.auth_cookie_name)
    if cookie_token:
        return cookie_token
    return None


def get_current_user(
    request: Request,
    db: DbSession,
) -> User:
    token = extract_access_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
        subject = payload.get("sub")
        jti = payload.get("jti")
        if not subject:
            raise credentials_exception
    except JWTError as exc:
        raise credentials_exception from exc

    token_hash = hash_token(token)
    revoked_token = db.query(TokenRevocation).filter(TokenRevocation.token_hash == token_hash).first()
    if not revoked_token and jti:
        revoked_token = db.query(TokenRevocation).filter(TokenRevocation.jti == jti).first()
    if revoked_token:
        raise credentials_exception

    user = db.query(User).filter(User.email == subject, User.deleted_at.is_(None)).first()
    if not user or user.status != "active":
        raise credentials_exception
    return user


def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user
