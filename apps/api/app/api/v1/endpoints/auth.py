from datetime import datetime, timedelta, timezone
from uuid import uuid4
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError, jwt
from sqlalchemy import func

from app.api.deps import DbSession, extract_access_token, get_current_user
from app.core.config import settings
from app.core.security import create_access_token, generate_password_salt, hash_password_with_salt, hash_token, verify_password_with_optional_salt
from app.models.audit_log import AuditLog
from app.models.token_revocation import TokenRevocation
from app.models.user import User
from app.schemas.auth import ChangePasswordRequest, LoginRequest, TokenResponse
from app.schemas.team import TeamMembershipSummary
from app.schemas.user import UserSummary
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter()


def _client_host(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _enforce_login_rate_limit(db: DbSession, email: str) -> None:
    window_start = datetime.now(timezone.utc) - timedelta(seconds=settings.login_rate_limit_window_seconds)
    recent_failures = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.action == "login_failed",
            AuditLog.resource_type == "auth",
            AuditLog.resource_id == email.lower(),
            AuditLog.created_at >= window_start,
        )
        .scalar()
        or 0
    )
    if recent_failures >= settings.login_rate_limit_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: DbSession) -> TokenResponse:
    _enforce_login_rate_limit(db, payload.email)
    auth_service = AuthService(db)
    auth_result = auth_service.authenticate(payload.email, payload.password)
    if not auth_result:
        AuditService(db).record(
            action="login_failed",
            resource_type="auth",
            resource_id=payload.email.lower(),
            details={"client_host": _client_host(request)},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    user, memberships = auth_result
    access_token = create_access_token(
        subject=user.email,
        expires_delta=timedelta(minutes=settings.access_token_expire_minutes),
        extra_claims={
            "tenant_id": user.tenant_id,
            "role": user.role,
            "user_id": user.id,
        },
    )
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=access_token,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite=settings.auth_cookie_samesite,
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    AuditService(db).record(
        action="login_succeeded",
        resource_type="user",
        resource_id=user.id,
        actor=user,
        details={"client_host": _client_host(request)},
    )
    db.commit()
    return TokenResponse(
        access_token=None,
        token_type="cookie",
        expires_in=settings.access_token_expire_minutes * 60,
        user=UserSummary(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            status=user.status,
        ),
        memberships=[
            TeamMembershipSummary(
                id=item.id,
                tenant_id=item.tenant_id,
                team_id=item.team_id,
                user_id=item.user_id,
                role=item.role,
            )
            for item in memberships
        ],
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    token = extract_access_token(request)
    if token:
        try:
            payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
            expires_at = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
            jti = payload.get("jti")
        except (JWTError, KeyError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials.",
            ) from exc
        db.add(
            TokenRevocation(
                id=f"revoked_{uuid4().hex[:24]}",
                tenant_id=current_user.tenant_id,
                token_hash=hash_token(token),
                jti=jti,
                user_id=current_user.id,
                expires_at=expires_at,
            )
        )
        AuditService(db).record(
            action="logout",
            resource_type="user",
            resource_id=current_user.id,
            actor=current_user,
        )
        db.commit()
    response.delete_cookie(
        key=settings.auth_cookie_name,
        path="/",
        samesite=settings.auth_cookie_samesite,
    )
    return response


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> Response:
    if not verify_password_with_optional_salt(
        payload.current_password,
        current_user.password_hash,
        current_user.password_salt,
    ):
        AuditService(db).record(
            action="password_change_failed",
            resource_type="user",
            resource_id=current_user.id,
            actor=current_user,
            details={"reason": "invalid_current_password", "client_host": _client_host(request)},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is invalid.",
        )
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from the current password.",
        )

    password_salt = generate_password_salt()
    current_user.password_salt = password_salt
    current_user.password_hash = hash_password_with_salt(payload.new_password, password_salt)
    AuditService(db).record(
        action="password_changed",
        resource_type="user",
        resource_id=current_user.id,
        actor=current_user,
        details={"client_host": _client_host(request)},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
