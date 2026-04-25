from datetime import datetime, timedelta, timezone
from uuid import uuid4
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError, jwt

from app.api.deps import DbSession, extract_access_token, get_current_user
from app.core.config import settings
from app.core.security import create_access_token, hash_token
from app.models.token_revocation import TokenRevocation
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.team import TeamMembershipSummary
from app.schemas.user import UserSummary
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter()
_login_failures: dict[str, list[float]] = {}


def _rate_limit_key(request: Request, email: str) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "")
    client_host = forwarded_for.split(",", 1)[0].strip() or (request.client.host if request.client else "unknown")
    return f"{client_host}:{email.lower()}"


def _enforce_login_rate_limit(request: Request, email: str) -> None:
    now = datetime.now(timezone.utc).timestamp()
    window_start = now - settings.login_rate_limit_window_seconds
    key = _rate_limit_key(request, email)
    recent_failures = [item for item in _login_failures.get(key, []) if item >= window_start]
    _login_failures[key] = recent_failures
    if len(recent_failures) >= settings.login_rate_limit_attempts:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Try again later.",
        )


def _record_login_failure(request: Request, email: str) -> None:
    key = _rate_limit_key(request, email)
    _login_failures.setdefault(key, []).append(datetime.now(timezone.utc).timestamp())


def _clear_login_failures(request: Request, email: str) -> None:
    _login_failures.pop(_rate_limit_key(request, email), None)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: DbSession) -> TokenResponse:
    _enforce_login_rate_limit(request, payload.email)
    auth_service = AuthService(db)
    auth_result = auth_service.authenticate(payload.email, payload.password)
    if not auth_result:
        _record_login_failure(request, payload.email)
        AuditService(db).record(
            action="login_failed",
            resource_type="auth",
            resource_id=payload.email.lower(),
            details={"client_host": request.client.host if request.client else None},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    user, memberships = auth_result
    _clear_login_failures(request, payload.email)
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
        details={"client_host": request.client.host if request.client else None},
    )
    db.commit()
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
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
