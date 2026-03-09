from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.api.deps import DbSession
from app.core.config import settings
from app.core.security import create_access_token
from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.team import TeamMembershipSummary
from app.schemas.user import UserSummary
from app.services.auth_service import AuthService

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, response: Response, db: DbSession) -> TokenResponse:
    auth_service = AuthService(db)
    auth_result = auth_service.authenticate(payload.email, payload.password)
    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )
    user, memberships = auth_result
    access_token = create_access_token(
        subject=user.email,
        expires_delta=timedelta(minutes=30),
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
        max_age=1800,
        path="/",
    )
    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=1800,
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
def logout(response: Response) -> Response:
    response.delete_cookie(
        key=settings.auth_cookie_name,
        path="/",
        samesite=settings.auth_cookie_samesite,
    )
    return response
