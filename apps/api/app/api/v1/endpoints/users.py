from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import DbSession, require_admin
from app.models.user import User
from app.schemas.user import UserCreate, UserListItem, UserRoleUpdate
from app.services.audit_service import AuditService
from app.services.user_service import UserService

router = APIRouter()


@router.get("/", response_model=list[UserListItem])
def list_users(
    db: DbSession,
    current_user: Annotated[User, Depends(require_admin)],
) -> list[UserListItem]:
    service = UserService(db)
    users = service.list_for_tenant(current_user.tenant_id)
    return [
        UserListItem(
            id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            role=user.role,
            status=user.status,
        )
        for user in users
    ]


@router.post("/", response_model=UserListItem, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: DbSession,
    current_user: Annotated[User, Depends(require_admin)],
) -> UserListItem:
    service = UserService(db)
    existing = service.get_by_email(payload.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User email already exists.",
        )
    try:
        user = service.create(
            tenant_id=current_user.tenant_id,
            email=payload.email,
            full_name=payload.full_name,
            password=payload.password,
            role="minimum",
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    AuditService(db).record(
        action="user_created",
        resource_type="user",
        resource_id=user.id,
        actor=current_user,
        details={"role": user.role},
    )
    db.commit()
    return UserListItem(
        id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        status=user.status,
    )


@router.patch("/{user_id}/role", response_model=UserListItem)
def update_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    db: DbSession,
    current_user: Annotated[User, Depends(require_admin)],
) -> UserListItem:
    service = UserService(db)
    user = service.get_for_tenant(current_user.tenant_id, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    old_role = user.role
    updated = service.update_role(user, payload.role)
    AuditService(db).record(
        action="user_role_updated",
        resource_type="user",
        resource_id=updated.id,
        actor=current_user,
        details={"old_role": old_role, "new_role": updated.role},
    )
    db.commit()
    return UserListItem(
        id=updated.id,
        tenant_id=updated.tenant_id,
        email=updated.email,
        full_name=updated.full_name,
        role=updated.role,
        status=updated.status,
    )
