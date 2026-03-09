from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.core.security import generate_password_salt, hash_password_with_salt
from app.models.user import User


class UserService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_for_tenant(self, tenant_id: str) -> list[User]:
        return (
            self.db.query(User)
            .filter(User.tenant_id == tenant_id, User.deleted_at.is_(None))
            .order_by(User.created_at.desc())
            .all()
        )

    def get_by_email(self, email: str) -> User | None:
        return self.db.query(User).filter(User.email == email, User.deleted_at.is_(None)).first()

    def create(
        self,
        *,
        tenant_id: str,
        email: str,
        full_name: str,
        password: str,
        role: str = "minimum",
    ) -> User:
        user = User(
            id=f"user_{uuid4().hex[:24]}",
            tenant_id=tenant_id,
            email=email.lower().strip(),
            password_salt=generate_password_salt(),
            password_hash="",
            full_name=full_name.strip(),
            role=role.strip().lower(),
            status="active",
        )
        user.password_hash = hash_password_with_salt(password, user.password_salt)
        self.db.add(user)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise ValueError("User email already exists.")
        self.db.refresh(user)
        return user

    def get_for_tenant(self, tenant_id: str, user_id: str) -> User | None:
        return (
            self.db.query(User)
            .filter(User.id == user_id, User.tenant_id == tenant_id, User.deleted_at.is_(None))
            .first()
        )

    def update_role(self, user: User, role: str) -> User:
        user.role = role.strip().lower()
        self.db.commit()
        self.db.refresh(user)
        return user
