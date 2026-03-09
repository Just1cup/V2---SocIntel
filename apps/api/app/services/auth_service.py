from sqlalchemy.orm import Session

from app.core.security import verify_password_with_optional_salt
from app.models.membership import TeamMembership
from app.models.user import User


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def authenticate(self, email: str, password: str) -> tuple[User, list[TeamMembership]] | None:
        user = self.db.query(User).filter(User.email == email, User.deleted_at.is_(None)).first()
        if not user or user.status != "active":
            return None
        if not verify_password_with_optional_salt(password, user.password_hash, user.password_salt):
            return None
        memberships = (
            self.db.query(TeamMembership)
            .filter(TeamMembership.user_id == user.id, TeamMembership.tenant_id == user.tenant_id)
            .all()
        )
        return user, memberships
