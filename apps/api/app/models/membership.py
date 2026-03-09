from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.base import TenantOwnedMixin, TimestampMixin


class TeamMembership(TenantOwnedMixin, TimestampMixin, Base):
    __tablename__ = "team_memberships"
    __table_args__ = (
        UniqueConstraint("tenant_id", "team_id", "user_id", name="uq_team_membership"),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    role: Mapped[str] = mapped_column(String(32), default="member", index=True)
