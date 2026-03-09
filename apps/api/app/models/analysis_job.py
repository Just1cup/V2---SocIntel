from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.base import TenantOwnedMixin, TimestampMixin


class AnalysisJob(TenantOwnedMixin, TimestampMixin, Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)
    owner_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id"), nullable=True, index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    ioc_value: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    priority: Mapped[str] = mapped_column(String(16), default="normal", index=True)
    requested_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    provider_fingerprint: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    result_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
