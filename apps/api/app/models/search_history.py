from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base
from app.models.base import TenantOwnedMixin, TimestampMixin


class SearchHistory(TenantOwnedMixin, TimestampMixin, Base):
    __tablename__ = "search_history"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    case_id: Mapped[str | None] = mapped_column(ForeignKey("cases.id"), nullable=True, index=True)
    investigation_id: Mapped[str | None] = mapped_column(ForeignKey("investigations.id"), nullable=True, index=True)
    analysis_job_id: Mapped[str | None] = mapped_column(ForeignKey("analysis_jobs.id"), nullable=True, index=True)
    ioc_type: Mapped[str] = mapped_column(String(32), index=True)
    ioc_value: Mapped[str] = mapped_column(String(1024))
