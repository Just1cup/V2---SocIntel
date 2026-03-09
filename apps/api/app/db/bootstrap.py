from app.db.session import Base, engine
from app.models import (
    AnalysisJob,
    AnalysisResult,
    AuditLog,
    Case,
    Investigation,
    SearchHistory,
    Team,
    TeamMembership,
    Tenant,
    User,
)


def create_all_tables() -> None:
    """Temporary bootstrap helper until Alembic migrations are added."""
    Base.metadata.create_all(bind=engine)
