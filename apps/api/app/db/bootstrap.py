from app.db.session import Base, engine
from app.models import (
    AnalysisJob,
    AnalysisResult,
    AuditLog,
    SearchHistory,
    Team,
    TeamMembership,
    Tenant,
    TokenRevocation,
    User,
)


def create_all_tables() -> None:
    """Temporary bootstrap helper until Alembic migrations are added."""
    Base.metadata.create_all(bind=engine)
