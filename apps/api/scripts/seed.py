from __future__ import annotations

from uuid import uuid4

from app.core.security import generate_password_salt, hash_password_with_salt
from app.db.session import SessionLocal
from app.models.case import Case
from app.models.investigation import Investigation
from app.models.membership import TeamMembership
from app.models.team import Team
from app.models.tenant import Tenant
from app.models.user import User

TENANT_ID = "tenant_default"
TEAM_ID = "team_blue"
USER_ID = "user_admin"
CASE_ID = "case_bootstrap"
INVESTIGATION_ID = "investigation_bootstrap"
ADMIN_EMAIL = "admin@socintel.dev"
ADMIN_PASSWORD = "Admin@123"


def seed() -> None:
    db = SessionLocal()
    try:
        tenant = db.query(Tenant).filter(Tenant.id == TENANT_ID).first()
        if not tenant:
            tenant = Tenant(
                id=TENANT_ID,
                name="SOCINTEL Default Tenant",
                slug="socintel-default",
                status="active",
            )
            db.add(tenant)

        user = db.query(User).filter(User.id == USER_ID).first()
        if not user:
            password_salt = generate_password_salt()
            user = User(
                id=USER_ID,
                tenant_id=TENANT_ID,
                email=ADMIN_EMAIL,
                password_salt=password_salt,
                password_hash=hash_password_with_salt(ADMIN_PASSWORD, password_salt),
                full_name="SOCINTEL Administrator",
                role="admin",
                status="active",
            )
            db.add(user)
        else:
            password_salt = generate_password_salt()
            user.tenant_id = TENANT_ID
            user.email = ADMIN_EMAIL
            user.password_salt = password_salt
            user.password_hash = hash_password_with_salt(ADMIN_PASSWORD, password_salt)
            user.full_name = "SOCINTEL Administrator"
            user.role = "admin"
            user.status = "active"

        db.flush()

        team = db.query(Team).filter(Team.id == TEAM_ID).first()
        if not team:
            team = Team(
                id=TEAM_ID,
                tenant_id=TENANT_ID,
                name="Blue Team",
                slug="blue-team",
                created_by_user_id=USER_ID,
            )
            db.add(team)

        db.flush()

        membership = db.query(TeamMembership).filter(TeamMembership.team_id == TEAM_ID, TeamMembership.user_id == USER_ID).first()
        if not membership:
            db.add(
                TeamMembership(
                    id=f"membership_{uuid4().hex[:24]}",
                    tenant_id=TENANT_ID,
                    team_id=TEAM_ID,
                    user_id=USER_ID,
                    role="lead",
                )
            )

        case_item = db.query(Case).filter(Case.id == CASE_ID).first()
        if not case_item:
            db.add(
                Case(
                    id=CASE_ID,
                    tenant_id=TENANT_ID,
                    owner_user_id=USER_ID,
                    team_id=TEAM_ID,
                    name="Bootstrap Investigation",
                    description="Initial shared case for validating auth and persistence.",
                    status="open",
                    visibility="team",
                )
            )

        investigation = db.query(Investigation).filter(Investigation.id == INVESTIGATION_ID).first()
        if not investigation:
            db.add(
                Investigation(
                    id=INVESTIGATION_ID,
                    tenant_id=TENANT_ID,
                    case_id=CASE_ID,
                    owner_user_id=USER_ID,
                    title="Initial IOC Triage",
                    summary="Seeded investigation for API validation.",
                    status="open",
                )
            )

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
