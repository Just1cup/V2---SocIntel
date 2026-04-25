from __future__ import annotations

import os
import secrets
from uuid import uuid4

from app.core.security import generate_password_salt, hash_password_with_salt
from app.db.session import SessionLocal
from app.models.membership import TeamMembership
from app.models.team import Team
from app.models.tenant import Tenant
from app.models.user import User

TENANT_ID = "tenant_default"
TEAM_ID = "team_blue"
USER_ID = "user_admin"
ADMIN_EMAIL = "admin@socintel.dev"
ADMIN_PASSWORD_ENV = "SOCINTEL_BOOTSTRAP_ADMIN_PASSWORD"


def seed() -> None:
    admin_password = os.getenv(ADMIN_PASSWORD_ENV)
    generated_password = None
    if not admin_password:
        generated_password = secrets.token_urlsafe(24)
        admin_password = generated_password

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
                password_hash=hash_password_with_salt(admin_password, password_salt),
                full_name="SOCINTEL Administrator",
                role="admin",
                status="active",
            )
            db.add(user)
            if generated_password:
                print(f"Created bootstrap admin {ADMIN_EMAIL} with password: {generated_password}")
        else:
            user.tenant_id = TENANT_ID
            user.email = ADMIN_EMAIL
            user.full_name = "SOCINTEL Administrator"
            user.role = "admin"
            user.status = "active"
            if os.getenv(ADMIN_PASSWORD_ENV):
                password_salt = generate_password_salt()
                user.password_salt = password_salt
                user.password_hash = hash_password_with_salt(admin_password, password_salt)

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

        db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    seed()
