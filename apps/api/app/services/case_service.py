from __future__ import annotations

from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.investigation import Investigation
from app.models.user import User


class CaseService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_cases_for_user(self, user: User) -> list[Case]:
        return (
            self.db.query(Case)
            .filter(
                Case.tenant_id == user.tenant_id,
                Case.deleted_at.is_(None),
                (Case.owner_user_id == user.id) | (Case.visibility == "team"),
            )
            .order_by(Case.created_at.desc())
            .all()
        )

    def get_case_for_user(self, user: User, case_id: str) -> Case | None:
        return (
            self.db.query(Case)
            .filter(
                Case.id == case_id,
                Case.tenant_id == user.tenant_id,
                Case.deleted_at.is_(None),
                (Case.owner_user_id == user.id) | (Case.visibility == "team"),
            )
            .first()
        )

    def create_case(
        self,
        *,
        user: User,
        name: str,
        description: str | None,
        visibility: str,
    ) -> Case:
        case = Case(
            id=f"case_{uuid4().hex[:24]}",
            tenant_id=user.tenant_id,
            owner_user_id=user.id,
            team_id=None,
            name=name,
            description=description,
            status="open",
            visibility=visibility,
        )
        self.db.add(case)
        self.db.commit()
        self.db.refresh(case)
        return case

    def list_investigations_for_case(self, user: User, case_id: str) -> list[Investigation]:
        return (
            self.db.query(Investigation)
            .join(Case, Investigation.case_id == Case.id)
            .filter(
                Investigation.tenant_id == user.tenant_id,
                Investigation.case_id == case_id,
                Investigation.deleted_at.is_(None),
                Case.deleted_at.is_(None),
            )
            .order_by(Investigation.created_at.desc())
            .all()
        )

    def create_investigation(
        self,
        *,
        user: User,
        case_id: str,
        title: str,
        summary: str | None,
    ) -> Investigation | None:
        case = self.get_case_for_user(user, case_id)
        if not case:
            return None
        investigation = Investigation(
            id=f"investigation_{uuid4().hex[:24]}",
            tenant_id=user.tenant_id,
            case_id=case_id,
            owner_user_id=user.id,
            title=title,
            summary=summary,
            status="open",
        )
        self.db.add(investigation)
        self.db.commit()
        self.db.refresh(investigation)
        return investigation
