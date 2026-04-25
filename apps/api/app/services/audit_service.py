from __future__ import annotations

import json
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.user import User


class AuditService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def record(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str,
        actor: User | None = None,
        tenant_id: str | None = None,
        details: dict | None = None,
    ) -> AuditLog:
        item = AuditLog(
            id=f"audit_{uuid4().hex[:24]}",
            tenant_id=tenant_id or (actor.tenant_id if actor else "tenant_unknown"),
            actor_user_id=actor.id if actor else None,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            details_json=json.dumps(details or {}, sort_keys=True),
        )
        self.db.add(item)
        return item
