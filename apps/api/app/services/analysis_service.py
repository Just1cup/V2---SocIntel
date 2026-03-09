from __future__ import annotations

import json
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models.analysis_job import AnalysisJob
from app.models.analysis_result import AnalysisResult
from app.models.user import User
from app.workers.tasks import process_analysis_job


class AnalysisService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def enqueue(
        self,
        *,
        user: User,
        ioc_type: str,
        ioc_value: str,
        case_id: str | None = None,
        investigation_id: str | None = None,
    ) -> AnalysisJob:
        job = AnalysisJob(
            id=f"job_{uuid4().hex[:24]}",
            tenant_id=user.tenant_id,
            case_id=case_id,
            investigation_id=investigation_id,
            owner_user_id=user.id,
            requested_by_user_id=user.id,
            team_id=None,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            status="queued",
            priority="normal",
        )
        self.db.add(job)
        self.db.commit()
        self.db.refresh(job)
        process_analysis_job.delay(job.id)
        return job

    def get_job_for_user(self, user: User, job_id: str) -> AnalysisJob | None:
        return (
            self.db.query(AnalysisJob)
            .filter(
                AnalysisJob.id == job_id,
                AnalysisJob.tenant_id == user.tenant_id,
            )
            .first()
        )

    def list_jobs_for_user(
        self,
        user: User,
        *,
        case_id: str | None = None,
        investigation_id: str | None = None,
    ) -> list[AnalysisJob]:
        query = self.db.query(AnalysisJob).filter(AnalysisJob.tenant_id == user.tenant_id)
        if case_id:
            query = query.filter(AnalysisJob.case_id == case_id)
        if investigation_id:
            query = query.filter(AnalysisJob.investigation_id == investigation_id)
        return query.order_by(AnalysisJob.created_at.desc()).limit(50).all()

    def get_result_for_user(self, user: User, job_id: str) -> AnalysisResult | None:
        return (
            self.db.query(AnalysisResult)
            .join(AnalysisJob, AnalysisResult.job_id == AnalysisJob.id)
            .filter(
                AnalysisResult.tenant_id == user.tenant_id,
                AnalysisJob.id == job_id,
            )
            .first()
        )

    @staticmethod
    def decode_json(value: str | None, fallback):
        if not value:
            return fallback
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return fallback

    def build_result_payload(self, result: AnalysisResult) -> dict:
        meta = self.decode_json(result.meta_json, {})
        return {
            "id": result.id,
            "tenant_id": result.tenant_id,
            "job_id": result.job_id,
            "verdict": result.verdict,
            "level": result.level,
            "risk_score": result.risk_score,
            "findings": self.decode_json(result.findings_json, []),
            "recommendations": meta.get("recommendations", []),
            "risk_factors": meta.get("risk_factors", []),
            "risk_meta": meta.get("risk_meta", {}),
            "timings_ms": meta.get("timings_ms", {}),
            "provider_details": meta.get("provider_details", {}),
            "legacy_verdict": meta.get("legacy_verdict"),
        }
