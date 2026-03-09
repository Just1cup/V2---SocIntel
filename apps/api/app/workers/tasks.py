from __future__ import annotations

import json
from uuid import uuid4

from app.db.session import SessionLocal
from app.models.analysis_job import AnalysisJob
from app.models.analysis_result import AnalysisResult
from app.services.legacy_analysis_adapter import run_legacy_analysis
from app.workers.celery_app import celery_app


def _normalize_verdict(payload: dict[str, object]) -> str:
    level = str(payload.get("level") or "").lower()
    if level == "alto":
        return "high_risk"
    if level == "médio" or level == "medio":
        return "medium_risk"
    return "low_risk"


@celery_app.task(name="socintel.analysis.process")
def process_analysis_job(job_id: str) -> dict[str, str]:
    db = SessionLocal()
    try:
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            return {"job_id": job_id, "status": "missing"}

        job.status = "running"
        db.commit()

        payload = run_legacy_analysis(job.ioc_type, job.ioc_value)
        normalized_verdict = _normalize_verdict(payload)
        findings_json = json.dumps(payload["findings"], ensure_ascii=False)
        meta_json = json.dumps(
            {
                "legacy_verdict": payload["verdict"],
                "recommendations": payload["recommendations"],
                "risk_factors": payload["risk_factors"],
                "risk_meta": payload["risk_meta"],
                "timings_ms": payload["timings_ms"],
                "provider_details": payload.get("provider_details") or {},
                "source": "legacy-backend-adapter",
            },
            ensure_ascii=False,
        )

        result = db.query(AnalysisResult).filter(AnalysisResult.job_id == job.id).first()
        if not result:
            result = AnalysisResult(
                id=f"result_{uuid4().hex[:24]}",
                tenant_id=job.tenant_id,
                job_id=job.id,
                owner_user_id=job.owner_user_id,
                verdict=normalized_verdict,
                level=payload["level"],
                risk_score=payload["risk"],
                findings_json=findings_json,
                meta_json=meta_json,
            )
            db.add(result)
        else:
            result.verdict = normalized_verdict
            result.level = payload["level"]
            result.risk_score = payload["risk"]
            result.findings_json = findings_json
            result.meta_json = meta_json

        job.result_payload = findings_json
        job.status = "completed"
        db.commit()
        return {"job_id": job.id, "status": job.status, "result_id": result.id}
    except Exception:
        db.rollback()
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if job:
            job.status = "failed"
            db.commit()
        raise
    finally:
        db.close()
