from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import DbSession, get_current_user
from app.models.user import User
from app.schemas.analysis import AnalysisJobCreate, AnalysisJobDetail, AnalysisJobResponse, AnalysisResultSummary
from app.services.analysis_service import AnalysisService

router = APIRouter()


@router.post("/", response_model=AnalysisJobResponse)
def create_analysis_job(
    payload: AnalysisJobCreate,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> AnalysisJobResponse:
    service = AnalysisService(db)
    job = service.enqueue(
        user=current_user,
        ioc_type=payload.ioc_type,
        ioc_value=payload.ioc_value,
        case_id=payload.case_id,
        investigation_id=payload.investigation_id,
    )
    return AnalysisJobResponse(
        id=job.id,
        tenant_id=job.tenant_id,
        case_id=job.case_id,
        investigation_id=job.investigation_id,
        ioc_type=job.ioc_type,
        ioc_value=job.ioc_value,
        status=job.status,
        priority=job.priority,
    )


@router.get("/", response_model=list[AnalysisJobDetail])
def list_analysis_jobs(
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
    case_id: str | None = None,
    investigation_id: str | None = None,
) -> list[AnalysisJobDetail]:
    service = AnalysisService(db)
    jobs = service.list_jobs_for_user(
        current_user,
        case_id=case_id,
        investigation_id=investigation_id,
    )
    return [
        AnalysisJobDetail(
            id=job.id,
            tenant_id=job.tenant_id,
            case_id=job.case_id,
            investigation_id=job.investigation_id,
            owner_user_id=job.owner_user_id,
            requested_by_user_id=job.requested_by_user_id,
            ioc_type=job.ioc_type,
            ioc_value=job.ioc_value,
            status=job.status,
            priority=job.priority,
            provider_fingerprint=job.provider_fingerprint,
            result_payload=service.decode_json(job.result_payload, None),
        )
        for job in jobs
    ]


@router.get("/{job_id}", response_model=AnalysisJobDetail)
def get_analysis_job(
    job_id: str,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> AnalysisJobDetail:
    service = AnalysisService(db)
    job = service.get_job_for_user(current_user, job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return AnalysisJobDetail(
        id=job.id,
        tenant_id=job.tenant_id,
        case_id=job.case_id,
        investigation_id=job.investigation_id,
        owner_user_id=job.owner_user_id,
        requested_by_user_id=job.requested_by_user_id,
        ioc_type=job.ioc_type,
        ioc_value=job.ioc_value,
        status=job.status,
        priority=job.priority,
        provider_fingerprint=job.provider_fingerprint,
        result_payload=service.decode_json(job.result_payload, None),
    )


@router.get("/{job_id}/result", response_model=AnalysisResultSummary)
def get_analysis_result(
    job_id: str,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> AnalysisResultSummary:
    service = AnalysisService(db)
    result = service.get_result_for_user(current_user, job_id)
    if not result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Result not found.")
    return AnalysisResultSummary(**service.build_result_payload(result))
