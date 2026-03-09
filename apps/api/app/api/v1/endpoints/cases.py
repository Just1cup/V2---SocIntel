from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import DbSession, get_current_user
from app.models.user import User
from app.schemas.case import CaseCreate, CaseDetail, CaseSummary
from app.schemas.investigation import InvestigationCreate, InvestigationSummary
from app.services.case_service import CaseService

router = APIRouter()


@router.get("/", response_model=list[CaseSummary])
def list_cases(
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[CaseSummary]:
    service = CaseService(db)
    cases = service.list_cases_for_user(current_user)
    return [
        CaseSummary(
            id=item.id,
            tenant_id=item.tenant_id,
            owner_user_id=item.owner_user_id,
            name=item.name,
            status=item.status,
            visibility=item.visibility,
        )
        for item in cases
    ]


@router.post("/", response_model=CaseDetail, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> CaseDetail:
    service = CaseService(db)
    item = service.create_case(
        user=current_user,
        name=payload.name,
        description=payload.description,
        visibility=payload.visibility,
    )
    return CaseDetail(
        id=item.id,
        tenant_id=item.tenant_id,
        owner_user_id=item.owner_user_id,
        team_id=item.team_id,
        name=item.name,
        description=item.description,
        status=item.status,
        visibility=item.visibility,
    )


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(
    case_id: str,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> CaseDetail:
    service = CaseService(db)
    item = service.get_case_for_user(current_user, case_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return CaseDetail(
        id=item.id,
        tenant_id=item.tenant_id,
        owner_user_id=item.owner_user_id,
        team_id=item.team_id,
        name=item.name,
        description=item.description,
        status=item.status,
        visibility=item.visibility,
    )


@router.get("/{case_id}/investigations", response_model=list[InvestigationSummary])
def list_case_investigations(
    case_id: str,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> list[InvestigationSummary]:
    service = CaseService(db)
    investigations = service.list_investigations_for_case(current_user, case_id)
    return [
        InvestigationSummary(
            id=item.id,
            tenant_id=item.tenant_id,
            case_id=item.case_id,
            owner_user_id=item.owner_user_id,
            title=item.title,
            status=item.status,
        )
        for item in investigations
    ]


@router.post("/{case_id}/investigations", response_model=InvestigationSummary, status_code=status.HTTP_201_CREATED)
def create_case_investigation(
    case_id: str,
    payload: InvestigationCreate,
    db: DbSession,
    current_user: Annotated[User, Depends(get_current_user)],
) -> InvestigationSummary:
    service = CaseService(db)
    item = service.create_investigation(
        user=current_user,
        case_id=case_id,
        title=payload.title,
        summary=payload.summary,
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found.")
    return InvestigationSummary(
        id=item.id,
        tenant_id=item.tenant_id,
        case_id=item.case_id,
        owner_user_id=item.owner_user_id,
        title=item.title,
        status=item.status,
    )
