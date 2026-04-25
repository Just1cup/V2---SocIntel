from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.deps import get_current_user
from app.models.user import User
from app.schemas.threat_feed import TaxiiResponse, TaxiiSourceSummary
from app.services.taxii_service import TaxiiNotFoundError, TaxiiServiceError, TaxiiUpstreamError, taxii_service

router = APIRouter()


def _handle_taxii_error(exc: Exception) -> HTTPException:
    if isinstance(exc, TaxiiNotFoundError):
        return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    if isinstance(exc, TaxiiServiceError) and not isinstance(exc, TaxiiUpstreamError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))


def _response(source_id: str, endpoint: str, data: dict) -> TaxiiResponse:
    source = taxii_service.get_source(source_id)
    return TaxiiResponse(source=TaxiiSourceSummary(**source.summary), endpoint=endpoint, data=data)


@router.get("/taxii/sources", response_model=list[TaxiiSourceSummary])
def list_taxii_sources(_: Annotated[User, Depends(get_current_user)]) -> list[TaxiiSourceSummary]:
    return [TaxiiSourceSummary(**source.summary) for source in taxii_service.list_sources()]


@router.get("/taxii/sources/{source_id}/discovery", response_model=TaxiiResponse)
def get_taxii_discovery(
    source_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "discovery", taxii_service.discovery(source_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/api-root", response_model=TaxiiResponse)
def get_taxii_api_root(
    source_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "api_root", taxii_service.api_root(source_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections", response_model=TaxiiResponse)
def list_taxii_collections(
    source_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "collections", taxii_service.collections(source_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections/{collection_id}", response_model=TaxiiResponse)
def get_taxii_collection(
    source_id: str,
    collection_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "collection", taxii_service.collection(source_id, collection_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections/{collection_id}/manifest", response_model=TaxiiResponse)
def get_taxii_manifest(
    source_id: str,
    collection_id: str,
    _: Annotated[User, Depends(get_current_user)],
    object_type: Annotated[str | None, Query(alias="type")] = None,
    object_id: Annotated[str | None, Query(alias="id")] = None,
    added_after: str | None = None,
) -> TaxiiResponse:
    try:
        data = taxii_service.manifest(
            source_id,
            collection_id,
            object_type=object_type,
            object_id=object_id,
            added_after=added_after,
        )
        return _response(source_id, "manifest", data)
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections/{collection_id}/objects", response_model=TaxiiResponse)
def get_taxii_objects(
    source_id: str,
    collection_id: str,
    _: Annotated[User, Depends(get_current_user)],
    object_type: Annotated[str | None, Query(alias="type")] = None,
    object_id: Annotated[str | None, Query(alias="id")] = None,
    added_after: str | None = None,
) -> TaxiiResponse:
    try:
        data = taxii_service.objects(
            source_id,
            collection_id,
            object_type=object_type,
            object_id=object_id,
            added_after=added_after,
        )
        return _response(source_id, "objects", data)
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections/{collection_id}/objects/{object_id}", response_model=TaxiiResponse)
def get_taxii_object(
    source_id: str,
    collection_id: str,
    object_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "object", taxii_service.object(source_id, collection_id, object_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc


@router.get("/taxii/sources/{source_id}/collections/{collection_id}/objects/{object_id}/versions", response_model=TaxiiResponse)
def get_taxii_object_versions(
    source_id: str,
    collection_id: str,
    object_id: str,
    _: Annotated[User, Depends(get_current_user)],
) -> TaxiiResponse:
    try:
        return _response(source_id, "versions", taxii_service.versions(source_id, collection_id, object_id))
    except (TaxiiServiceError, TaxiiUpstreamError) as exc:
        raise _handle_taxii_error(exc) from exc

