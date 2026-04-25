from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

from app.core.config import settings

TAXII_ACCEPT_HEADER = "application/taxii+json;version=2.1"


@dataclass(frozen=True)
class TaxiiSource:
    id: str
    name: str
    description: str
    base_url: str
    api_root: str

    @property
    def summary(self) -> dict[str, str]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "base_url": self.base_url,
            "api_root": self.api_root,
        }


class TaxiiServiceError(Exception):
    pass


class TaxiiNotFoundError(TaxiiServiceError):
    pass


class TaxiiUpstreamError(TaxiiServiceError):
    pass


class TaxiiService:
    def __init__(self) -> None:
        self._cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._sources = {
            "mitre-attack": TaxiiSource(
                id="mitre-attack",
                name="MITRE ATT&CK TAXII 2.1",
                description="MITRE ATT&CK Enterprise, ICS, and Mobile collections served over TAXII 2.1.",
                base_url=settings.taxii_mitre_base_url.rstrip("/"),
                api_root="/" + settings.taxii_mitre_api_root.strip("/"),
            )
        }

    def list_sources(self) -> list[TaxiiSource]:
        return list(self._sources.values())

    def get_source(self, source_id: str) -> TaxiiSource:
        source = self._sources.get(source_id)
        if not source:
            raise TaxiiNotFoundError("TAXII source not found.")
        return source

    def discovery(self, source_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        return self._get_json(source, "/taxii2/")

    def api_root(self, source_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        return self._get_json(source, f"{source.api_root}/")

    def collections(self, source_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        return self._get_json(source, f"{source.api_root}/collections/")

    def collection(self, source_id: str, collection_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        safe_collection_id = quote(collection_id, safe="")
        return self._get_json(source, f"{source.api_root}/collections/{safe_collection_id}/")

    def manifest(
        self,
        source_id: str,
        collection_id: str,
        *,
        object_type: str | None = None,
        object_id: str | None = None,
        added_after: str | None = None,
    ) -> dict[str, Any]:
        source = self.get_source(source_id)
        safe_collection_id = quote(collection_id, safe="")
        return self._get_json(
            source,
            f"{source.api_root}/collections/{safe_collection_id}/manifest/",
            params=self._build_filter_params(object_type=object_type, object_id=object_id, added_after=added_after),
        )

    def objects(
        self,
        source_id: str,
        collection_id: str,
        *,
        object_type: str | None = None,
        object_id: str | None = None,
        added_after: str | None = None,
    ) -> dict[str, Any]:
        if not any([object_type, object_id, added_after]):
            raise TaxiiServiceError("At least one filter is required for TAXII object queries.")
        source = self.get_source(source_id)
        safe_collection_id = quote(collection_id, safe="")
        return self._get_json(
            source,
            f"{source.api_root}/collections/{safe_collection_id}/objects/",
            params=self._build_filter_params(object_type=object_type, object_id=object_id, added_after=added_after),
        )

    def object(self, source_id: str, collection_id: str, object_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        safe_collection_id = quote(collection_id, safe="")
        safe_object_id = quote(object_id, safe="")
        return self._get_json(source, f"{source.api_root}/collections/{safe_collection_id}/objects/{safe_object_id}/")

    def versions(self, source_id: str, collection_id: str, object_id: str) -> dict[str, Any]:
        source = self.get_source(source_id)
        safe_collection_id = quote(collection_id, safe="")
        safe_object_id = quote(object_id, safe="")
        return self._get_json(
            source,
            f"{source.api_root}/collections/{safe_collection_id}/objects/{safe_object_id}/versions/",
        )

    def _build_filter_params(
        self,
        *,
        object_type: str | None,
        object_id: str | None,
        added_after: str | None,
    ) -> dict[str, str]:
        params: dict[str, str] = {}
        if object_type:
            params["match[type]"] = object_type
        if object_id:
            params["match[id]"] = object_id
        if added_after:
            params["added_after"] = added_after
        return params

    def _get_json(self, source: TaxiiSource, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        normalized_path = "/" + path.lstrip("/")
        url = f"{source.base_url}{normalized_path}"
        cache_key = f"{url}?{httpx.QueryParams(params or {})}"
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached and cached[0] > now:
            return cached[1]

        try:
            with httpx.Client(
                headers={"Accept": TAXII_ACCEPT_HEADER},
                follow_redirects=False,
                timeout=settings.taxii_request_timeout_seconds,
            ) as client:
                response = client.get(url, params=params)
                response.raise_for_status()
                payload = response.json()
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            raise TaxiiUpstreamError(f"TAXII upstream returned HTTP {status_code}.") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise TaxiiUpstreamError("TAXII upstream request failed.") from exc

        if not isinstance(payload, dict):
            raise TaxiiUpstreamError("TAXII upstream returned an unexpected payload.")

        self._cache[cache_key] = (now + settings.taxii_cache_ttl_seconds, payload)
        return payload


taxii_service = TaxiiService()

