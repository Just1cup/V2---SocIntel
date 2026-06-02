from __future__ import annotations

import json
import time
from collections import OrderedDict
from dataclasses import dataclass
from threading import Lock
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
        self._cache: OrderedDict[str, tuple[float, int, dict[str, Any]]] = OrderedDict()
        self._cache_lock = Lock()
        self._cache_bytes = 0
        self._cache_max_entries = settings.taxii_cache_max_entries
        self._cache_max_bytes = settings.taxii_cache_max_bytes
        self._cache_max_entry_bytes = settings.taxii_cache_max_entry_bytes
        self._response_max_bytes = settings.taxii_response_max_bytes
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
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached and cached[0] > now:
                self._cache.move_to_end(cache_key)
                return cached[2]
            if cached:
                self._remove_cache_entry(cache_key)

        try:
            with httpx.Client(
                headers={"Accept": TAXII_ACCEPT_HEADER},
                follow_redirects=False,
                timeout=settings.taxii_request_timeout_seconds,
            ) as client:
                with client.stream("GET", url, params=params) as response:
                    response.raise_for_status()
                    payload_bytes = self._read_response_bytes(response)
                payload_size = len(payload_bytes)
                payload = json.loads(payload_bytes)
        except httpx.HTTPStatusError as exc:
            status_code = exc.response.status_code
            raise TaxiiUpstreamError(f"TAXII upstream returned HTTP {status_code}.") from exc
        except TaxiiUpstreamError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise TaxiiUpstreamError("TAXII upstream request failed.") from exc

        if not isinstance(payload, dict):
            raise TaxiiUpstreamError("TAXII upstream returned an unexpected payload.")

        if payload_size <= self._cache_max_entry_bytes:
            with self._cache_lock:
                self._store_cache_entry(cache_key, now + settings.taxii_cache_ttl_seconds, payload_size, payload)
        return payload

    def _read_response_bytes(self, response) -> bytes:
        payload = bytearray()
        for chunk in response.iter_bytes():
            payload.extend(chunk)
            if len(payload) > self._response_max_bytes:
                raise TaxiiUpstreamError("TAXII upstream response is too large.")
        return bytes(payload)

    def _remove_cache_entry(self, cache_key: str) -> None:
        cached = self._cache.pop(cache_key, None)
        if cached:
            self._cache_bytes = max(0, self._cache_bytes - cached[1])

    def _store_cache_entry(self, cache_key: str, expires_at: float, payload_size: int, payload: dict[str, Any]) -> None:
        self._remove_cache_entry(cache_key)
        self._cache[cache_key] = (expires_at, payload_size, payload)
        self._cache_bytes += payload_size
        self._cache.move_to_end(cache_key)
        while len(self._cache) > self._cache_max_entries or self._cache_bytes > self._cache_max_bytes:
            _, evicted = self._cache.popitem(last=False)
            self._cache_bytes = max(0, self._cache_bytes - evicted[1])


taxii_service = TaxiiService()
