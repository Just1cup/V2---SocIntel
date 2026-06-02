import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


os.environ.setdefault("JWT_SECRET", "test-secret-value-with-more-than-32-characters")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.taxii_service import TaxiiService  # noqa: E402


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload
        self.content = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

    def raise_for_status(self):
        return None

    def iter_bytes(self):
        midpoint = max(1, len(self.content) // 2)
        yield self.content[:midpoint]
        yield self.content[midpoint:]


class FakeStream:
    def __init__(self, payload):
        self.response = FakeResponse(payload)

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc, traceback):
        return None


class FakeClient:
    calls = 0
    payloads = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None

    def stream(self, method, url, params=None):
        type(self).calls += 1
        return FakeStream(type(self).payloads.pop(0))


class TaxiiServiceCacheTests(unittest.TestCase):
    def setUp(self):
        FakeClient.calls = 0
        FakeClient.payloads = []
        self.service = TaxiiService()
        self.source = self.service.get_source("mitre-attack")

    def test_reuses_cached_payload_when_entry_is_within_size_limit(self):
        self.service._cache_max_entry_bytes = 1024
        FakeClient.payloads = [{"ok": True}]

        with patch("app.services.taxii_service.httpx.Client", FakeClient):
            first = self.service._get_json(self.source, "/taxii2/")
            second = self.service._get_json(self.source, "/taxii2/")

        self.assertEqual(first, {"ok": True})
        self.assertEqual(second, {"ok": True})
        self.assertEqual(FakeClient.calls, 1)
        self.assertEqual(len(self.service._cache), 1)

    def test_does_not_cache_payload_larger_than_entry_budget(self):
        self.service._cache_max_entry_bytes = 10
        FakeClient.payloads = [{"data": "first large payload"}, {"data": "second large payload"}]

        with patch("app.services.taxii_service.httpx.Client", FakeClient):
            first = self.service._get_json(self.source, "/taxii2/")
            second = self.service._get_json(self.source, "/taxii2/")

        self.assertEqual(first, {"data": "first large payload"})
        self.assertEqual(second, {"data": "second large payload"})
        self.assertEqual(FakeClient.calls, 2)
        self.assertEqual(len(self.service._cache), 0)
        self.assertEqual(self.service._cache_bytes, 0)

    def test_evicts_old_entries_when_total_cache_budget_is_exceeded(self):
        self.service._cache_max_entry_bytes = 1024
        self.service._cache_max_bytes = 45
        FakeClient.payloads = [{"item": "a" * 20}, {"item": "b" * 20}]

        with patch("app.services.taxii_service.httpx.Client", FakeClient):
            self.service._get_json(self.source, "/one/")
            self.service._get_json(self.source, "/two/")

        self.assertEqual(FakeClient.calls, 2)
        self.assertEqual(len(self.service._cache), 1)
        cached_payloads = [entry[2] for entry in self.service._cache.values()]
        self.assertEqual(cached_payloads, [{"item": "b" * 20}])

    def test_rejects_upstream_response_larger_than_response_budget(self):
        self.service._response_max_bytes = 10
        FakeClient.payloads = [b'{"data":"this payload is too large"}']

        with patch("app.services.taxii_service.httpx.Client", FakeClient):
            with self.assertRaisesRegex(Exception, "too large"):
                self.service._get_json(self.source, "/taxii2/")

        self.assertEqual(FakeClient.calls, 1)
        self.assertEqual(len(self.service._cache), 0)


if __name__ == "__main__":
    unittest.main()
