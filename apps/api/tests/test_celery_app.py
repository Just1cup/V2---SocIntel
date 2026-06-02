import os
import sys
import unittest
from pathlib import Path


os.environ.setdefault("JWT_SECRET", "test-secret-value-with-more-than-32-characters")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.workers.celery_app import celery_app  # noqa: E402


class CeleryAppMemoryConfigTests(unittest.TestCase):
    def test_analysis_tasks_do_not_store_redundant_redis_results(self):
        self.assertTrue(celery_app.conf.task_ignore_result)
        self.assertFalse(celery_app.conf.task_track_started)
        self.assertFalse(celery_app.conf.task_store_errors_even_if_ignored)
        self.assertLessEqual(celery_app.conf.result_expires, 3600)


if __name__ == "__main__":
    unittest.main()
