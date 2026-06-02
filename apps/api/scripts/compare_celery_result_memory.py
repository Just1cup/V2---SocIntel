from __future__ import annotations

import json
import time
import tracemalloc


TASK_COUNT = 10_000
RESULT_PAYLOAD = {"job_id": "job_example", "status": "completed", "result_id": "result_example"}


def measure(label: str, operation):
    tracemalloc.start()
    start = time.perf_counter()
    result = operation()
    duration_ms = (time.perf_counter() - start) * 1000
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "label": label,
        "duration_ms": round(duration_ms, 2),
        "tracemalloc_current_mb": round(current / 1024 / 1024, 2),
        "tracemalloc_peak_mb": round(peak / 1024 / 1024, 2),
        **result,
    }


def before_store_task_results():
    redis_like_backend = {}
    for index in range(TASK_COUNT):
        redis_like_backend[f"celery-task-meta-{index}"] = json.dumps(
            {"status": "SUCCESS", "result": RESULT_PAYLOAD},
            separators=(",", ":"),
        )
    retained_bytes = sum(len(value.encode("utf-8")) for value in redis_like_backend.values())
    return {
        "stored_results": len(redis_like_backend),
        "retained_backend_mb": round(retained_bytes / 1024 / 1024, 2),
    }


def after_ignore_task_results():
    redis_like_backend = {}
    for _ in range(TASK_COUNT):
        pass
    retained_bytes = sum(len(value.encode("utf-8")) for value in redis_like_backend.values())
    return {
        "stored_results": len(redis_like_backend),
        "retained_backend_mb": round(retained_bytes / 1024 / 1024, 2),
    }


if __name__ == "__main__":
    before = measure("before_celery_result_backend_storage", before_store_task_results)
    after = measure("after_task_ignore_result", after_ignore_task_results)
    print({"task_count": TASK_COUNT, "before": before, "after": after})
