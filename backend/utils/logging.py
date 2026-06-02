"""File-based error logging helpers."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
import re
import traceback


def log_error(module: str, message: str, exc: Exception | None = None) -> None:
    try:
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        safe_module = re.sub(r"[^a-zA-Z0-9._-]+", "_", module or "unknown")
        log_dir = Path(__file__).resolve().parent.parent / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{ts}_{safe_module}.log"
        parts = [
            f"timestamp: {ts}",
            f"module: {module}",
            f"message: {message}",
        ]
        if exc is not None:
            parts.append("exception:")
            parts.append(traceback.format_exc().strip())
        log_file.write_text("\n".join(parts) + "\n", encoding="utf-8")
    except Exception:
        pass
