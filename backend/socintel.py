"""Backward-compatible script entrypoint."""
from __future__ import annotations

import sys
from pathlib import Path


if __name__ == "__main__":
    project_root = Path(__file__).resolve().parents[1]
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))

    from backend.cli import main

    main()
