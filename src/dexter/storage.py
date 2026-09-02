from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .models import Run


def data_dir() -> Path:
    configured = os.environ.get("DEXTER_HOME")
    return Path(configured).expanduser() if configured else Path.home() / ".dexter"


def runs_dir() -> Path:
    path = data_dir() / "runs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_run_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "-", value).strip(".-") or "run"


def save_run(run: Run) -> Path:
    path = runs_dir() / safe_run_id(run.run_id)
    path.mkdir(parents=True, exist_ok=True)
    destination = path / "run.json"
    destination.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
    return destination


def load_run(run_id: str | None = None) -> dict[str, Any]:
    candidates = sorted(runs_dir().glob("*/run.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if run_id:
        candidate = runs_dir() / safe_run_id(run_id) / "run.json"
        if not candidate.exists():
            raise FileNotFoundError(f"Run not found: {run_id}")
    elif candidates:
        candidate = candidates[0]
    else:
        raise FileNotFoundError("No Dexter runs found")
    return json.loads(candidate.read_text(encoding="utf-8"))


def list_runs() -> list[dict[str, Any]]:
    return [json.loads(path.read_text(encoding="utf-8")) for path in sorted(runs_dir().glob("*/run.json"), reverse=True)]
