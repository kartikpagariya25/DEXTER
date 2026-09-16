from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .storage import data_dir


def _cache_path() -> Path:
    return data_dir() / "verify_cache.json"


def fingerprint(finding_dict: dict[str, Any]) -> str:
    # Same title + file + evidence means the same underlying finding — if
    # nothing about it changed since a prior scan, there's no reason to
    # pay for another round of LLM reasoning to reach the same conclusion.
    key = f"{finding_dict.get('title')}|{finding_dict.get('file')}|{finding_dict.get('evidence')}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _load() -> dict[str, dict]:
    path = _cache_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def get(finding_dict: dict[str, Any]) -> dict[str, Any] | None:
    return _load().get(fingerprint(finding_dict))


def put(finding_dict: dict[str, Any], result: dict[str, Any]) -> None:
    cache = _load()
    cache[fingerprint(finding_dict)] = result
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(cache), encoding="utf-8")


def clear() -> int:
    path = _cache_path()
    if not path.exists():
        return 0
    count = len(_load())
    path.unlink()
    return count
