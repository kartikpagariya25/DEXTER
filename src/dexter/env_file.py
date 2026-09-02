from __future__ import annotations

import os
from pathlib import Path

from .storage import data_dir


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def load_env() -> None:
    # ~/.dexter/.env first, then a project-local .env — either can be missing.
    # Existing environment variables always win, so `set X=...` for one
    # session still overrides whatever is saved on disk.
    for path in (data_dir() / ".env", Path.cwd() / ".env"):
        for key, value in _parse_env_file(path).items():
            os.environ.setdefault(key, value)
