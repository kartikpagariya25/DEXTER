from __future__ import annotations

from pathlib import Path

from .storage import data_dir


def _authorized_file() -> Path:
    return data_dir() / "authorized_targets.txt"


def list_authorized() -> list[str]:
    path = _authorized_file()
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]


def is_authorized(target: str) -> bool:
    return target.rstrip("/") in {t.rstrip("/") for t in list_authorized()}


def authorize(target: str) -> None:
    path = _authorized_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not is_authorized(target):
        with path.open("a", encoding="utf-8") as handle:
            handle.write(target.rstrip("/") + "\n")


def revoke(target: str) -> None:
    remaining = [t for t in list_authorized() if t != target.rstrip("/")]
    content = "\n".join(remaining) + ("\n" if remaining else "")
    _authorized_file().write_text(content, encoding="utf-8")
