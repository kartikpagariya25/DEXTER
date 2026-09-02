from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .storage import data_dir

DEFAULT_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.3-70b-versatile"
DEFAULT_COOLDOWN_SECONDS = 5 * 3600
DEFAULT_LOCAL_URL = "http://localhost:11434/v1"
DEFAULT_LOCAL_MODEL = "llama3.1"


@dataclass
class PoolResult:
    text: str
    provider: str  # "pool", "local", or "none"
    message: dict | None = None  # full assistant message, only populated when tools were used


def _state_path() -> Path:
    return data_dir() / "key_state.json"


def _key_id(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def _load_state() -> dict[str, float]:
    path = _state_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(state: dict[str, float]) -> None:
    path = _state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state), encoding="utf-8")


def _load_keys() -> list[str]:
    raw = os.environ.get("DEXTER_LLM_KEYS", "")
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if keys:
        return keys
    single = os.environ.get("GROQ_API_KEY") or os.environ.get("LLM_API_KEY")
    return [single] if single else []


def _resolve_base_url() -> str:
    return os.environ.get("DEXTER_LLM_BASE_URL", DEFAULT_BASE_URL)


def _resolve_model() -> str:
    return os.environ.get("DEXTER_LLM_MODEL") or os.environ.get("DEXTER_GROQ_MODEL", DEFAULT_MODEL)


def _chat_completion(base_url: str, api_key: str | None, model: str, messages: list[dict], tools: list[dict] | None = None) -> dict:
    body: dict = {"model": model, "temperature": 0.1, "messages": messages}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(f"{base_url}/chat/completions", data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload["choices"][0]["message"]


def call_llm(messages: list[dict], tools: list[dict] | None = None) -> PoolResult:
    base_url = _resolve_base_url()
    model = _resolve_model()
    cooldown = int(os.environ.get("DEXTER_LLM_COOLDOWN_SECONDS", DEFAULT_COOLDOWN_SECONDS))
    keys = _load_keys()
    state = _load_state()
    now = time.time()

    for key in keys:
        kid = _key_id(key)
        if state.get(kid, 0) > now:
            continue
        try:
            message = _chat_completion(base_url, key, model, messages, tools)
            return PoolResult(message.get("content") or "", "pool", message)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                state[kid] = now + cooldown
                _save_state(state)
            continue
        except Exception:
            continue

    local_url = os.environ.get("DEXTER_LLM_LOCAL_URL", DEFAULT_LOCAL_URL)
    local_model = os.environ.get("DEXTER_LLM_LOCAL_MODEL", DEFAULT_LOCAL_MODEL)
    try:
        message = _chat_completion(local_url, None, local_model, messages, tools)
        return PoolResult(message.get("content") or "", "local", message)
    except Exception:
        return PoolResult("", "none")


def _reachable(base_url: str) -> bool:
    try:
        urllib.request.urlopen(f"{base_url}/models", timeout=1.5)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def pool_status() -> str:
    base_url = _resolve_base_url()
    keys = _load_keys()
    state = _load_state()
    now = time.time()
    lines = [f"provider: {base_url}", f"model: {_resolve_model()}", f"keys configured: {len(keys)}"]
    if not keys:
        lines.append("  set DEXTER_LLM_KEYS (comma-separated) or GROQ_API_KEY")
    for key in keys:
        kid = _key_id(key)
        until = state.get(kid, 0)
        if until > now:
            remaining = int(until - now)
            lines.append(f"  key {kid}: cooling down ({remaining // 3600}h{(remaining % 3600) // 60}m left)")
        else:
            lines.append(f"  key {kid}: ready")
    local_url = os.environ.get("DEXTER_LLM_LOCAL_URL", DEFAULT_LOCAL_URL)
    lines.append(f"local fallback ({local_url}): {'reachable' if _reachable(local_url) else 'unreachable'}")
    return "\n".join(lines)
