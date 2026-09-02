from __future__ import annotations

import json
from typing import Any

from .provider_pool import call_llm

SYSTEM_PROMPT = (
    "You are a defensive application security reviewer. Summarize evidence, "
    "prioritize risk, and give safe remediation. Do not invent validation."
)


def enrich(findings: list[dict[str, Any]], instructions: str = "") -> str:
    if not findings:
        return "No findings to summarize."
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({"instructions": instructions, "findings": findings})},
    ]
    result = call_llm(messages)
    if result.provider == "none":
        return "Local rules completed. No LLM reachable — set DEXTER_LLM_KEYS (or GROQ_API_KEY), or run Ollama locally."
    if not result.text:
        return "LLM returned an empty summary."
    return result.text + (" (via local fallback)" if result.provider == "local" else "")
