from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from .provider_pool import call_llm
from . import verify_cache

MAX_TOOL_ITERATIONS = 4

VERIFY_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_lines",
            "description": "Read a range of lines from a file in the scanned codebase, to see the surrounding context of a finding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "start": {"type": "integer"},
                    "end": {"type": "integer"},
                },
                "required": ["file", "start", "end"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "shannon_entropy",
            "description": "Compute the Shannon entropy of a string. Roughly: >3.5 suggests a real random secret; lower suggests a placeholder, common word, or short value.",
            "parameters": {
                "type": "object",
                "properties": {"value": {"type": "string"}},
                "required": ["value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "grep_codebase",
            "description": "Search the scanned target directory for other occurrences of a string, to see how a value or variable is used elsewhere (e.g. is a 'hardcoded' value actually read from an environment variable nearby).",
            "parameters": {
                "type": "object",
                "properties": {"pattern": {"type": "string"}},
                "required": ["pattern"],
            },
        },
    },
]

SYSTEM_PROMPT = (
    "You are a security analyst verifying ONE static-analysis finding. You may call tools "
    "to inspect the surrounding code before deciding — use them when they would change your "
    "answer, not by default. When you are done investigating, respond with a JSON object "
    '(it is fine if you add a sentence before or after it, it will be extracted): '
    '{"verdict": "verified" | "false-positive-suspected" | "needs-manual-review", '
    '"confidence": <0.0 to 1.0>, "reasoning": "<2-3 sentences: what you checked, what you found, and why '
    'it changed or confirmed your assessment. Plain language, no jargon.>"}. '
    "Be decisive once you have enough context — do not call more than a couple of tools."
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _read_lines(root: str, file: str, start: int, end: int) -> str:
    try:
        path = Path(file)
        if not path.is_absolute():
            path = Path(root) / file
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start = max(1, start)
        end = min(len(lines), max(start, end))
        return "\n".join(lines[start - 1:end]) or "(empty range)"
    except OSError as exc:
        return f"error reading file: {exc}"


def _grep_codebase(root: str, pattern: str) -> str:
    if not pattern:
        return "empty pattern"
    matches: list[str] = []
    try:
        compiled = re.compile(re.escape(pattern))
    except re.error:
        return "invalid pattern"
    base = Path(root)
    if not base.exists():
        return "search root does not exist"
    for path in base.rglob("*"):
        if not path.is_file() or path.stat().st_size > 500_000:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), start=1):
            if compiled.search(line):
                matches.append(f"{path.name}:{i}: {line.strip()[:200]}")
                if len(matches) >= 10:
                    return "\n".join(matches)
    return "\n".join(matches) if matches else "no matches found"


def _execute_tool(root: str, name: str, args: dict[str, Any]) -> str:
    if name == "read_lines":
        return _read_lines(root, str(args.get("file", "")), int(args.get("start", 1)), int(args.get("end", 1)))
    if name == "shannon_entropy":
        return str(round(_entropy(str(args.get("value", ""))), 2))
    if name == "grep_codebase":
        return _grep_codebase(root, str(args.get("pattern", "")))
    return f"unknown tool: {name}"


def _parse_verdict(text: str) -> dict[str, Any] | None:
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:]
    cleaned = cleaned.strip()
    # Real models frequently wrap the JSON in a sentence even when told not
    # to ("Here's my analysis: {...}") — extract the first {...} block
    # instead of requiring the whole response to be clean JSON.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        cleaned = cleaned[start:end + 1]
    try:
        parsed = json.loads(cleaned)
        return {
            "verdict": parsed.get("verdict", "needs-manual-review"),
            "confidence": float(parsed.get("confidence", 0.5)),
            "reasoning": str(parsed.get("reasoning", ""))[:600],
        }
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def agentic_verify(finding_dict: dict[str, Any], root: str, on_step: Callable[[str], None] | None = None) -> dict[str, Any] | None:
    """Runs a real tool-calling verification loop for one finding.
    Returns {"verdict", "confidence", "reasoning"} or None if unavailable
    (no LLM reachable, or the loop didn't converge — caller should fall
    back to the deterministic heuristic in that case, never treat None as
    a verdict of its own).
    """
    cached = verify_cache.get(finding_dict)
    if cached is not None:
        if on_step:
            on_step("cache hit — reusing prior verification, no LLM call")
        return cached

    messages: list[dict] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({
            "title": finding_dict.get("title"),
            "file": finding_dict.get("file"),
            "line": finding_dict.get("line"),
            "evidence": finding_dict.get("evidence"),
            "description": finding_dict.get("description"),
        })},
    ]

    last_text = ""
    for _ in range(MAX_TOOL_ITERATIONS):
        result = call_llm(messages, tools=VERIFY_TOOLS)
        if result.provider == "none":
            if on_step:
                on_step(f"LLM unavailable — {result.error or 'unknown reason'}")
            return None
        message = result.message or {"content": result.text, "tool_calls": None}
        tool_calls = message.get("tool_calls")
        last_text = message.get("content") or ""

        if not tool_calls:
            verdict = _parse_verdict(last_text)
            if verdict is not None:
                verify_cache.put(finding_dict, verdict)
            elif on_step:
                on_step(f"LLM responded but verdict didn't parse — raw: {last_text[:150]!r}")
            return verdict

        messages.append(message)
        for call in tool_calls:
            fn = call.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {}
            if on_step:
                on_step(f"{fn.get('name', '?')}({', '.join(f'{k}={v}' for k, v in args.items())})")
            output = _execute_tool(root, fn.get("name", ""), args)
            messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": output[:2000]})

    verdict = _parse_verdict(last_text)  # circuit breaker hit — use whatever the model last said, if parseable
    if verdict is not None:
        verify_cache.put(finding_dict, verdict)
    return verdict
