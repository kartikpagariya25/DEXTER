from __future__ import annotations

import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from .provider_pool import call_llm

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
    "answer, not by default. When you are done investigating, respond with ONLY a JSON object "
    'and nothing else: {"verdict": "verified" | "false-positive-suspected" | "needs-manual-review", '
    '"confidence": <0.0 to 1.0>, "reasoning": "<one sentence, plain language>"}. '
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
    try:
        parsed = json.loads(cleaned.strip())
        return {
            "verdict": parsed.get("verdict", "needs-manual-review"),
            "confidence": float(parsed.get("confidence", 0.5)),
            "reasoning": str(parsed.get("reasoning", ""))[:300],
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
            return None
        message = result.message or {"content": result.text, "tool_calls": None}
        tool_calls = message.get("tool_calls")
        last_text = message.get("content") or ""

        if not tool_calls:
            return _parse_verdict(last_text)

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

    return _parse_verdict(last_text)  # circuit breaker hit — use whatever the model last said, if parseable
