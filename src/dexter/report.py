from __future__ import annotations

import json
from typing import Any

from .provider_pool import call_llm

HUMAN_SYSTEM_PROMPT = (
    "You are explaining a security scan to someone who is not a security expert — "
    "a manager, a professor, a teammate. Use short sentences and everyday words. "
    "No jargon without a one-line explanation. No CVSS scores, no CWE codes. "
    "Structure: 1) one paragraph, what this means overall and how worried to be, "
    "2) the most important issues in plain language and why they matter, "
    "3) what to do about it, in order. Do not invent findings that weren't given to you."
)


def _fallback_human_report(run: dict[str, Any]) -> str:
    findings = run.get("findings", [])
    if not findings:
        return "Good news — the scan didn't find any issues in this codebase."
    counts = {level: sum(f["severity"] == level for f in findings) for level in ("critical", "high", "medium", "low")}
    lines = [f"This scan of {', '.join(run.get('targets', []))} found {len(findings)} issue(s)."]
    if counts["critical"] or counts["high"]:
        lines.append(f"{counts['critical'] + counts['high']} of these are serious and should be fixed soon.")
    lines.append("")
    lines.append("What was found, in plain terms:")
    ranked = sorted(findings, key=lambda f: (f.get("cvss") or 0, f.get("confidence", 0.5)), reverse=True)
    for finding in ranked[:10]:
        lines.append(f"- {finding['title']}: {finding.get('description', '')}")
    lines.append("")
    lines.append("(No LLM configured, so this is a simplified auto-generated summary rather than a full narrative. Set DEXTER_LLM_KEYS for a richer explanation.)")
    return "\n".join(lines)


def generate_human_report(run: dict[str, Any]) -> str:
    findings = run.get("findings", [])
    if not findings:
        return "Good news — the scan didn't find any issues in this codebase."
    payload = [
        {
            "title": f["title"],
            "severity": f["severity"],
            "verification": f.get("verification", "unverified"),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
            "location": f"{f.get('file')}:{f.get('line')}" if f.get("file") else "n/a",
        }
        for f in findings
    ]
    messages = [
        {"role": "system", "content": HUMAN_SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps({"findings": payload})},
    ]
    result = call_llm(messages)
    if result.provider == "none" or not result.text:
        return _fallback_human_report(run)
    suffix = "\n\n(generated via local fallback model)" if result.provider == "local" else ""
    return result.text + suffix
