from __future__ import annotations

from pathlib import Path
from typing import Callable

from .agentic_verify import agentic_verify
from .llm import enrich
from .models import Finding, Run
from .sandbox import Sandbox, sandbox_enabled, set_active
from .scanner import scan_target
from .tools import run_adapters

MAX_REFINE_ITERATIONS = 2

PLACEHOLDER_MARKERS = ("changeme", "example", "xxx", "todo", "dummy", "your_api_key", "<", "insert_")

SECRET_LIKE_TITLES = {"Hard-coded secret", "Hardcoded JWT signing secret"}

DETERMINISTIC_TITLES = {
    "Debug mode enabled",
    "TLS verification disabled",
    "Cleartext HTTP target",
    "Undocumented public API operation",
}

StageCallback = Callable[[str], None]


def _looks_like_placeholder(evidence: str) -> bool:
    lowered = evidence.lower()
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def _fallback_verify_heuristic(finding: Finding) -> None:
    # Used only when no LLM is reachable — same logic as before agentic
    # verification existed, kept so Dexter still works fully offline.
    if finding.title in SECRET_LIKE_TITLES:
        if _looks_like_placeholder(finding.evidence):
            finding.verification = "false-positive-suspected"
            finding.confidence = max(finding.confidence - 0.3, 0.05)
        else:
            finding.verification = "verified"
            finding.confidence = min(finding.confidence + 0.2, 0.95)
    else:
        finding.verification = "needs-manual-review"


def _verify(finding: Finding, on_step: StageCallback | None = None) -> None:
    if finding.source == "dexter-guard":
        return  # already fully set — an authorization-skip marker, not a real finding
    if finding.source != "local-rule":
        # External tools report their own confidence; trust it rather than
        # re-guessing. High confidence from a real scanner is as close to
        # "verified" as static analysis gets.
        if finding.confidence >= 0.8:
            finding.verification = "verified"
        elif finding.confidence >= 0.5:
            finding.verification = "needs-manual-review"
        else:
            finding.verification = "false-positive-suspected"
        finding.validated = finding.verification == "verified"
        return
    if finding.title in DETERMINISTIC_TITLES:
        finding.verification = "verified"
        finding.validated = True
        return

    root = str(Path(finding.file).parent) if finding.file else "."
    result = agentic_verify(finding.to_dict(), root, on_step=on_step)
    if result:
        finding.verification = result["verdict"]
        finding.confidence = result["confidence"]
        if result.get("reasoning"):
            finding.description = f"{finding.description}\n\nAI verification: {result['reasoning']}"
    else:
        _fallback_verify_heuristic(finding)
    finding.validated = finding.verification == "verified"


def _refine_once(finding: Finding, keywords: list[str]) -> bool:
    if finding.verification != "needs-manual-review" or not keywords:
        return False
    haystack = f"{finding.title} {finding.category} {finding.description}".lower()
    if any(keyword in haystack for keyword in keywords):
        finding.confidence = min(finding.confidence + 0.15, 0.9)
        return True
    return False


def run_savr(
    targets: list[str],
    instructions: str,
    scan_mode: str,
    run_id: str,
    on_stage: StageCallback | None = None,
) -> Run:
    def stage(name: str) -> None:
        if on_stage:
            on_stage(name)

    run = Run.create(run_id, targets, scan_mode, instructions)

    stage("scan")
    findings: list[Finding] = []
    for target in targets:
        findings.extend(scan_target(target))
        box: Sandbox | None = None
        if sandbox_enabled():
            local_dir = target if Path(target).is_dir() else None
            try:
                box = Sandbox(local_dir)
                box.start()
                set_active(box)
                stage(f"scan:sandbox-started ({box.container_name})")
            except RuntimeError as exc:
                stage(f"scan:sandbox-unavailable ({exc}) — falling back to host execution")
                box = None
        try:
            findings.extend(run_adapters(target, on_tool=lambda name: stage(f"scan:{name}")))
        finally:
            if box is not None:
                set_active(None)
                box.stop()
    run.findings = findings

    stage("analyze")
    # Base confidence per finding is already assigned by its source rule at
    # scan time. This stage exists as a real, separate step so later tool
    # adapters (Semgrep, Nuclei, etc.) have a place to cross-reference and
    # deduplicate overlapping findings before verification runs.

    stage("verify")
    for finding in run.findings:
        _verify(finding, on_step=lambda step, f=finding: stage(f"verify:{f.title[:24]} → {step}"))

    stage("refine")
    keywords = [w.strip(".,").lower() for w in instructions.split() if len(w) > 3]
    already_refined: set[int] = set()
    for _ in range(MAX_REFINE_ITERATIONS):
        changed = False
        for finding in run.findings:
            if id(finding) in already_refined:
                continue
            if _refine_once(finding, keywords):
                already_refined.add(id(finding))
                changed = True
        if not changed:
            break

    stage("report")
    run.summary = enrich([finding.to_dict() for finding in run.findings], instructions)
    run.status = "completed"
    return run


def insight_summary(run: Run) -> str:
    total = len(run.findings)
    if not total:
        return "No findings — clean scan."
    by_severity = {level: sum(f.severity == level for f in run.findings) for level in ("critical", "high", "medium", "low")}
    verified = sum(f.verification == "verified" for f in run.findings)
    review = sum(f.verification == "needs-manual-review" for f in run.findings)
    dropped = sum(f.verification == "false-positive-suspected" for f in run.findings)
    top = max(run.findings, key=lambda f: (f.cvss or 0.0, f.confidence))
    lines = [
        f"{total} finding(s) — critical:{by_severity['critical']} high:{by_severity['high']} medium:{by_severity['medium']} low:{by_severity['low']}",
        f"{verified} verified, {review} need manual review, {dropped} likely false positive",
        f"Top risk: [{top.severity.upper()}] {top.title} (confidence {top.confidence:.2f})",
    ]
    return "\n".join(lines)
