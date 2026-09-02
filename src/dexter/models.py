from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    description: str
    evidence: str
    remediation: str
    file: str | None = None
    line: int | None = None
    cwe: str | None = None
    cvss: float | None = None
    validated: bool = False
    source: str = "local-rule"
    confidence: float = 0.5
    verification: str = "unverified"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Run:
    run_id: str
    started_at: str
    status: str
    targets: list[str]
    scan_mode: str
    findings: list[Finding] = field(default_factory=list)
    instructions: str = ""
    summary: str = ""

    @classmethod
    def create(cls, run_id: str, targets: list[str], scan_mode: str, instructions: str = "") -> "Run":
        return cls(run_id, datetime.now(timezone.utc).isoformat(), "running", targets, scan_mode, instructions=instructions)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        return data
