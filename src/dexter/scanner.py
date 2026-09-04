from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlparse

from .models import Finding

TEXT_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php", ".cs", ".yaml", ".yml", ".json", ".env", ".conf"}
# A file literally named ".env" (or ".env.local", ".env.production", etc.) has
# an EMPTY path.suffix in pathlib — the leading dot is read as "hidden file",
# not an extension — so it's invisible to the check above. Without this,
# the single most common place for real secrets is silently never scanned.
DOTFILE_PREFIXES = (".env",)
DOTFILE_NAMES = {".npmrc", ".dockercfg"}


def _is_scannable(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    name = path.name.lower()
    return name in DOTFILE_NAMES or name.startswith(DOTFILE_PREFIXES)


def _finding(rule: tuple[re.Pattern[str], str, str, str, str, str, float, float], path: Path, line_number: int, line: str) -> Finding:
    pattern, title, severity, description, remediation, cwe, cvss, confidence = rule
    return Finding(title, severity, "OWASP", description, line.strip()[:500], remediation, str(path), line_number, cwe, cvss, confidence=confidence)


# Trailing float on each rule is base confidence: how reliable this regex is
# at matching a real issue vs. a placeholder/false positive. The verify stage
# in loop.py adjusts this per-finding; this is just the starting point.
RULES = [
    (re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*[:=]\s*(['\"][^'\"]{3,}['\"]|[^\s'\"#]{6,})"), "Hard-coded secret", "high", "A credential-like value is embedded in source or config.", "Move the value to a secret manager or environment variable and rotate it.", "CWE-798", 8.1, 0.5),
    (re.compile(r"(?i)\beval\s*\(|child_process\.(exec|execSync)\s*\(|os\.system\s*\("), "Dynamic command execution", "high", "Dynamic execution can become command injection when input is controllable.", "Remove dynamic execution or use an allowlisted argument array with strict validation.", "CWE-78", 9.0, 0.7),
    (re.compile(r"(?i)\b(debug\s*=\s*true|app\.run\([^)]*debug\s*=\s*True)"), "Debug mode enabled", "medium", "Debug configuration may expose stack traces or interactive tooling.", "Disable debug mode outside local development.", "CWE-489", 5.3, 0.9),
    (re.compile(r"(?i)\b(verify=False|rejectUnauthorized\s*:\s*false|ssl[_-]?verify\s*=\s*false)"), "TLS verification disabled", "high", "Disabled certificate verification permits man-in-the-middle attacks.", "Keep certificate verification enabled and install the correct trust chain.", "CWE-295", 7.4, 0.85),
    (re.compile(r"(?i)select\s+.+\s+from\s+.+\+\s*\w+|execute\s*\([^)]*\+"), "Potential SQL injection", "high", "SQL assembled from concatenated input can alter query semantics.", "Use parameterized queries and allowlist dynamic identifiers.", "CWE-89", 9.0, 0.4),
    (re.compile(r"(?i)jwt\.sign\s*\([^,]+,\s*['\"][^'\"]+['\"]"), "Hardcoded JWT signing secret", "high", "The JWT signing secret is a literal string in source instead of a managed secret.", "Load the signing secret from environment variables or a secret manager, and use a high-entropy value.", "CWE-321", 8.3, 0.75),
    (re.compile(r"(?i)(cors\([^)]*origin\s*:\s*['\"]\*['\"]|access-control-allow-origin['\"]?\s*[:=]\s*['\"]\*['\"]|cors\([^)]*origin\s*:\s*true)"), "CORS wildcard / reflected origin", "medium", "Allowing any origin (or reflecting all origins) lets any website make authenticated cross-origin requests.", "Restrict CORS to an explicit allowlist of trusted origins.", "CWE-942", 6.5, 0.7),
    (re.compile(r"dangerouslySetInnerHTML"), "Potential XSS via unescaped HTML rendering", "high", "Rendering unsanitized content directly into the DOM can execute attacker-controlled scripts.", "Sanitize the content (e.g. DOMPurify) before rendering, or avoid raw HTML injection entirely.", "CWE-79", 7.6, 0.55),
]


def scan_source(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    ignored = {".git", "node_modules", "venv", ".venv", "__pycache__"}
    for path in root.rglob("*"):
        # Check the ignore list and extension BEFORE touching the filesystem
        #  (is_file() below calls stat(), which raises OSError on a broken
        # symlink/junction — e.g. a Linux venv's "lib64 -> lib" symlink is
        # unreadable on Windows with WinError 1920). Filtering by path parts
        # first means a broken link inside an ignored dir like venv/ never
        # reaches stat() at all.
        if any(part in ignored for part in path.parts) or not _is_scannable(path):
            continue
        try:
            if not path.is_file():
                continue
        except OSError:
            continue  # unreadable path (broken symlink/junction) — skip it
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            for rule in RULES:
                if rule[0].search(line):
                    findings.append(_finding(rule, path, number, line))
    return findings


def scan_contract(path: Path) -> list[Finding]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    findings: list[Finding] = []
    for endpoint, methods in raw.get("paths", {}).items():
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                continue
            if not operation.get("security", raw.get("security")):
                findings.append(Finding("Undocumented public API operation", "medium", "API security", f"{method.upper()} {endpoint} has no declared security requirement.", "OpenAPI operation lacks a security field.", "Declare the required auth scheme and enforce it server-side.", str(path), None, "CWE-306", 5.3, confidence=0.85))
    return findings


def scan_target(target: str) -> list[Finding]:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"}:
        if parsed.scheme == "http":
            return [Finding("Cleartext HTTP target", "medium", "Transport security", "The target uses HTTP and may transmit data without encryption.", target, "Use HTTPS and redirect HTTP to HTTPS.", target, None, "CWE-319", 5.9, confidence=0.95)]
        return []
    path = Path(target).expanduser().resolve()
    if path.is_file() and path.suffix.lower() == ".json":
        return scan_contract(path)
    return scan_source(path) if path.is_dir() else []