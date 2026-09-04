from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse
from xml.etree import ElementTree

from .authorization import is_authorized
from .models import Finding
from . import sandbox

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "ERROR": "high",
    "HIGH": "high",
    "WARNING": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "INFO": "low",
    "UNDEFINED": "low",
    "UNKNOWN": "low",
}

CONFIDENCE_LABELS = {"HIGH": 0.85, "MEDIUM": 0.6, "LOW": 0.4}


def _severity(value: str | None) -> str:
    return SEVERITY_MAP.get((value or "").upper(), "medium")


def _confidence(value: str | None, default: float = 0.6) -> float:
    return CONFIDENCE_LABELS.get((value or "").upper(), default)


def _which(binary: str) -> str | None:
    return shutil.which(binary)


def _run(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a tool command. If a sandbox is active for this run (DEXTER_SANDBOX=1
    and loop.py opened one for the current target), the command is executed
    inside that container instead of on the host — any argument that points
    inside the sandboxed target directory is rewritten to /workspace first.
    Otherwise this behaves exactly as before (host subprocess)."""
    box = sandbox.get_active()
    if box is not None:
        translated = [sandbox.to_workspace_path(box, arg) for arg in cmd]
        return box.exec(translated, timeout=timeout)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "binary not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timed out"


def _report_path(name: str) -> tuple[str, Path]:
    """Return (path_for_command, path_for_reading_back).

    Non-sandboxed: both are the same host tempfile path.
    Sandboxed: the command gets a container-side /output/<name> path; the
    read-back path is the host side of that same bind-mounted directory, so
    Dexter can read the file the tool just wrote inside the container.
    """
    box = sandbox.get_active()
    if box is not None:
        return f"/output/{name}", box.output_dir / name
    host_path = Path(tempfile.gettempdir()) / name
    return str(host_path), host_path


def _snippet(path: str | None, line: int | None) -> str:
    if not path or not line:
        return ""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[line - 1].strip()[:300] if 0 < line <= len(lines) else ""
    except OSError:
        return ""


EXCLUDED_DIRS = [".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build", "site-packages"]


def run_semgrep(target: str) -> list[Finding]:
    if not _which("semgrep"):
        return []
    exclude_args = []
    for d in EXCLUDED_DIRS:
        exclude_args += ["--exclude", d]
    _, out, _ = _run(["semgrep", "--config=auto", "--json", "--quiet", "--timeout", "120", *exclude_args, target], timeout=240)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        path = r.get("path", target)
        line = r.get("start", {}).get("line")
        cwe_list = metadata.get("cwe") or []
        findings.append(Finding(
            title=extra.get("message", r.get("check_id", "Semgrep finding")).split(".")[0][:120],
            severity=_severity(extra.get("severity")),
            category="Semgrep",
            description=extra.get("message", ""),
            evidence=_snippet(path, line) or r.get("check_id", ""),
            remediation="See the Semgrep rule reference (shortlink in metadata) for the recommended fix.",
            file=path,
            line=line,
            cwe=cwe_list[0].split(":")[0] if cwe_list else None,
            cvss=None,
            source="semgrep",
            confidence=_confidence(metadata.get("confidence"), 0.7),
        ))
    return findings


def run_bandit(target: str) -> list[Finding]:
    if not _which("bandit"):
        return []
    _, out, _ = _run(["bandit", "-r", target, "-f", "json", "-q", "-x", ",".join(EXCLUDED_DIRS)], timeout=180)
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    findings = []
    for r in data.get("results", []):
        code_lines = (r.get("code", "") or "").strip().splitlines()
        findings.append(Finding(
            title=r.get("issue_text", "Bandit finding")[:120],
            severity=_severity(r.get("issue_severity")),
            category="Bandit",
            description=r.get("issue_text", ""),
            evidence=code_lines[-1][:300] if code_lines else "",
            remediation=r.get("more_info", "See Bandit documentation for remediation guidance."),
            file=r.get("filename"),
            line=r.get("line_number"),
            cwe=f"CWE-{r['issue_cwe']['id']}" if r.get("issue_cwe") else None,
            cvss=None,
            source="bandit",
            confidence=_confidence(r.get("issue_confidence"), 0.6),
        ))
    return findings


def run_gitleaks(target: str) -> list[Finding]:
    binary = _which("gitleaks")
    if not binary:
        return []
    cmd_path, read_path = _report_path(f"dexter_gitleaks_{abs(hash(target))}.json")
    _run([binary, "detect", "--source", target, "--no-git", "--report-format", "json", "--report-path", cmd_path, "--exit-code", "0"], timeout=180)
    findings: list[Finding] = []
    if read_path.exists():
        try:
            data = json.loads(read_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = []
        for r in data:
            findings.append(Finding(
                title=f"Secret detected: {r.get('RuleID', 'unknown rule')}",
                severity="high",
                category="Gitleaks",
                description=r.get("Description", "A secret was detected by gitleaks."),
                evidence=(r.get("Match", "") or "")[:200],
                remediation="Rotate the exposed credential immediately and remove it from source (and git history if committed).",
                file=r.get("File"),
                line=r.get("StartLine"),
                cwe="CWE-798",
                cvss=8.1,
                source="gitleaks",
                confidence=0.85,
            ))
        read_path.unlink(missing_ok=True)
    return findings


def run_trivy(target: str) -> list[Finding]:
    binary = _which("trivy")
    if not binary or not Path(target).is_dir():
        return []
    cmd_path, read_path = _report_path(f"dexter_trivy_{abs(hash(target))}.json")
    _run([binary, "fs", "--format", "json", "--scanners", "vuln", "--output", cmd_path, target], timeout=300)
    findings: list[Finding] = []
    if read_path.exists():
        try:
            data = json.loads(read_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                pkg = vuln.get("PkgName", "dependency")
                version = vuln.get("InstalledVersion", "?")
                fixed = vuln.get("FixedVersion", "a patched version")
                findings.append(Finding(
                    title=f"{pkg} {version} has a known vulnerability ({vuln.get('VulnerabilityID')})",
                    severity=_severity(vuln.get("Severity")),
                    category="Trivy (dependency)",
                    description=(vuln.get("Title") or vuln.get("Description", ""))[:400],
                    evidence=f"{pkg}@{version} (fixed in {fixed})",
                    remediation=f"Upgrade {pkg} to {fixed}.",
                    file=result.get("Target"),
                    line=None,
                    cwe=None,
                    cvss=None,
                    source="trivy",
                    confidence=0.9,
                ))
        read_path.unlink(missing_ok=True)
    return findings


def run_nmap(target: str) -> list[Finding]:
    binary = _which("nmap")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "nmap")]
    host = urlparse(target).hostname or target
    cmd_path, read_path = _report_path(f"dexter_nmap_{abs(hash(target))}.xml")
    _run([binary, "-T4", "-sV", "--top-ports", "100", "-oX", cmd_path, host], timeout=240)
    findings: list[Finding] = []
    if read_path.exists():
        try:
            root = ElementTree.parse(read_path).getroot()
        except ElementTree.ParseError:
            root = None
        if root is not None:
            for host_el in root.findall("host"):
                addr_el = host_el.find("address")
                addr = addr_el.get("addr") if addr_el is not None else host
                ports_el = host_el.find("ports")
                if ports_el is None:
                    continue
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    service_el = port_el.find("service")
                    service = service_el.get("name") if service_el is not None else "unknown"
                    port_id = port_el.get("portid")
                    protocol = port_el.get("protocol")
                    findings.append(Finding(
                        title=f"Open port {port_id}/{protocol} ({service})",
                        severity="low",
                        category="Nmap (recon)",
                        description=f"Port {port_id}/{protocol} is open on {addr}, running {service}.",
                        evidence=f"{addr}:{port_id} ({service})",
                        remediation="Confirm this service is intended to be exposed to the network; close or firewall it if not.",
                        source="nmap",
                        confidence=0.95,
                    ))
        read_path.unlink(missing_ok=True)
    return findings


ZAP_RISK_MAP = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "low"}
ZAP_CONFIDENCE_MAP = {"Confirmed": 0.95, "High": 0.85, "Medium": 0.6, "Low": 0.4}


def _zap_base_url() -> str:
    return os.environ.get("DEXTER_ZAP_URL", "http://localhost:8080")


def _zap_get(path: str, params: dict[str, str] | None = None, timeout: int = 15) -> dict | None:
    query = dict(params or {})
    api_key = os.environ.get("DEXTER_ZAP_API_KEY", "")
    if api_key:
        query["apikey"] = api_key
    url = f"{_zap_base_url()}{path}"
    if query:
        url += f"?{urllib.parse.urlencode(query)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except Exception:
        return None


def zap_reachable() -> bool:
    return _zap_get("/JSON/core/view/version/") is not None


def run_zap(target: str) -> list[Finding]:
    # ZAP is a daemon Dexter connects to, not a binary it launches — start it
    # yourself first (zap.sh -daemon, or Docker). See README.
    if not is_authorized(target):
        return [_authorization_required(target, "zap")]
    if not zap_reachable():
        return []

    spider = _zap_get("/JSON/spider/action/scan/", {"url": target})
    if spider and "scan" in spider:
        scan_id = spider["scan"]
        for _ in range(60):  # up to ~2 minutes
            status = _zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
            if status and status.get("status") == "100":
                break
            time.sleep(2)

    if os.environ.get("DEXTER_ZAP_ACTIVE_SCAN") == "1":
        # Active scan sends real attack payloads and can take a long time —
        # opt-in only, same posture as sqlmap/Metasploit being excluded by
        # default. Bounded wait; grabs whatever alerts exist if it overruns.
        ascan = _zap_get("/JSON/ascan/action/scan/", {"url": target})
        if ascan and "scan" in ascan:
            ascan_id = ascan["scan"]
            for _ in range(200):  # up to ~10 minutes
                status = _zap_get("/JSON/ascan/view/status/", {"scanId": ascan_id})
                if status and status.get("status") == "100":
                    break
                time.sleep(3)
    else:
        for _ in range(30):
            remaining = _zap_get("/JSON/pscan/view/recordsToScan/")
            if remaining and remaining.get("recordsToScan") == "0":
                break
            time.sleep(2)

    alerts = _zap_get("/JSON/core/view/alerts/", {"baseurl": target})
    findings: list[Finding] = []
    for a in (alerts or {}).get("alerts", []):
        cweid = a.get("cweid")
        findings.append(Finding(
            title=a.get("alert") or a.get("name", "ZAP finding"),
            severity=ZAP_RISK_MAP.get(a.get("risk"), "medium"),
            category="OWASP ZAP",
            description=a.get("description", ""),
            evidence=a.get("evidence") or a.get("url", target),
            remediation=a.get("solution", "See ZAP's alert reference for remediation guidance.").split("\n")[0][:400],
            source="zap",
            confidence=ZAP_CONFIDENCE_MAP.get(a.get("confidence"), 0.6),
            cwe=f"CWE-{cweid}" if cweid and cweid not in ("-1", "0") else None,
        ))
    return findings


SENSITIVE_PATH_MARKERS = (".env", ".git", "backup", ".sql", "config", "credential", "secret", "private", "id_rsa", ".key", ".htpasswd", ".aws", ".ssh", ".npmrc", "dump")


def _default_wordlist() -> Path:
    return Path(__file__).parent / "wordlists" / "common.txt"


def run_ffuf(target: str) -> list[Finding]:
    binary = _which("ffuf")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "ffuf")]
    fuzz_url = target.rstrip("/") + "/FUZZ"
    cmd_path, read_path = _report_path(f"dexter_ffuf_{abs(hash(target))}.json")
    _run([binary, "-u", fuzz_url, "-w", str(_default_wordlist()), "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", cmd_path, "-s"], timeout=180)
    findings: list[Finding] = []
    if read_path.exists():
        try:
            data = json.loads(read_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for r in data.get("results", []):
            path = r.get("input", {}).get("FUZZ", "")
            sensitive = any(marker in path.lower() for marker in SENSITIVE_PATH_MARKERS)
            findings.append(Finding(
                title=f"Discovered path: /{path} (HTTP {r.get('status')})",
                severity="high" if sensitive else "low",
                category="ffuf (content discovery)",
                description=f"An unlinked path responded with HTTP {r.get('status')}.",
                evidence=r.get("url", target),
                remediation="Confirm this path should be publicly reachable; remove or restrict access if not.",
                source="ffuf",
                confidence=0.85 if sensitive else 0.6,
            ))
        read_path.unlink(missing_ok=True)
    return findings


SQLI_CWE = "CWE-89"


def run_sqlmap(target: str, param: str) -> list[Finding]:
    # Deliberately NOT registered in URL_ADAPTERS — a normal `scan` must never
    # trigger real exploitation attempts. Only reachable via an explicit,
    # separate invocation that names the exact parameter to test.
    binary = _which("sqlmap")
    if not binary:
        return []
    if not param:
        raise ValueError("sqlmap requires an explicit parameter name (e.g. --param id) — it does not blind-fuzz a whole target.")
    if not is_authorized(target):
        return [_authorization_required(target, "sqlmap")]

    output_dir = Path(tempfile.gettempdir()) / f"dexter_sqlmap_{abs(hash(target))}"
    _run([binary, "-u", target, "-p", param, "--batch", "--level=1", "--risk=1", f"--output-dir={output_dir}"], timeout=180)

    findings: list[Finding] = []
    log_files = list(output_dir.rglob("log"))
    if not log_files:
        return findings
    text = log_files[0].read_text(encoding="utf-8", errors="ignore")
    if "injection point(s)" not in text:
        return findings  # ran clean, no injectable parameter found

    dbms_match = re.search(r"back-end DBMS:\s*(.+)", text)
    dbms = dbms_match.group(1).strip() if dbms_match else "unknown"

    for block in re.split(r"\n\s*\n", text):
        type_match = re.search(r"Type:\s*(.+)", block)
        title_match = re.search(r"Title:\s*(.+)", block)
        payload_match = re.search(r"Payload:\s*(.+)", block)
        if not (type_match and title_match):
            continue
        findings.append(Finding(
            title=f"SQL injection confirmed ({type_match.group(1).strip()}) on '{param}'",
            severity="critical",
            category="sqlmap (confirmed exploit)",
            description=f"{title_match.group(1).strip()}. Back-end DBMS: {dbms}.",
            evidence=payload_match.group(1).strip() if payload_match else param,
            remediation="Use parameterized queries / prepared statements. Never build SQL via string concatenation of user input.",
            source="sqlmap",
            confidence=0.98,
            verification="verified",
        ))
    return findings


def _authorization_required(target: str, tool: str) -> Finding:
    return Finding(
        title=f"{tool} skipped — target not authorized",
        severity="low",
        category="Authorization",
        description=f"{target} is not on the authorized targets list, so {tool} (a live-target tool) was not run against it.",
        evidence=target,
        remediation=f"Run `dexter authorize {target}` once you have explicit permission to test this target.",
        source="dexter-guard",
        confidence=1.0,
        verification="verified",
    )


def run_nuclei(target: str) -> list[Finding]:
    binary = _which("nuclei")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "nuclei")]
    _, out, _ = _run([binary, "-u", target, "-jsonl", "-silent"], timeout=300)
    findings = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = r.get("info", {})
        findings.append(Finding(
            title=info.get("name", "Nuclei finding"),
            severity=_severity(info.get("severity")),
            category="Nuclei",
            description=info.get("description", ""),
            evidence=r.get("matched-at", target),
            remediation="Review the matched template's reference links for remediation guidance.",
            source="nuclei",
            confidence=0.7,
        ))
    return findings


def run_nikto(target: str) -> list[Finding]:
    binary = _which("nikto")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "nikto")]
    _, out, _ = _run([binary, "-h", target, "-Format", "json", "-output", "-"], timeout=300)
    findings = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    for v in data.get("vulnerabilities", []):
        findings.append(Finding(
            title=(v.get("msg", "Nikto finding") or "Nikto finding")[:120],
            severity="medium",
            category="Nikto",
            description=v.get("msg", ""),
            evidence=v.get("url", target),
            remediation="Review the server configuration flagged by Nikto.",
            source="nikto",
            confidence=0.5,
        ))
    return findings


# ---------------------------------------------------------------------------
# Secrets — trufflehog (complements gitleaks by also scanning git history,
# not just the current working tree)
# ---------------------------------------------------------------------------
def run_trufflehog(target: str) -> list[Finding]:
    binary = _which("trufflehog")
    if not binary:
        return []
    _, out, _ = _run([binary, "filesystem", target, "--json", "--no-update"], timeout=180)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        detector = r.get("DetectorName", "unknown")
        file_path = ((r.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem", {}).get("file")
        verified = bool(r.get("Verified"))
        findings.append(Finding(
            title=f"Secret detected: {detector}" + (" (verified live)" if verified else ""),
            severity="critical" if verified else "high",
            category="Trufflehog",
            description=f"Trufflehog matched a {detector} credential pattern" + (
                ", and confirmed it is currently active by testing it against the provider's API."
                if verified else ". Verification against the live provider was not possible/attempted."
            ),
            evidence=(r.get("Redacted") or "")[:200],
            remediation="Rotate the exposed credential immediately and remove it from source and git history.",
            file=file_path,
            line=r.get("line"),
            cwe="CWE-798",
            cvss=9.1 if verified else 8.1,
            source="trufflehog",
            confidence=0.98 if verified else 0.75,
            verification="verified" if verified else "unverified",
        ))
    return findings


# ---------------------------------------------------------------------------
# JS dependency vulnerabilities — retire.js (front-end specific; Trivy covers
# backend/lockfile dependencies but historically has weaker front-end-bundle
# coverage, so both are kept)
# ---------------------------------------------------------------------------
def run_retire(target: str) -> list[Finding]:
    binary = _which("retire")
    if not binary:
        return []
    cmd_path, read_path = _report_path(f"dexter_retire_{abs(hash(target))}.json")
    _run([binary, "--path", target, "--outputformat", "json", "--outputpath", cmd_path, "--exitwith", "0"], timeout=180)
    findings: list[Finding] = []
    if read_path.exists():
        try:
            data = json.loads(read_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = {}
        for entry in data.get("data", []):
            file_path = entry.get("file")
            for result in entry.get("results", []):
                component = result.get("component", "unknown component")
                version = result.get("version", "?")
                for vuln in result.get("vulnerabilities", []):
                    identifiers = vuln.get("identifiers", {})
                    cve_list = identifiers.get("CVE") or []
                    findings.append(Finding(
                        title=f"{component} {version} has a known vulnerability" + (f" ({cve_list[0]})" if cve_list else ""),
                        severity=_severity(vuln.get("severity")),
                        category="Retire.js (frontend dependency)",
                        description=identifiers.get("summary", f"{component} {version} matches a known-vulnerable signature."),
                        evidence=f"{component}@{version}" + (f" (fixed below {vuln['below']})" if vuln.get("below") else ""),
                        remediation=f"Upgrade {component} to a patched version" + (f" (>= {vuln['below']})." if vuln.get("below") else "."),
                        file=file_path,
                        cwe="CWE-1104" if not cve_list else None,
                        source="retire.js",
                        confidence=0.85,
                    ))
        read_path.unlink(missing_ok=True)
    return findings


# ---------------------------------------------------------------------------
# Recon enrichment — httpx (liveness + technology fingerprint) and katana
# (crawling). Both are informational/recon-stage tools: they rarely confirm
# a vulnerability by themselves, so findings here stay low-severity context
# unless a discovered path looks sensitive.
# ---------------------------------------------------------------------------
def run_httpx(target: str) -> list[Finding]:
    binary = _which("httpx")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "httpx")]
    _, out, _ = _run([binary, "-u", target, "-json", "-silent", "-title", "-tech-detect", "-server"], timeout=60)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        tech = ", ".join(r.get("tech", []) or [])
        server = r.get("webserver", "")
        if not (tech or server):
            continue
        findings.append(Finding(
            title="Technology fingerprint",
            severity="low",
            category="httpx (recon)",
            description="Identified server/technology stack; use this to prioritize which CVE feeds and Nuclei templates are relevant.",
            evidence=f"server={server or 'unknown'}; tech={tech or 'none detected'}",
            remediation="Not a vulnerability by itself — remove identifying banners if minimizing fingerprinting surface is a goal.",
            source="httpx",
            confidence=0.9,
            verification="verified",
        ))
    return findings


def run_katana(target: str) -> list[Finding]:
    binary = _which("katana")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "katana")]
    _, out, _ = _run([binary, "-u", target, "-jsonl", "-silent", "-depth", "2", "-timeout", "30"], timeout=120)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        endpoint = (r.get("request") or {}).get("endpoint", "")
        if not endpoint or not any(marker in endpoint.lower() for marker in SENSITIVE_PATH_MARKERS):
            continue  # only surface crawled paths that look sensitive; the rest is just a sitemap, not a finding
        findings.append(Finding(
            title=f"Crawler discovered a sensitive-looking path: {endpoint}",
            severity="medium",
            category="Katana (crawl)",
            description="This path was reachable via normal crawling and its name suggests it may expose sensitive data or functionality.",
            evidence=endpoint,
            remediation="Confirm this path is intended to be publicly reachable; restrict or remove it if not.",
            source="katana",
            confidence=0.5,
        ))
    return findings


# ---------------------------------------------------------------------------
# JS SAST — eslint, scoped to a small security-relevant ruleset rather than
# a full style/lint pass (which would bury real issues under formatting
# noise and requires the target's own, possibly-absent, eslint config).
# ---------------------------------------------------------------------------
_ESLINT_SECURITY_CONFIG = {
    "env": {"browser": True, "node": True, "es2021": True},
    "parserOptions": {"ecmaVersion": 2021, "sourceType": "module"},
    "rules": {
        "no-eval": "error",
        "no-implied-eval": "error",
        "no-new-func": "error",
        "no-script-url": "error",
    },
}


def run_eslint(target: str) -> list[Finding]:
    binary = _which("eslint")
    if not binary:
        return []
    config_path = Path(tempfile.gettempdir()) / f"dexter_eslintrc_{abs(hash(target))}.json"
    config_path.write_text(json.dumps(_ESLINT_SECURITY_CONFIG), encoding="utf-8")
    _, out, _ = _run([binary, "--no-eslintrc", "-c", str(config_path), "--ext", ".js,.jsx,.ts,.tsx", "--format", "json", target], timeout=180)
    config_path.unlink(missing_ok=True)
    findings: list[Finding] = []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    for file_result in data:
        file_path = file_result.get("filePath")
        for msg in file_result.get("messages", []):
            rule = msg.get("ruleId") or "unknown-rule"
            findings.append(Finding(
                title=f"ESLint security rule violation: {rule}",
                severity="high" if msg.get("severity") == 2 else "medium",
                category="ESLint (security rules)",
                description=msg.get("message", ""),
                evidence=_snippet(file_path, msg.get("line")),
                remediation="Avoid dynamic code execution (eval/Function/setTimeout with strings) — refactor to explicit function references.",
                file=file_path,
                line=msg.get("line"),
                cwe="CWE-95",
                source="eslint",
                confidence=0.75,
            ))
    return findings


# ---------------------------------------------------------------------------
# Structural SAST — ast-grep. Matches code by AST shape rather than text, so
# it catches things a text-regex would miss (e.g. eval() called with
# whitespace/line-breaks/comments in between) and misses less than the
# built-in scanner.py regex rules would on reformatted code. Ships with a
# small built-in pattern set rather than requiring an external rules repo.
# ---------------------------------------------------------------------------
_AST_GREP_PATTERNS: list[tuple[str, str, str]] = [
    # (pattern, language, human title)
    ("eval($X)", "python", "Dynamic code execution via eval()"),
    ("eval($X)", "javascript", "Dynamic code execution via eval()"),
    ("document.write($X)", "javascript", "Unsafe DOM write via document.write()"),
    ("subprocess.call($X, shell=True)", "python", "Shell injection risk via subprocess shell=True"),
]


def run_ast_grep(target: str) -> list[Finding]:
    binary = _which("ast-grep")
    if not binary:
        return []
    findings: list[Finding] = []
    for pattern, lang, title in _AST_GREP_PATTERNS:
        _, out, _ = _run([binary, "run", "--pattern", pattern, "--lang", lang, "--json", target], timeout=60)
        try:
            matches = json.loads(out)
        except json.JSONDecodeError:
            continue
        for m in matches:
            file_path = m.get("file")
            line = ((m.get("range") or {}).get("start") or {}).get("line")
            findings.append(Finding(
                title=title,
                severity="high",
                category="ast-grep (structural)",
                description=f"Structural match for pattern `{pattern}` ({lang}) — matched regardless of formatting/whitespace.",
                evidence=(m.get("text") or "")[:300],
                remediation="Review whether dynamic execution/shell invocation here is necessary; replace with a safer, explicit alternative.",
                file=file_path,
                line=(line + 1) if isinstance(line, int) else None,  # ast-grep lines are 0-indexed
                cwe="CWE-95",
                source="ast-grep",
                confidence=0.7,
            ))
    return findings


# ---------------------------------------------------------------------------
# JWT testing — jwt_tool. Like sqlmap, this is an active-testing tool that
# needs an explicit input (a token) it wasn't handed automatically, so it is
# deliberately NOT registered in FILE_ADAPTERS/URL_ADAPTERS. Only reachable
# via `dexter exploit jwt_tool <token>`.
# ---------------------------------------------------------------------------
def run_jwt_tool(token: str) -> list[Finding]:
    binary = _which("jwt_tool")
    if not binary:
        return []
    if not token:
        raise ValueError("jwt_tool requires an explicit JWT to test (e.g. --token <jwt>).")
    _, out, _ = _run([binary, token, "-M", "pb"], timeout=120)
    findings: list[Finding] = []
    for line in out.splitlines():
        if "vulnerable" not in line.lower():
            continue
        findings.append(Finding(
            title="JWT weakness identified",
            severity="high",
            category="jwt_tool",
            description=line.strip()[:300],
            evidence=line.strip()[:300],
            remediation="Enforce a fixed, strong signing algorithm server-side (reject 'none' and algorithm-confusion attempts) and use a high-entropy secret or asymmetric keys.",
            cwe="CWE-347",
            source="jwt_tool",
            confidence=0.75,
        ))
    return findings


FILE_ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {
    "semgrep": run_semgrep,
    "bandit": run_bandit,
    "gitleaks": run_gitleaks,
    "trivy": run_trivy,
    "trufflehog": run_trufflehog,
    "retire": run_retire,
    "eslint": run_eslint,
    "ast-grep": run_ast_grep,
}

URL_ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {
    "nuclei": run_nuclei,
    "nikto": run_nikto,
    "nmap": run_nmap,
    "zap": run_zap,
    "ffuf": run_ffuf,
    "httpx": run_httpx,
    "katana": run_katana,
}

ALL_ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {**FILE_ADAPTERS, **URL_ADAPTERS}


def is_url(target: str) -> bool:
    return urlparse(target).scheme in {"http", "https"}


def is_live_target(target: str) -> bool:
    # A URL, or anything that isn't a real local path — covers bare
    # hostnames/IPs (nmap doesn't take a scheme, just a host).
    return is_url(target) or not Path(target).exists()


def is_installed(name: str) -> bool:
    if name == "zap":
        return zap_reachable()
    box = sandbox.get_active()
    if box is not None:
        rc, _, _ = box.exec(["sh", "-c", f"command -v {name}"])
        return rc == 0
    return _which(name) is not None


def tool_status() -> list[dict]:
    def kind(name: str) -> str:
        if name in FILE_ADAPTERS:
            return "file/dir"
        if name == "zap":
            return "live URL (requires authorization + a running daemon)"
        return "live host/URL (requires authorization)"

    return [{"name": name, "installed": is_installed(name), "target_kind": kind(name)} for name in ALL_ADAPTERS]


def run_adapters(target: str, on_tool: Callable[[str], None] | None = None) -> list[Finding]:
    if Path(target).is_dir():
        adapters = FILE_ADAPTERS
    elif is_live_target(target):
        adapters = URL_ADAPTERS
    else:
        adapters = {}
    findings: list[Finding] = []
    for name, fn in adapters.items():
        if not is_installed(name):
            continue
        if on_tool:
            on_tool(name)
        findings.extend(fn(target))
    return findings


EXPLOIT_TOOLS = {"sqlmap", "jwt_tool"}


def run_single_exploit(name: str, target: str, param: str) -> list[Finding]:
    if name not in EXPLOIT_TOOLS:
        raise ValueError(f"Unknown exploit tool: {name}. Known: {', '.join(EXPLOIT_TOOLS)}")
    if not _which(name):
        raise RuntimeError(f"{name} is not installed or not on PATH.")
    if name == "sqlmap":
        return run_sqlmap(target, param)
    if name == "jwt_tool":
        return run_jwt_tool(target)  # `target` holds the JWT string for this tool
    raise ValueError(f"No dispatcher wired for {name}")


def run_single_adapter(name: str, target: str) -> list[Finding]:
    fn = ALL_ADAPTERS.get(name)
    if not fn:
        raise ValueError(f"Unknown tool: {name}. Known tools: {', '.join(ALL_ADAPTERS)}")
    if not is_installed(name):
        raise RuntimeError(f"{name} is not installed or not on PATH.")
    return fn(target)