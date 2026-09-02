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
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        return -1, "", "binary not found"
    except subprocess.TimeoutExpired:
        return -2, "", "timed out"


def _snippet(path: str | None, line: int | None) -> str:
    if not path or not line:
        return ""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()
        return lines[line - 1].strip()[:300] if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def run_semgrep(target: str) -> list[Finding]:
    if not _which("semgrep"):
        return []
    _, out, _ = _run(["semgrep", "--config=auto", "--json", "--quiet", "--timeout", "120", target], timeout=240)
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
    _, out, _ = _run(["bandit", "-r", target, "-f", "json", "-q"], timeout=180)
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
    report_path = Path(tempfile.gettempdir()) / f"dexter_gitleaks_{abs(hash(target))}.json"
    _run([binary, "detect", "--source", target, "--no-git", "--report-format", "json", "--report-path", str(report_path), "--exit-code", "0"], timeout=180)
    findings: list[Finding] = []
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
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
        report_path.unlink(missing_ok=True)
    return findings


def run_trivy(target: str) -> list[Finding]:
    binary = _which("trivy")
    if not binary or not Path(target).is_dir():
        return []
    report_path = Path(tempfile.gettempdir()) / f"dexter_trivy_{abs(hash(target))}.json"
    _run([binary, "fs", "--format", "json", "--scanners", "vuln", "--output", str(report_path), target], timeout=300)
    findings: list[Finding] = []
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
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
        report_path.unlink(missing_ok=True)
    return findings


def run_nmap(target: str) -> list[Finding]:
    binary = _which("nmap")
    if not binary:
        return []
    if not is_authorized(target):
        return [_authorization_required(target, "nmap")]
    host = urlparse(target).hostname or target
    report_path = Path(tempfile.gettempdir()) / f"dexter_nmap_{abs(hash(target))}.xml"
    _run([binary, "-T4", "-sV", "--top-ports", "100", "-oX", str(report_path), host], timeout=240)
    findings: list[Finding] = []
    if report_path.exists():
        try:
            root = ElementTree.parse(report_path).getroot()
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
        report_path.unlink(missing_ok=True)
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
    report_path = Path(tempfile.gettempdir()) / f"dexter_ffuf_{abs(hash(target))}.json"
    _run([binary, "-u", fuzz_url, "-w", str(_default_wordlist()), "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", str(report_path), "-s"], timeout=180)
    findings: list[Finding] = []
    if report_path.exists():
        try:
            data = json.loads(report_path.read_text(encoding="utf-8"))
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
        report_path.unlink(missing_ok=True)
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


FILE_ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {
    "semgrep": run_semgrep,
    "bandit": run_bandit,
    "gitleaks": run_gitleaks,
    "trivy": run_trivy,
}

URL_ADAPTERS: dict[str, Callable[[str], list[Finding]]] = {
    "nuclei": run_nuclei,
    "nikto": run_nikto,
    "nmap": run_nmap,
    "zap": run_zap,
    "ffuf": run_ffuf,
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


EXPLOIT_TOOLS = {"sqlmap"}


def run_single_exploit(name: str, target: str, param: str) -> list[Finding]:
    if name not in EXPLOIT_TOOLS:
        raise ValueError(f"Unknown exploit tool: {name}. Known: {', '.join(EXPLOIT_TOOLS)}")
    if not _which(name):
        raise RuntimeError(f"{name} is not installed or not on PATH.")
    if name == "sqlmap":
        return run_sqlmap(target, param)
    raise ValueError(f"No dispatcher wired for {name}")


def run_single_adapter(name: str, target: str) -> list[Finding]:
    fn = ALL_ADAPTERS.get(name)
    if not fn:
        raise ValueError(f"Unknown tool: {name}. Known tools: {', '.join(ALL_ADAPTERS)}")
    if not is_installed(name):
        raise RuntimeError(f"{name} is not installed or not on PATH.")
    return fn(target)
