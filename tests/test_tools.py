import json
import tempfile
from pathlib import Path

import pytest

from dexter import tools
from dexter.authorization import authorize, is_authorized, list_authorized, revoke


def test_is_url_detection():
    assert tools.is_url("https://example.test") is True
    assert tools.is_url("/local/path") is False


def test_run_adapters_picks_file_adapters_for_directory(tmp_path: Path, monkeypatch):
    calls = []
    monkeypatch.setattr(tools, "is_installed", lambda name: name == "semgrep")
    monkeypatch.setattr(tools, "FILE_ADAPTERS", {"semgrep": lambda t: calls.append(t) or []})
    monkeypatch.setattr(tools, "URL_ADAPTERS", {})

    tools.run_adapters(str(tmp_path))

    assert calls == [str(tmp_path)]


def test_run_adapters_skips_uninstalled_tools(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(tools, "is_installed", lambda name: False)
    monkeypatch.setattr(tools, "FILE_ADAPTERS", {"semgrep": lambda t: [1, 2, 3]})
    monkeypatch.setattr(tools, "URL_ADAPTERS", {})

    result = tools.run_adapters(str(tmp_path))

    assert result == []


def test_nuclei_skipped_without_authorization(monkeypatch):
    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/nuclei")

    findings = tools.run_nuclei("https://not-authorized.test")

    assert len(findings) == 1
    assert findings[0].source == "dexter-guard"
    assert "not authorized" in findings[0].title


def test_nmap_skipped_without_authorization(monkeypatch):
    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/nmap")

    findings = tools.run_nmap("not-authorized.test")

    assert len(findings) == 1
    assert findings[0].source == "dexter-guard"


def test_nmap_parses_open_ports_from_real_xml(tmp_path: Path, monkeypatch):
    # Real nmap -oX output shape (trimmed), captured from a live scan.
    xml = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="filtered"/><service name="ssh"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports>
</host>
</nmaprun>"""
    target = "example.test"
    expected_path = tmp_path / f"dexter_nmap_{abs(hash(target))}.xml"
    expected_path.write_text(xml, encoding="utf-8")

    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/nmap")
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "_run", lambda cmd, timeout=300: (0, "", ""))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    findings = tools.run_nmap(target)

    titles = {f.title for f in findings}
    assert "Open port 80/tcp (http)" in titles
    assert "Open port 443/tcp (https)" in titles
    assert not any("22" in t for t in titles)  # filtered port must not appear


def test_zap_uses_daemon_check_not_path(monkeypatch):
    monkeypatch.setattr(tools, "_which", lambda binary: None)  # zap not a binary on PATH
    monkeypatch.setattr(tools, "zap_reachable", lambda: True)

    assert tools.is_installed("zap") is True


def test_ffuf_skipped_without_authorization(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/ffuf")

    findings = tools.run_ffuf("https://not-authorized.test")

    assert len(findings) == 1
    assert findings[0].source == "dexter-guard"


def test_ffuf_marks_sensitive_paths_higher(tmp_path: Path, monkeypatch):
    # Real ffuf -of json output shape.
    fake_report = {
        "results": [
            {"input": {"FUZZ": ".env"}, "status": 200, "url": "http://t/.env"},
            {"input": {"FUZZ": "admin"}, "status": 301, "url": "http://t/admin"},
        ]
    }
    target = "http://t"
    report_path = tmp_path / f"dexter_ffuf_{abs(hash(target))}.json"
    report_path.write_text(json.dumps(fake_report), encoding="utf-8")

    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/ffuf")
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "_run", lambda cmd, timeout=300: (0, "", ""))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    findings = tools.run_ffuf(target)
    by_path = {f.evidence: f for f in findings}

    assert by_path["http://t/.env"].severity == "high"
    assert by_path["http://t/admin"].severity == "low"
    assert tools.is_live_target("https://example.test") is True
    assert tools.is_live_target("scanme.nmap.org") is True
    assert tools.is_live_target(str(tmp_path)) is False


def test_authorize_then_revoke(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))

    assert not is_authorized("https://example.test")
    authorize("https://example.test")
    assert is_authorized("https://example.test")
    assert "https://example.test" in list_authorized()

    revoke("https://example.test")
    assert not is_authorized("https://example.test")


def test_zap_skipped_without_authorization(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setattr(tools, "zap_reachable", lambda: True)

    findings = tools.run_zap("https://not-authorized.test")

    assert len(findings) == 1
    assert findings[0].source == "dexter-guard"


def test_zap_returns_nothing_when_daemon_unreachable(monkeypatch):
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "zap_reachable", lambda: False)

    findings = tools.run_zap("https://authorized.test")

    assert findings == []


def test_zap_parses_real_alert_schema(monkeypatch):
    # Captured from a live ZAP 2.17.0 daemon's /JSON/core/view/alerts/ response.
    real_alert = {
        "alert": "Missing Anti-clickjacking Header",
        "risk": "Medium",
        "confidence": "Medium",
        "description": "The response does not protect against ClickJacking attacks.",
        "solution": "Ensure one of the following:\nSet X-Frame-Options.",
        "evidence": "",
        "url": "http://localhost:9191/",
        "cweid": "1021",
    }
    responses = {
        "/JSON/core/view/version/": {"version": "2.17.0"},
        "/JSON/spider/action/scan/": {"scan": "0"},
        "/JSON/spider/view/status/": {"status": "100"},
        "/JSON/pscan/view/recordsToScan/": {"recordsToScan": "0"},
        "/JSON/core/view/alerts/": {"alerts": [real_alert]},
    }
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "_zap_get", lambda path, params=None, timeout=15: responses.get(path))
    monkeypatch.delenv("DEXTER_ZAP_ACTIVE_SCAN", raising=False)

    findings = tools.run_zap("http://localhost:9191/")

    assert len(findings) == 1
    assert findings[0].title == "Missing Anti-clickjacking Header"
    assert findings[0].severity == "medium"
    assert findings[0].source == "zap"
    assert findings[0].cwe == "CWE-1021"


def test_is_live_target(tmp_path: Path):
    assert tools.is_live_target("https://example.test") is True
    assert tools.is_live_target("scanme.nmap.org") is True
    assert tools.is_live_target(str(tmp_path)) is False


def test_sqlmap_not_in_automatic_scan_adapters():
    # Structural safety check: sqlmap must never fire from a normal scan.
    assert "sqlmap" not in tools.URL_ADAPTERS
    assert "sqlmap" not in tools.FILE_ADAPTERS
    assert "sqlmap" not in tools.ALL_ADAPTERS
    assert "sqlmap" in tools.EXPLOIT_TOOLS


def test_sqlmap_requires_explicit_param(monkeypatch):
    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/sqlmap")

    with pytest.raises(ValueError):
        tools.run_sqlmap("http://t/?id=1", "")


def test_sqlmap_skipped_without_authorization(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/sqlmap")

    findings = tools.run_sqlmap("http://not-authorized.test/?id=1", "id")

    assert len(findings) == 1
    assert findings[0].source == "dexter-guard"


def test_sqlmap_parses_real_log_output(tmp_path: Path, monkeypatch):
    # Captured verbatim from a real sqlmap run against a genuinely
    # SQL-injectable local test endpoint.
    real_log = """sqlmap identified the following injection point(s) with a total of 53 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 3118=3118

    Type: error-based
    Title: SQLite >= 3.9 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON path)
    Payload: id=1 AND 5451=JSON_EXTRACT(CHAR(123,125),CHAR(113,118,107,122,113))
---
back-end DBMS: SQLite
"""
    target = "http://localhost:9299/?id=1"
    output_dir = tmp_path / f"dexter_sqlmap_{abs(hash(target))}" / "localhost"
    output_dir.mkdir(parents=True)
    (output_dir / "log").write_text(real_log, encoding="utf-8")

    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/sqlmap")
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "_run", lambda cmd, timeout=300: (0, "", ""))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    findings = tools.run_sqlmap(target, "id")

    assert len(findings) == 2
    assert all(f.severity == "critical" for f in findings)
    assert all(f.verification == "verified" for f in findings)
    assert "boolean-based blind" in findings[0].title


def test_sqlmap_no_injection_found(tmp_path: Path, monkeypatch):
    clean_log = "[INFO] testing connection to the target URL\nall tested parameters do not appear to be injectable\n"
    target = "http://localhost:9300/?id=1"
    output_dir = tmp_path / f"dexter_sqlmap_{abs(hash(target))}" / "localhost"
    output_dir.mkdir(parents=True)
    (output_dir / "log").write_text(clean_log, encoding="utf-8")

    monkeypatch.setattr(tools, "_which", lambda binary: "/usr/bin/sqlmap")
    monkeypatch.setattr(tools, "is_authorized", lambda t: True)
    monkeypatch.setattr(tools, "_run", lambda cmd, timeout=300: (0, "", ""))
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(tmp_path))

    findings = tools.run_sqlmap(target, "id")

    assert findings == []


def test_run_single_exploit_rejects_unknown_tool():
    with pytest.raises(ValueError):
        tools.run_single_exploit("metasploit", "http://t", "id")
