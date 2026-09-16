import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from dexter import verify_cache
from dexter.agentic_verify import agentic_verify


def test_fingerprint_is_stable_for_same_finding():
    f1 = {"title": "Hard-coded secret", "file": "/a.py", "evidence": "SECRET=x"}
    f2 = {"title": "Hard-coded secret", "file": "/a.py", "evidence": "SECRET=x"}

    assert verify_cache.fingerprint(f1) == verify_cache.fingerprint(f2)


def test_fingerprint_differs_for_different_evidence():
    f1 = {"title": "Hard-coded secret", "file": "/a.py", "evidence": "SECRET=x"}
    f2 = {"title": "Hard-coded secret", "file": "/a.py", "evidence": "SECRET=y"}

    assert verify_cache.fingerprint(f1) != verify_cache.fingerprint(f2)


def test_put_then_get_round_trip(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    finding = {"title": "x", "file": "/a.py", "evidence": "e"}
    result = {"verdict": "verified", "confidence": 0.9, "reasoning": "test"}

    assert verify_cache.get(finding) is None
    verify_cache.put(finding, result)

    assert verify_cache.get(finding) == result


def test_clear_removes_cache(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    finding = {"title": "x", "file": "/a.py", "evidence": "e"}
    verify_cache.put(finding, {"verdict": "verified", "confidence": 0.9, "reasoning": "r"})

    removed = verify_cache.clear()

    assert removed == 1
    assert verify_cache.get(finding) is None


class _CountingHandler(BaseHTTPRequestHandler):
    call_count = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        _CountingHandler.call_count += 1
        msg = {"role": "assistant", "content": json.dumps({"verdict": "verified", "confidence": 0.9, "reasoning": "real call"}), "tool_calls": None}
        body = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


def test_second_call_for_same_finding_never_hits_the_llm(tmp_path: Path, monkeypatch):
    _CountingHandler.call_count = 0
    server = HTTPServer(("127.0.0.1", 0), _CountingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
        monkeypatch.setenv("DEXTER_LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("DEXTER_LLM_KEYS", "fake-key")

        finding = {"title": "Hard-coded secret", "file": "/a.py", "line": 1, "evidence": "SECRET=realvalue", "description": "d"}

        first = agentic_verify(finding, str(tmp_path))
        assert _CountingHandler.call_count == 1
        assert first["verdict"] == "verified"

        second = agentic_verify(finding, str(tmp_path))
        assert _CountingHandler.call_count == 1  # still 1 — no new LLM call was made
        assert second == first
    finally:
        server.shutdown()
