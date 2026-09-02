import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from dexter import agentic_verify as av


def test_entropy_distinguishes_real_secrets_from_placeholders():
    assert av._entropy("changeme") < av._entropy("sk-live-7hK9mP2xQ4nR8vT1")


def test_read_lines_returns_real_file_content(tmp_path: Path):
    f = tmp_path / "app.py"
    f.write_text("line one\nline two\nline three\n", encoding="utf-8")

    result = av._read_lines(str(tmp_path), "app.py", 1, 2)

    assert result == "line one\nline two"


def test_grep_codebase_finds_real_matches(tmp_path: Path):
    (tmp_path / "a.py").write_text("SECRET = 'x'\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import os\n", encoding="utf-8")

    result = av._grep_codebase(str(tmp_path), "SECRET")

    assert "a.py" in result
    assert "b.py" not in result


def test_parse_verdict_handles_fenced_json():
    text = '```json\n{"verdict": "verified", "confidence": 0.9, "reasoning": "clear"}\n```'
    result = av._parse_verdict(text)
    assert result == {"verdict": "verified", "confidence": 0.9, "reasoning": "clear"}


def test_parse_verdict_returns_none_on_garbage():
    assert av._parse_verdict("not json at all") is None


class _MultiTurnHandler(BaseHTTPRequestHandler):
    calls = 0

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        _MultiTurnHandler.calls += 1
        if _MultiTurnHandler.calls == 1:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                {"id": "1", "function": {"name": "shannon_entropy", "arguments": json.dumps({"value": "abc"})}}
            ]}
        else:
            msg = {"role": "assistant", "content": json.dumps({"verdict": "verified", "confidence": 0.8, "reasoning": "ok"}), "tool_calls": None}
        body = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


def test_full_loop_executes_tool_then_returns_verdict(tmp_path: Path, monkeypatch):
    _MultiTurnHandler.calls = 0
    server = HTTPServer(("127.0.0.1", 0), _MultiTurnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
        monkeypatch.setenv("DEXTER_LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("DEXTER_LLM_KEYS", "fake-key")

        steps = []
        result = av.agentic_verify({"title": "t", "file": "f", "line": 1, "evidence": "e", "description": "d"}, str(tmp_path), on_step=steps.append)

        assert result == {"verdict": "verified", "confidence": 0.8, "reasoning": "ok"}
        assert len(steps) == 1
        assert "shannon_entropy" in steps[0]
    finally:
        server.shutdown()


class _NeverStopsHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        msg = {"role": "assistant", "content": None, "tool_calls": [
            {"id": "x", "function": {"name": "shannon_entropy", "arguments": json.dumps({"value": "x"})}}
        ]}
        body = json.dumps({"choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        return


def test_circuit_breaker_stops_runaway_tool_calling(tmp_path: Path, monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), _NeverStopsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
        monkeypatch.setenv("DEXTER_LLM_BASE_URL", f"http://127.0.0.1:{server.server_port}")
        monkeypatch.setenv("DEXTER_LLM_KEYS", "fake-key")

        steps = []
        result = av.agentic_verify({"title": "t", "file": "f", "line": 1, "evidence": "e", "description": "d"}, str(tmp_path), on_step=steps.append)

        assert len(steps) == av.MAX_TOOL_ITERATIONS
        assert result is None
    finally:
        server.shutdown()


def test_returns_none_when_no_llm_reachable(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    result = av.agentic_verify({"title": "t", "file": "f", "line": 1, "evidence": "e", "description": "d"}, str(tmp_path))

    assert result is None
