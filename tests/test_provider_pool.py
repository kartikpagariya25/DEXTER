import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from dexter import provider_pool as pp


class _FakeHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        auth = self.headers.get("Authorization", "")
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if auth == "Bearer bad-key":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error":"rate limited"}')
        else:
            body = json.dumps({"choices": [{"message": {"content": f"ok:{auth}"}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


@pytest.fixture()
def fake_server():
    server = HTTPServer(("127.0.0.1", 0), _FakeHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_rotates_past_rate_limited_key(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key,good-key")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "pool"
    assert result.text == "ok:Bearer good-key"


def test_rate_limited_key_marked_cooling(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key,good-key")

    pp.call_llm([{"role": "user", "content": "hi"}])
    state = pp._load_state()

    assert pp._key_id("bad-key") in state
    assert pp._key_id("good-key") not in state


def test_all_keys_exhausted_falls_back_to_none(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DEXTER_LLM_KEYS", "any-key")
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "none"
