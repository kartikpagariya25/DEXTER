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
        elif auth == "Bearer bad-key-with-retry-after":
            self.send_response(429)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "3")
            self.end_headers()
            self.wfile.write(b'{"error":"rate limited"}')
        else:
            ua = self.headers.get("User-Agent", "")
            body = json.dumps({"choices": [{"message": {"content": f"ok:{auth}", "_ua": ua}}]}).encode()
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


def test_sends_real_user_agent_not_default_urllib_signature(fake_server, tmp_path: Path, monkeypatch):
    # Regression: requests sent with no explicit User-Agent default to
    # "Python-urllib/x.x", a well-known automated-client signature. Groq's
    # API sits behind Cloudflare, whose edge WAF blocks that signature
    # outright with error 1010 - before the request ever reaches Groq's
    # actual API logic. This has nothing to do with the API key itself.
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "good-key")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    ua = result.message["_ua"]
    assert ua, "no User-Agent header was sent at all"
    assert "python-urllib" not in ua.lower()


def test_local_fallback_sends_api_key_when_configured(fake_server, tmp_path: Path, monkeypatch):
    # Regression: the local endpoint never sent an Authorization header at
    # all, so a locked-down local server (e.g. vLLM started with --api-key)
    # was unreachable from Dexter with no way to authenticate.
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_API_KEY", "good-key")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "local"
    assert result.text == "ok:Bearer good-key"


def test_rate_limited_key_marked_cooling(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key,good-key")

    pp.call_llm([{"role": "user", "content": "hi"}])
    state = pp._load_state()

    assert pp._key_id("bad-key") in state
    assert pp._key_id("good-key") not in state


def test_retry_after_header_is_honored_over_default_cooldown(fake_server, tmp_path: Path, monkeypatch):
    # Regression: a single 429 used to blind-cool a key for 5 hours
    # regardless of what the server actually asked for. Groq sends a real
    # Retry-After header on every 429, almost always a short per-minute
    # window, not a day-long block.
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key-with-retry-after,good-key")
    monkeypatch.delenv("DEXTER_LLM_COOLDOWN_SECONDS", raising=False)

    pp.call_llm([{"role": "user", "content": "hi"}])
    state = pp._load_state()

    kid = pp._key_id("bad-key-with-retry-after")
    remaining = state[kid] - pp.time.time()
    assert 0 < remaining <= 5, f"expected ~3s cooldown from Retry-After header, got {remaining:.1f}s"


def test_default_cooldown_without_retry_after_is_short_not_five_hours(fake_server, tmp_path: Path, monkeypatch):
    # Regression: DEFAULT_COOLDOWN_SECONDS was 5 * 3600. With only one key
    # configured (the common single-free-tier-key setup this tool
    # documents), one ordinary per-minute rate limit blip took the whole
    # pool offline for 5 hours.
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key,good-key")
    monkeypatch.delenv("DEXTER_LLM_COOLDOWN_SECONDS", raising=False)

    pp.call_llm([{"role": "user", "content": "hi"}])
    state = pp._load_state()

    kid = pp._key_id("bad-key")
    remaining = state[kid] - pp.time.time()
    assert remaining <= 120, f"default cooldown with no Retry-After header should be short, got {remaining:.1f}s"


def test_cooldown_display_shows_seconds_for_short_waits(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key-with-retry-after")

    pp.call_llm([{"role": "user", "content": "hi"}])
    status = pp.pool_status()

    assert "0h0m left" not in status
    assert "s left" in status


def test_all_keys_exhausted_falls_back_to_none(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DEXTER_LLM_KEYS", "any-key")
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "none"


def test_no_keys_configured_gives_specific_error(tmp_path: Path, monkeypatch):
    # Regression: failures used to be swallowed into an empty PoolResult
    # with no way to tell why - "unreachable or unparseable" covered five
    # different real causes with one message.
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "none"
    assert result.error is not None
    assert "no cloud api key" in result.error.lower()


def test_429_failure_reports_rate_limited_in_error(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key")
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    result = pp.call_llm([{"role": "user", "content": "hi"}])

    assert result.provider == "none"
    assert result.error is not None
    assert "429" in result.error or "rate-limited" in result.error


def test_key_already_cooling_reports_that_specifically(fake_server, tmp_path: Path, monkeypatch):
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path))
    monkeypatch.setenv("DEXTER_LLM_BASE_URL", fake_server)
    monkeypatch.setenv("DEXTER_LLM_KEYS", "bad-key")
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")

    pp.call_llm([{"role": "user", "content": "hi"}])  # first call puts the key in cooldown
    result = pp.call_llm([{"role": "user", "content": "hi again"}])  # second call should see it already cooling

    assert result.provider == "none"
    assert "cooling down" in result.error
