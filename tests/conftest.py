import pytest


@pytest.fixture(autouse=True)
def _no_rate_limit_waits(monkeypatch):
    monkeypatch.setenv("DEXTER_LLM_MAX_WAIT", "0")
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "")
