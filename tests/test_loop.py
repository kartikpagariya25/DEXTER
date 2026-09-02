from pathlib import Path

import pytest

from dexter.loop import run_savr


@pytest.fixture(autouse=True)
def _no_external_tools(monkeypatch):
    # These tests exercise verify/refine logic on local-rule findings only.
    # Whether Semgrep/Bandit/etc. happen to be installed on the machine
    # running the suite shouldn't change their outcome or speed.
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])


def test_agentic_verify_used_when_llm_reachable(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text('query = "SELECT * FROM users WHERE id=" + user_id\n', encoding="utf-8")
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    monkeypatch.setattr(
        "dexter.loop.agentic_verify",
        lambda finding_dict, root, on_step=None: {"verdict": "needs-manual-review", "confidence": 0.77, "reasoning": "test reasoning"},
    )

    run = run_savr([str(tmp_path)], "", "standard", "test-run")
    finding = next(f for f in run.findings if f.title == "Potential SQL injection")

    assert finding.confidence == 0.77
    assert "AI verification: test reasoning" in finding.description


def test_falls_back_to_heuristic_when_agentic_verify_unavailable(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text('password = "changeme"\n', encoding="utf-8")
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    monkeypatch.setattr("dexter.loop.agentic_verify", lambda finding_dict, root, on_step=None: None)

    run = run_savr([str(tmp_path)], "", "standard", "test-run")
    finding = run.findings[0]

    # Same offline heuristic behavior as before agentic verification existed.
    assert finding.verification == "false-positive-suspected"
    assert finding.confidence < 0.5


def test_placeholder_secret_is_downgraded(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text('password = "changeme"\n', encoding="utf-8")
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    run = run_savr([str(tmp_path)], "", "standard", "test-run")
    finding = run.findings[0]

    assert finding.verification == "false-positive-suspected"
    assert finding.confidence < 0.5


def test_real_looking_secret_is_verified(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text('api_key = "sk-live-abc123def456ghi789jklmno"\n', encoding="utf-8")
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    run = run_savr([str(tmp_path)], "", "standard", "test-run")
    finding = run.findings[0]

    assert finding.verification == "verified"
    assert finding.confidence > 0.5


def test_refine_boosts_confidence_once_not_per_iteration(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text('query = "SELECT * FROM users WHERE id=" + user_id\n', encoding="utf-8")
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    run = run_savr([str(tmp_path)], "prioritize injection issues", "standard", "test-run")
    finding = run.findings[0]

    assert finding.verification == "needs-manual-review"
    assert finding.confidence == 0.55


def test_stage_callback_fires_in_order(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    seen: list[str] = []

    run_savr([str(tmp_path)], "", "standard", "test-run", on_stage=seen.append)
    base_stages = [s for s in seen if ":" not in s]

    assert base_stages == ["scan", "analyze", "verify", "refine", "report"]
