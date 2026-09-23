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


def test_agentic_refine_applies_cross_finding_adjustment():
    from dexter.loop import _agentic_refine, _apply_refine_result
    from dexter.models import Finding

    f1 = Finding("Debug mode enabled", "medium", "OWASP", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.9)
    f2 = Finding("Hard-coded secret", "high", "OWASP", "d", "e", "r", "/a.py", 2, None, None, source="local-rule", confidence=0.6)
    fake_result = {"adjustments": [{"index": 1, "confidence_delta": 0.2, "reason": "corroborating context"}], "summary": "test"}

    _apply_refine_result([f1, f2], fake_result)

    assert f2.confidence == 0.8
    assert "Refine: corroborating context" in f2.description
    assert f1.confidence == 0.9  # untouched, no adjustment targeted it


def test_agentic_refine_clamps_extreme_delta():
    from dexter.loop import _apply_refine_result
    from dexter.models import Finding

    f = Finding("x", "high", "y", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.5)
    _apply_refine_result([f], {"adjustments": [{"index": 0, "confidence_delta": 999, "reason": "x"}]})

    assert f.confidence == 0.8  # clamped to the real +0.3 max, not the attempted +999


def test_agentic_refine_ignores_out_of_range_index():
    from dexter.loop import _apply_refine_result
    from dexter.models import Finding

    f = Finding("x", "high", "y", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.5)
    _apply_refine_result([f], {"adjustments": [{"index": 5, "confidence_delta": 0.3, "reason": "x"}]})

    assert f.confidence == 0.5  # unchanged, index 5 doesn't exist


def test_agentic_refine_returns_none_when_no_llm(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")
    from dexter.loop import _agentic_refine
    from dexter.models import Finding

    f = Finding("x", "high", "y", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.5)

    assert _agentic_refine([f], "") is None


def test_agentic_refine_reports_reason_via_on_step(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("DEXTER_LLM_LOCAL_URL", "http://127.0.0.1:1")
    from dexter.loop import _agentic_refine
    from dexter.models import Finding

    f = Finding("x", "high", "y", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.5)
    steps: list[str] = []

    _agentic_refine([f], "", on_step=steps.append)

    assert any("no cloud api key" in s.lower() for s in steps)


def test_agentic_refine_parses_json_wrapped_in_prose(monkeypatch):
    # Regression: same brittle "whole response must be clean JSON" parser
    # that was fixed in agentic_verify existed here too, unfixed, and
    # would silently discard every real Refine response that Groq wraps
    # in a sentence (the common case).
    from dexter.loop import _agentic_refine
    from dexter.models import Finding
    from dexter import provider_pool as pp

    wrapped = 'Here is my analysis:\n\n{"adjustments": [], "summary": "no changes needed"}\n\nHope that helps.'
    monkeypatch.setattr("dexter.loop.call_llm", lambda messages, tools=None: pp.PoolResult(wrapped, "pool"))

    f = Finding("x", "high", "y", "d", "e", "r", "/a.py", 1, None, None, source="local-rule", confidence=0.5)
    result = _agentic_refine([f], "")

    assert result == {"adjustments": [], "summary": "no changes needed"}


def test_refine_falls_back_to_keyword_matching_offline(tmp_path: Path, monkeypatch):
    # Regression: with no LLM reachable, refine behavior must match exactly
    # what it did before agentic refine existed.
    target = tmp_path / "app.py"
    target.write_text('query = "SELECT * FROM users WHERE id=" + user_id\n', encoding="utf-8")
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    run = run_savr([str(tmp_path)], "prioritize injection issues", "standard", "test-run")
    finding = run.findings[0]

    assert finding.confidence == 0.55  # same value as the original pre-agentic test


def test_stage_callback_fires_in_order(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("DEXTER_LLM_KEYS", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    seen: list[str] = []

    run_savr([str(tmp_path)], "", "standard", "test-run", on_stage=seen.append)
    base_stages = [s for s in seen if ":" not in s]

    assert base_stages == ["scan", "analyze", "verify", "refine", "report"]


def test_github_fetch_temp_dir_is_cleaned_up_after_scan(tmp_path: Path, monkeypatch):
    fake_repo_dir = tmp_path / "fetched" / "repo-main"
    fake_repo_dir.mkdir(parents=True)
    (fake_repo_dir / "app.py").write_text("x = 1\n", encoding="utf-8")

    monkeypatch.setattr("dexter.loop.is_github_repo_url", lambda t: t == "https://github.com/owner/repo")
    monkeypatch.setattr("dexter.loop.fetch_github_repo", lambda t, on_step=None: str(fake_repo_dir))
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    monkeypatch.delenv("DEXTER_KEEP_GITHUB_TEMP", raising=False)

    run_savr(["https://github.com/owner/repo"], "", "standard", "cleanup-test")

    assert not fake_repo_dir.exists()


def test_github_fetch_temp_dir_kept_when_env_set(tmp_path: Path, monkeypatch):
    fake_repo_dir = tmp_path / "fetched" / "repo-main"
    fake_repo_dir.mkdir(parents=True)

    monkeypatch.setattr("dexter.loop.is_github_repo_url", lambda t: t == "https://github.com/owner/repo")
    monkeypatch.setattr("dexter.loop.fetch_github_repo", lambda t, on_step=None: str(fake_repo_dir))
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    monkeypatch.setenv("DEXTER_KEEP_GITHUB_TEMP", "1")

    run_savr(["https://github.com/owner/repo"], "", "standard", "cleanup-test2")

    assert fake_repo_dir.exists()
