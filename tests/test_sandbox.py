from pathlib import Path

from dexter import sandbox


def test_sandbox_disabled_by_default(monkeypatch):
    monkeypatch.delenv("DEXTER_SANDBOX", raising=False)
    assert sandbox.sandbox_enabled() is False


def test_sandbox_enabled_via_env_var(monkeypatch):
    monkeypatch.setenv("DEXTER_SANDBOX", "1")
    assert sandbox.sandbox_enabled() is True


def test_sandbox_not_enabled_for_other_values(monkeypatch):
    monkeypatch.setenv("DEXTER_SANDBOX", "true")  # only the literal "1" counts
    assert sandbox.sandbox_enabled() is False


def test_active_sandbox_registry_defaults_to_none():
    sandbox.set_active(None)
    assert sandbox.get_active() is None


def test_active_sandbox_registry_roundtrip(tmp_path: Path):
    box = sandbox.Sandbox(tmp_path)
    sandbox.set_active(box)
    try:
        assert sandbox.get_active() is box
    finally:
        sandbox.set_active(None)  # don't leak state into other tests


def test_to_workspace_path_rewrites_paths_under_target(tmp_path: Path):
    box = sandbox.Sandbox(tmp_path)
    nested = str(tmp_path / "src" / "app.py")

    assert sandbox.to_workspace_path(box, str(tmp_path)) == "/workspace"
    assert sandbox.to_workspace_path(box, nested) == "/workspace/src/app.py"


def test_to_workspace_path_leaves_unrelated_args_unchanged(tmp_path: Path):
    box = sandbox.Sandbox(tmp_path)

    assert sandbox.to_workspace_path(box, "--json") == "--json"
    assert sandbox.to_workspace_path(box, "https://example.test") == "https://example.test"


def test_to_workspace_path_noop_for_live_target_sandbox():
    box = sandbox.Sandbox(None)  # live-target scan, nothing mounted at /workspace

    assert sandbox.to_workspace_path(box, "https://example.test") == "https://example.test"


def test_image_exists_false_when_docker_missing(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    assert sandbox.image_exists() is False


def test_build_image_fails_cleanly_without_docker(monkeypatch):
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)

    ok, message = sandbox.build_image()

    assert ok is False
    assert "Docker" in message
