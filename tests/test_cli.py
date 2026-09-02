from pathlib import Path

from dexter.cli import main


def test_local_scan_persists_finding(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setattr("dexter.loop.run_adapters", lambda target, on_tool=None: [])
    target = tmp_path / "app.py"
    target.write_text('password = "exposed-value-not-a-placeholder"\n', encoding="utf-8")
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path / ".dexter"))

    assert main(["-n", "--target", str(tmp_path), "--run-name", "fixture"]) == 1
    output = capsys.readouterr().out
    assert "Hard-coded secret" in output
    assert (tmp_path / ".dexter" / "runs" / "fixture" / "run.json").exists()
