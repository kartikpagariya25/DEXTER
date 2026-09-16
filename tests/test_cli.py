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
    assert "verified" in output
    assert str(target) in output or target.name in output
    assert (tmp_path / ".dexter" / "runs" / "fixture" / "run.json").exists()


def test_ctrl_c_during_scan_exits_cleanly(tmp_path: Path, monkeypatch, capsys):
    # Regression test: a long-running live-target scan (nuclei etc. can take
    # several minutes) interrupted with Ctrl+C used to propagate a raw
    # KeyboardInterrupt traceback instead of exiting cleanly.
    def raise_interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr("dexter.cli.run_savr", raise_interrupt)
    monkeypatch.setenv("DEXTER_HOME", str(tmp_path / ".dexter"))

    exit_code = main(["-n", "--target", str(tmp_path), "--run-name", "interrupted"])

    assert exit_code == 130
    assert "interrupted" in capsys.readouterr().out.lower()
    assert not (tmp_path / ".dexter" / "runs" / "interrupted").exists()
