from pathlib import Path

from dexter.scanner import scan_source


def test_dotenv_files_are_scanned(tmp_path: Path):
    # Regression test: pathlib treats a file named ".env" as having an empty
    # suffix, so the old extension-based filter silently skipped it entirely.
    (tmp_path / ".env").write_text("JWT_SECRET=supersecretkey123\n", encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "Hard-coded secret" for f in findings)


def test_unquoted_secret_values_are_caught(tmp_path: Path):
    # Regression test: the old regex required quotes around the value, so
    # KEY=value (the normal .env / shell-export style) was never matched.
    (tmp_path / "config.env").write_text("DB_PASSWORD=hunter2mailji\n", encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "Hard-coded secret" for f in findings)


def test_env_read_is_not_a_false_positive(tmp_path: Path):
    # Regression test: found on a real scan of MailJi. The previous
    # unquoted-value secret regex flagged `SECRET = os.getenv(...)` as a
    # hardcoded secret — it's the opposite, reading from environment is the
    # correct pattern. The unquoted branch was matching any 6+ character
    # expression before a quote/space, including function calls.
    (tmp_path / "main.py").write_text('CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")\n', encoding="utf-8")

    findings = scan_source(tmp_path)

    assert not any(f.title == "Hard-coded secret" for f in findings)


def test_dict_access_is_not_a_false_positive(tmp_path: Path):
    # Same root cause, different shape: also found on MailJi.
    (tmp_path / "gmail.py").write_text('            pageToken=result["nextPageToken"]\n', encoding="utf-8")

    findings = scan_source(tmp_path)

    assert not any(f.title == "Hard-coded secret" for f in findings)


def test_real_secret_in_source_is_still_caught(tmp_path: Path):
    # Make sure fixing the false positives above didn't also break detection
    # of an actual quoted hardcoded secret in regular source code.
    (tmp_path / "main.py").write_text('GOOGLE_CLIENT_SECRET="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"\n', encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "Hard-coded secret" for f in findings)


def test_fastapi_cors_regex_pattern(tmp_path: Path):
    # Found on a real scan of MailJi: allow_origin_regex=r"https://.*" is a
    # FastAPI/Starlette CORS misconfiguration the original JS-oriented CORS
    # rule didn't recognize at all.
    (tmp_path / "main.py").write_text('    allow_origin_regex=r"https://.*",\n', encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "CORS wildcard / reflected origin" for f in findings)


def test_hardcoded_jwt_secret_rule(tmp_path: Path):
    (tmp_path / "auth.js").write_text("jwt.sign({id: user.id}, 'hardcoded_jwt_secret_value')\n", encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "Hardcoded JWT signing secret" for f in findings)


def test_cors_wildcard_rule(tmp_path: Path):
    (tmp_path / "server.js").write_text("app.use(cors({ origin: '*' }));\n", encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "CORS wildcard / reflected origin" for f in findings)


def test_dangerously_set_inner_html_rule(tmp_path: Path):
    (tmp_path / "Preview.jsx").write_text("<div dangerouslySetInnerHTML={{__html: content}} />\n", encoding="utf-8")

    findings = scan_source(tmp_path)

    assert any(f.title == "Potential XSS via unescaped HTML rendering" for f in findings)


def test_broken_symlink_inside_ignored_dir_does_not_crash(tmp_path: Path):
    # Regression test: a Linux-style venv contains a "lib64 -> lib" symlink.
    # On Windows this is unreadable (WinError 1920: "The file cannot be
    # accessed by the system"). The old code called path.is_file() (which
    # stats the path and raises) BEFORE checking the venv/ ignore list, so
    # scanning any project with a checked-in Linux venv crashed the whole
    # scan on Windows. The ignore-list/extension check must run first, and
    # is_file() must be guarded against OSError as a second line of defense.
    venv_lib = tmp_path / "venv" / "lib"
    venv_lib.mkdir(parents=True)
    broken_link = tmp_path / "venv" / "lib64"
    try:
        broken_link.symlink_to("/nonexistent-target")
    except OSError:
        pytest_skip_reason = "symlinks not supported/permitted in this environment"
        import pytest
        pytest.skip(pytest_skip_reason)

    (tmp_path / "app.py").write_text("password = 'hunter2mailji'\n", encoding="utf-8")

    findings = scan_source(tmp_path)  # must not raise

    assert any(f.title == "Hard-coded secret" for f in findings)
    assert not any("venv" in (f.file or "") for f in findings)