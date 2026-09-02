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
