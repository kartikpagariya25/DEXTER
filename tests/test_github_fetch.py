from pathlib import Path

import pytest

from dexter import github_fetch


def test_detects_various_github_url_forms():
    assert github_fetch.is_github_repo_url("https://github.com/octocat/Hello-World") is True
    assert github_fetch.is_github_repo_url("github.com/octocat/Hello-World") is True
    assert github_fetch.is_github_repo_url("https://github.com/octocat/Hello-World.git") is True
    assert github_fetch.is_github_repo_url("https://github.com/octocat/Hello-World/") is True


def test_rejects_non_github_targets():
    assert github_fetch.is_github_repo_url("/local/path") is False
    assert github_fetch.is_github_repo_url("https://example.com") is False
    assert github_fetch.is_github_repo_url("https://gitlab.com/owner/repo") is False


def test_fetch_rejects_malformed_url():
    with pytest.raises(ValueError):
        github_fetch.fetch_github_repo("not-a-github-url")


def test_tries_main_then_master(monkeypatch, tmp_path: Path):
    attempted = []

    class FakeHTTPError(Exception):
        pass

    def fake_urlopen(req, timeout=60):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        attempted.append(url)
        if "main.zip" in url:
            import urllib.error
            raise urllib.error.HTTPError(url, 404, "not found", {}, None)
        import io
        import zipfile

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("repo-master/README.md", "hello")
        buf.seek(0)

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return buf.read()

        return FakeResponse()

    monkeypatch.setattr(github_fetch.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(github_fetch.tempfile, "mkdtemp", lambda prefix="": str(tmp_path))

    result = github_fetch.fetch_github_repo("https://github.com/owner/repo")

    assert any("main.zip" in u for u in attempted)
    assert any("master.zip" in u for u in attempted)
    assert Path(result).name == "repo-master"
    assert (Path(result) / "README.md").exists()


def test_raises_when_both_branches_fail(monkeypatch, tmp_path: Path):
    import urllib.error

    def fake_urlopen(req, timeout=60):
        raise urllib.error.HTTPError("x", 404, "not found", {}, None)

    monkeypatch.setattr(github_fetch.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(github_fetch.tempfile, "mkdtemp", lambda prefix="": str(tmp_path))

    with pytest.raises(RuntimeError):
        github_fetch.fetch_github_repo("https://github.com/owner/does-not-exist")
