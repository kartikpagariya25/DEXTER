from __future__ import annotations

import re
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

GITHUB_REPO_RE = re.compile(r"^(?:https?://)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")

# Tried in order — covers the overwhelming majority of repos without ever
# needing GitHub's REST API (which unauthenticated clients rate-limit to
# 60 requests/hour, an easy limit to hit and a bad thing to depend on for
# something as basic as "which branch is default").
CANDIDATE_BRANCHES = ("main", "master")


def is_github_repo_url(target: str) -> bool:
    return GITHUB_REPO_RE.match(target.strip()) is not None


def fetch_github_repo(target: str, on_step=None) -> str:
    """Downloads a public GitHub repo's current source tree to a local temp
    directory via GitHub's own archive endpoint and returns that path.
    No git history, no API calls, no new dependency — just stdlib
    urllib + zipfile. Raises ValueError/RuntimeError on failure."""
    match = GITHUB_REPO_RE.match(target.strip())
    if not match:
        raise ValueError(f"Not a recognized GitHub repo URL: {target}")
    owner, repo = match.group(1), match.group(2)

    tmp_dir = Path(tempfile.mkdtemp(prefix="dexter_github_"))
    zip_path = tmp_dir / "repo.zip"
    last_error: Exception | None = None

    for branch in CANDIDATE_BRANCHES:
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        if on_step:
            on_step(f"fetching {owner}/{repo}@{branch}")
        try:
            req = urllib.request.Request(zip_url, headers={"User-Agent": "dexter-cli"})
            with urllib.request.urlopen(req, timeout=60) as response:
                zip_path.write_bytes(response.read())
            break
        except urllib.error.HTTPError as exc:
            last_error = exc
            continue
    else:
        raise RuntimeError(f"Could not fetch {owner}/{repo} — tried branches {CANDIDATE_BRANCHES}. Last error: {last_error}")

    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(tmp_dir)
    zip_path.unlink()

    extracted = [p for p in tmp_dir.iterdir() if p.is_dir()]
    if not extracted:
        raise RuntimeError(f"Downloaded archive for {owner}/{repo} but found no extracted directory.")
    return str(extracted[0])
