"""Per-run Docker sandbox for tool execution.

Design goal (matching Strix's model, adapted to Dexter's architecture):
Dexter's LLM never gets raw shell access to the sandbox — that stays
Strix's approach, not ours (see DESIGN.md "Not Copying From Strix"). What
we DO copy is the *isolation* idea: instead of running nmap/gitleaks/etc.
directly on the host, each scan run gets its own disposable container
(built from containers/Dockerfile), tool adapters in tools.py execute
inside it via `docker exec`, and the container is torn down when the run
finishes. This also fixes the Windows PATH/tool-install friction we hit
earlier — the sandbox always has every tool, regardless of host OS.

Sandbox mode is OPT-IN (DEXTER_SANDBOX=1). With it off, tools.py falls
back to running binaries directly on the host, exactly as it does today —
so nothing here changes behavior for anyone who hasn't turned it on.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

IMAGE_NAME = "dexter-sandbox:latest"
CONTAINER_PREFIX = "dexter-run-"
DOCKERFILE_DIR = Path(__file__).resolve().parent.parent.parent / "containers"


def sandbox_enabled() -> bool:
    return os.environ.get("DEXTER_SANDBOX", "").strip() == "1"


def docker_available() -> bool:
    return shutil.which("docker") is not None


def image_exists(image: str = IMAGE_NAME) -> bool:
    if not docker_available():
        return False
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True, text=True, timeout=15,
    )
    return result.returncode == 0


def build_image(image: str = IMAGE_NAME, dockerfile_dir: Path = DOCKERFILE_DIR, on_line=None, with_browser: bool = False) -> tuple[bool, str]:
    """Build the sandbox image. Fast by default (~5-10 min): Chromium and
    agent-browser are skipped unless with_browser=True, since no tool
    adapter uses them yet and Chromium alone can take 20-30 minutes on a
    slow/rolling Kali mirror.

    Streams output line-by-line via on_line(str) as the build progresses
    (docker build produces no output at all until a step finishes, so it can
    look "stuck" for a minute or two on heavy steps — that's normal, not a
    hang)."""
    if not docker_available():
        return False, "Docker is not installed or not on PATH."
    dockerfile = dockerfile_dir / "Dockerfile"
    if not dockerfile.exists():
        return False, f"No Dockerfile at {dockerfile}"
    cmd = ["docker", "build", "-t", image, "-f", str(dockerfile)]
    if with_browser:
        cmd += ["--build-arg", "WITH_BROWSER=true"]
    cmd.append(str(dockerfile_dir))
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, encoding="utf-8", errors="replace", bufsize=1,
    )
    lines: list[str] = []
    assert process.stdout is not None
    for line in process.stdout:
        lines.append(line)
        if on_line:
            on_line(line.rstrip("\n"))
    process.wait(timeout=1800)
    return process.returncode == 0, "".join(lines[-200:])


class Sandbox:
    """One disposable container for the lifetime of a single scan run.

    Usage:
        with Sandbox(target_dir) as box:
            rc, out, err = box.exec(["gitleaks", "detect", "--source", "/workspace", ...])

    The target directory is bind-mounted read-only at /workspace inside the
    container — tools can read the code being scanned but cannot modify it.
    A scratch /output directory (writable) is provided for tools that need
    to write a report file before Dexter reads it back out.
    """

    def __init__(self, target_dir: str | Path | None, image: str = IMAGE_NAME):
        # target_dir is None for live-target (URL/host) scans that don't
        # need a local directory mounted in — the container is still used
        # for isolation and to collect tool output.
        self.target_dir = Path(target_dir).resolve() if target_dir else None
        self.image = image
        self.container_name = f"{CONTAINER_PREFIX}{uuid.uuid4().hex[:12]}"
        self._output_dir: Path | None = None
        self._empty_dir: Path | None = None
        self._started = False

    def __enter__(self) -> "Sandbox":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def start(self) -> None:
        if not docker_available():
            raise RuntimeError("Docker is not installed or not on PATH.")
        if not image_exists(self.image):
            raise RuntimeError(
                f"Sandbox image '{self.image}' not found. Build it first with "
                f"`dexter sandbox build` (uses containers/Dockerfile)."
            )
        import tempfile
        self._output_dir = Path(tempfile.mkdtemp(prefix="dexter_sandbox_out_"))
        if self.target_dir is None:
            self._empty_dir = Path(tempfile.mkdtemp(prefix="dexter_sandbox_empty_"))
        mount_source = self.target_dir or self._empty_dir
        cmd = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "--network", "bridge",          # live-target tools need egress; no host network access
            "--memory", "2g", "--cpus", "2",  # crude circuit breaker: cap resource use per run
            "-v", f"{mount_source}:/workspace:ro",
            "-v", f"{self._output_dir}:/output:rw",
            self.image,
            "sleep", "infinity",            # keep container alive; we `exec` into it per tool
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to start sandbox container: {result.stderr.strip()}")
        self._started = True

    def stop(self) -> None:
        if not self._started:
            return
        subprocess.run(["docker", "rm", "-f", self.container_name], capture_output=True, timeout=30)
        self._started = False
        if self._empty_dir is not None:
            shutil.rmtree(self._empty_dir, ignore_errors=True)

    @property
    def output_dir(self) -> Path:
        if self._output_dir is None:
            raise RuntimeError("Sandbox not started yet.")
        return self._output_dir

    def exec(self, cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
        """Run a command inside the running container. `cmd` should reference
        /workspace and/or /output, not host paths."""
        if not self._started:
            raise RuntimeError("Sandbox not started — use `with Sandbox(...) as box:`.")
        full_cmd = ["docker", "exec", self.container_name, *cmd]
        try:
            result = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -2, "", "timed out"

    def read_output_file(self, relative_name: str) -> str | None:
        path = self.output_dir / relative_name
        if not path.exists():
            return None
        return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Active-sandbox registry
#
# loop.py opens one Sandbox per local-directory target at the start of a
# scan and registers it here; tools.py adapters check get_active() (via the
# shared _run()/_report_path() helpers) and transparently execute inside the
# container instead of on the host when one is registered. This keeps every
# existing and new tool adapter sandbox-aware without each one needing to
# know about Docker directly.
# ---------------------------------------------------------------------------
_active: Sandbox | None = None


def set_active(box: Sandbox | None) -> None:
    global _active
    _active = box


def get_active() -> Sandbox | None:
    return _active


def to_workspace_path(box: Sandbox, host_path: str) -> str:
    """Rewrite a host path argument to its in-container equivalent, if it
    falls under this sandbox's mounted target directory. Anything else
    (flags, URLs, unrelated strings) is returned unchanged."""
    if box.target_dir is None:
        return host_path
    target_str = str(box.target_dir)
    if host_path == target_str:
        return "/workspace"
    if host_path.startswith(target_str + os.sep):
        return "/workspace" + host_path[len(target_str):].replace(os.sep, "/")
    return host_path