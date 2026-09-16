from __future__ import annotations

import sys
import threading
import time

FRAMES = "|/-\\"


def _is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


class Spinner:
    """Animated in-place progress indicator for a blocking call. No-op when
    stdout isn't a real terminal (CI, redirected output, pytest capture) —
    never interferes with piped/scripted usage."""

    def __init__(self, label: str):
        self.label = label
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _spin(self) -> None:
        start = time.time()
        frame_index = 0
        while not self._stop.is_set():
            elapsed = time.time() - start
            frame = FRAMES[frame_index % len(FRAMES)]
            sys.stdout.write(f"\r   {frame} {self.label} ({elapsed:.0f}s)")
            sys.stdout.flush()
            frame_index += 1
            self._stop.wait(0.15)
        clear_width = len(self.label) + 20
        sys.stdout.write("\r" + " " * clear_width + "\r")
        sys.stdout.flush()

    def __enter__(self) -> "Spinner":
        if _is_tty():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
