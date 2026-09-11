# syntax=docker/dockerfile:1
#
# Dexter sandbox image
#
# This is NOT a full Kali install ("kali-linux-everything" is 350-600+ tools
# and several GB). Like Strix, we use kali-rolling only as a convenient base
# OS with good apt package availability, then install a small, curated set
# of tools ourselves. Every tool below was explicitly chosen for a stage of
# Dexter's SAVR loop -- nothing is here "because Kali has it".
#
# Build:  dexter sandbox build                 (fast path, no browser)
#         dexter sandbox build --with-browser  (adds Chromium + agent-browser)
# Run:    handled by dexter/sandbox.py, not manually.
#
# SPEED NOTES (why this build used to take 30-40 minutes and now doesn't):
#   1. Chromium is ~25-30 minutes of that on a slow/rolling Kali mirror, and
#      NO tool adapter in Dexter uses it yet (it's there for future
#      browser-driven DAST/verification work). It is now opt-in via
#      --build-arg WITH_BROWSER=true, off by default.
#   2. httpx/katana/ffuf are pre-built binaries from GitHub Releases, not
#      `go install`-ed from source (that pulled 300+ transitive packages —
#      see git history if curious why this changed).
#   3. --mount=type=cache on apt/pip/npm layers means that editing this
#      Dockerfile later (e.g. adding one more tool) does NOT re-download
#      everything from scratch on the next build — only genuinely new
#      packages get fetched. Requires BuildKit, which `docker build` and
#      Docker Desktop both use by default already.
#   4. The base image is pinned to a specific digest (not `:latest`) so that
#      once it's pulled once, later builds use the local copy directly with
#      NO registry network call at all — this avoids Docker Desktop's WSL2
#      networking layer occasionally failing the "is latest still current?"
#      metadata check with a TLS handshake timeout, even when your actual
#      internet connection is fine (confirmed via `curl -v` to the registry
#      succeeding independently of Docker). Update the digest deliberately
#      if you ever want a newer Kali snapshot: `docker pull
#      kalilinux/kali-rolling:latest` then copy the sha256 it reports.

FROM kalilinux/kali-rolling@sha256:ed99295a386abde2fb31e01a441b7c2800d9bcf19a20028b77d642c3ef068363

ARG WITH_BROWSER=false
ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# Base OS packages + language runtimes.
#
# Kali is a rolling-release repo, so mirrors occasionally serve a
# half-synced package ("File has unexpected size"). That's transient, not a
# broken Dockerfile, so apt retries instead of failing the whole build on one
# bad fetch. The cache mount means even a failed/retried download or a later
# rebuild reuses whatever .deb files were already fetched.
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    set -eux; \
    PKGS="ca-certificates curl git unzip jq python3 python3-pip python3-venv nodejs npm"; \
    if [ "$WITH_BROWSER" = "true" ]; then PKGS="$PKGS chromium"; fi; \
    echo 'Acquire::Retries "5";' > /etc/apt/apt.conf.d/80-retries; \
    for i in 1 2 3; do \
        apt-get update && apt-get install -y --no-install-recommends $PKGS && break \
        || { echo "apt attempt $i failed, retrying..."; sleep 5; }; \
    done; \
    rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# SAST / secrets / dependency tools (Python)
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --break-system-packages semgrep bandit

# ---------------------------------------------------------------------------
# All of these — gitleaks, trivy, trufflehog, httpx, katana, ffuf — are
# pulled the same way: the latest pre-built Linux binary straight from each
# project's GitHub Releases page.
#
# Earlier this used each vendor's own "curl | sh" install script instead,
# but gitleaks's script URL turned out to be dead (404), and because
# `curl broken-url | sh` doesn't fail loudly (sh happily "runs" an empty
# script and exits 0), the build silently skipped installing gitleaks
# instead of erroring. This approach fails loudly instead: if a release
# asset can't be found, the build stops with a clear message.
#
# Asset filenames aren't consistent across projects (ProjectDiscovery/ffuf/
# trufflehog use "linux_amd64", gitleaks uses "linux_x64", trivy uses
# "Linux-64bit") — hence a pattern argument per tool below.
# ---------------------------------------------------------------------------
RUN set -eux; \
    install_gh_release_binary() { \
        repo="$1"; binary="$2"; pattern="$3"; \
        asset_url=$(curl -sSfL --retry 5 --retry-all-errors --retry-delay 3 \
                "https://api.github.com/repos/${repo}/releases/latest" \
            | jq -r '.assets[].browser_download_url' \
            | grep -Ei "$pattern" \
            | head -n1); \
        [ -n "$asset_url" ] || { echo "No release asset matching '${pattern}' found for ${repo}"; exit 1; }; \
        echo "Installing ${binary} from ${asset_url}"; \
        tmp=$(mktemp -d); \
        curl -sSfL --retry 5 --retry-all-errors --retry-delay 3 "$asset_url" -o "${tmp}/pkg"; \
        case "$asset_url" in \
            *.zip) unzip -q -o "${tmp}/pkg" -d "$tmp" ;; \
            *.tar.gz|*.tgz) tar -xzf "${tmp}/pkg" -C "$tmp" ;; \
        esac; \
        install -m 0755 "${tmp}/${binary}" "/usr/local/bin/${binary}"; \
        rm -rf "$tmp"; \
    }; \
    install_gh_release_binary "projectdiscovery/httpx" "httpx" 'linux_amd64\.(zip|tar\.gz)$'; \
    install_gh_release_binary "projectdiscovery/katana" "katana" 'linux_amd64\.(zip|tar\.gz)$'; \
    install_gh_release_binary "ffuf/ffuf" "ffuf" 'linux_amd64\.(zip|tar\.gz)$'; \
    install_gh_release_binary "trufflesecurity/trufflehog" "trufflehog" 'linux_amd64\.(zip|tar\.gz)$'; \
    install_gh_release_binary "gitleaks/gitleaks" "gitleaks" 'linux_x64\.tar\.gz$'; \
    install_gh_release_binary "aquasecurity/trivy" "trivy" 'linux-64bit\.tar\.gz$'

# ---------------------------------------------------------------------------
# JS/TS tooling — dependency vuln checks + JS-specific SAST signal
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/root/.npm \
    npm install -g retire eslint @microsoft/eslint-formatter-sarif @ast-grep/cli

# agent-browser: drives Chromium for future DAST/verification work. Only
# installed alongside Chromium itself (WITH_BROWSER=true) — installing it
# without a browser present would be dead weight. Verify the exact published
# package name/version before relying on this; pin a version once confirmed.
RUN --mount=type=cache,target=/root/.npm \
    if [ "$WITH_BROWSER" = "true" ]; then npm install -g agent-browser || true; fi

# ---------------------------------------------------------------------------
# Code-structure tooling used by the agentic Verify step (read code as a
# syntax tree instead of raw text, e.g. "find every call site of eval()").
#
# tree-sitter-languages (the package most tutorials reference) is
# unmaintained and its last release only supports Python <3.12 — it can't
# install on Kali's current Python 3.14. tree-sitter-language-pack is the
# actively maintained successor with the same purpose (bundled grammars for
# many languages) and current-Python support.
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --break-system-packages tree-sitter tree-sitter-language-pack

# ---------------------------------------------------------------------------
# Auth/JWT testing
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --break-system-packages pycryptodomex requests \
    && git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
    && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
    && chmod +x /usr/local/bin/jwt_tool

# ---------------------------------------------------------------------------
# Non-root execution: tools run as an unprivileged user inside the sandbox.
# The target is bind-mounted read-only at /workspace by dexter/sandbox.py;
# a separate writable /output volume is where reports get written.
# ---------------------------------------------------------------------------
RUN useradd -m -u 1000 dexter
USER dexter
WORKDIR /workspace

CMD ["/bin/bash"]