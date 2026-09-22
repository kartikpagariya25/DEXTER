```
 ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗
 ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗
 ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝
 ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗
 ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
Loop Engineering based Agentic Vulnerability and Penetration testing
```

<div align="center">

![version](https://img.shields.io/badge/version-0.9.0-red?style=flat-square)
![python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)
![tests](https://img.shields.io/badge/tests-65%20passing-brightgreen?style=flat-square)
![platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-informational?style=flat-square)

**Scan → Analyze → Verify → Refine.**
Not a single-pass scanner — a closed loop that investigates its own findings before it trusts them.

</div>

---

## What is Dexter

Most vulnerability scanners work the same broken way: run a fixed set of checks, dump a static report, hand the mess to a human. High false-positive rates, no correlation between tools, no transparent path from "flagged" to "confirmed."

Dexter is different. Every scan runs through the **SAVR loop**:

```
   SCAN            ANALYZE          VERIFY              REFINE
┌──────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────────┐
│ 14 tools │───▶│ base     │───▶│ real agent   │───▶│ instruction- │
│ + rules  │    │confidence│    │ reads code,  │    │ aware        │
│          │    │ per rule │    │ checks       │    │ confidence   │
│          │    │          │    │ entropy,     │    │ boost        │
│          │    │          │    │ greps repo   │    │              │
└──────────┘    └──────────┘    └──────────────┘    └──────────────┘
```

The **Verify** stage isn't a lookup table — it's a real tool-calling agent (ReAct pattern) that investigates ambiguous findings before deciding, the same way an agentic coding assistant investigates a bug before fixing it. It reads surrounding code, computes the entropy of a suspected secret, and searches the codebase for related usage — then gives a plain-English verdict, not just a severity label.

Tool execution is **sandboxed when Docker is available**: every tool can run inside a disposable, per-scan container instead of directly on your host — see [Docker Sandbox](#docker-sandbox) below.

---

## Demo codebase

`demo/greenleaf-bank/` is a small, deliberately vulnerable codebase (not a real app — safe to scan repeatedly, offline, no authorization needed since it's local files only) covering every local rule and several tool categories: hardcoded JWT secret, CORS misconfiguration, SQL injection, dynamic command execution (JS + Python), TLS verification disabled, XSS, unquoted `.env` secrets, and an outdated npm dependency for Trivy.

```bash
dexter --target ./demo/greenleaf-bank -n --instruction "prioritize secrets and injection"
```

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e ".[dev]"

dexter --target ./your-project -n --instruction "prioritize secrets and access control"
wakeupdexter                     # interactive command center
```

**Recommended — build the sandbox once so tools don't need host installation:**

```bash
dexter sandbox build            # ~5-10 min, builds the Docker image
set DEXTER_SANDBOX=1            # Windows CMD (PowerShell: $env:DEXTER_SANDBOX="1")
dexter --target ./your-project -n
```

Full setup, tool installation links, and every environment variable are in [Usage](#usage--commands) below.

---

## Table of Contents

- [Architecture](#architecture)
- [Docker Sandbox](#docker-sandbox)
- [Project Status](#project-status)
- [Usage & Commands](#usage--commands)
- [LLM Provider Setup](#llm-provider-setup)
- [Integrated Tools](#integrated-tools)
- [Authorization & Safety Model](#authorization--safety-model)
- [Repository Layout](#repository-layout)
- [Roadmap](#roadmap)
- [Team](#team)

---

## Architecture

```
                     dexter (CLI)        wakeupdexter (interactive REPL)
                          │                        │
                          └────────────┬───────────┘
                                        ▼
                              dexter.loop.run_savr()
                     (single shared engine — no logic duplicated
                      between the CLI and the interactive dashboard)
                                        │
        ┌───────────────┬──────────────┼──────────────┬───────────────┐
        ▼               ▼              ▼               ▼               ▼
      SCAN           ANALYZE        VERIFY          REFINE          REPORT
  local rules      base conf.   agentic ReAct    instruction-     LLM summary
  + 14 ext tools   per finding  loop (tools:     aware boost      (technical or
  (file + live-                 read_lines,      + circuit        human-language)
  target, auth-                 entropy, grep)   breaker
  gated) — run                  + offline
  in a per-scan                 fallback
  Docker sandbox
  when available
```

Both entry points — the one-shot `dexter` command (CI-friendly, non-zero exit on findings) and the interactive `wakeupdexter` dashboard — call the exact same `run_savr()` engine, matching the "loop logic is never duplicated across interfaces" principle from the original project synopsis.

---

## Docker Sandbox

When `DEXTER_SANDBOX=1` is set, every containerized tool in the Scan stage runs inside a disposable, per-run Docker container instead of directly on your machine — the target directory is bind-mounted read-only at `/workspace`, and the container is destroyed the moment the scan finishes. This removes host-OS friction entirely (no per-platform tool installs, no PATH issues, no Windows-specific tool ports) and isolates whatever a scan tool does from your real environment.

### One-time setup

```bash
dexter sandbox build              # fast path — skips Chromium (~5-10 min)
dexter sandbox build --with-browser   # adds Chromium + agent-browser (~20-30 min extra; not used by any tool yet, only needed for future browser-driven checks)
dexter sandbox status             # check Docker + image status any time
```

### Using it

```bash
set DEXTER_SANDBOX=1              # Windows CMD
$env:DEXTER_SANDBOX="1"           # PowerShell
export DEXTER_SANDBOX=1           # Linux/macOS

dexter --target ./your-project -n
```

If Docker isn't available, Dexter prints a notice and transparently falls back to running tools on the host — `DEXTER_SANDBOX=1` is always safe to leave set.

### Important: reaching a locally-running app from inside the sandbox

Containers don't share the host's `localhost`. If you're scanning something running on your own machine (e.g. a Flask dev server on `http://localhost:5000`) with `DEXTER_SANDBOX=1`, use Docker Desktop's special DNS name instead:

```bash
dexter authorize http://host.docker.internal:5000
dexter --target http://host.docker.internal:5000 -n
```

(`localhost:5000` still works correctly for local-directory scans, and for URL scans when `DEXTER_SANDBOX` is unset.)

### What's inside the image

`containers/Dockerfile` — Kali-based, deliberately minimal (not `kali-linux-everything`): only tools Dexter actually wires up, pulled as pre-built binaries from each project's GitHub Releases where possible (faster and far more reliable in CI than compiling from source). See [Integrated Tools](#integrated-tools) for the full list and what's sandboxed vs. host-only today.

---

## Project Status

### Core engine
- [x] SAVR loop (Scan → Analyze → Verify → Refine → Report) as a real, shared engine
- [x] Circuit breaker on the Refine stage (bounded iterations, converges instead of looping forever)
- [x] Confidence + verification fields on every finding (not just severity)
- [x] Shared engine used identically by `dexter` (CLI) and `wakeupdexter` (REPL)
- [x] Zero external Python runtime dependencies (pure stdlib `urllib`, `subprocess`, `xml.etree`)
- [x] **Docker sandbox execution** (`DEXTER_SANDBOX=1`) — per-scan disposable container, host fallback when Docker is unavailable

### Agentic verification (real ReAct loop, not a fixed pipeline)
- [x] Tool-calling support in the LLM provider layer (OpenAI-style `tools` / `tool_calls`)
- [x] Verify-stage agent with three safe, read-only tools: `read_lines`, `shannon_entropy`, `grep_codebase`
- [x] Circuit breaker on the tool-calling loop (max iterations, tested against a runaway-model scenario)
- [x] Deterministic offline fallback when no LLM is reachable — Dexter still fully functions with zero API keys
- [x] Plain-English reasoning attached to every agentically-verified finding
- [x] Cross-tool finding correlation — findings at the same location with overlapping topic (e.g. a local rule and Semgrep both flagging the same secret) are merged, with confidence boosted by independent corroboration. Deliberately deterministic, not LLM-driven — this is a mechanical matching problem, and a rule-based implementation is faster, free, and can't hallucinate a merge that shouldn't happen
- [x] Refine stage made agentic — reasons across the *whole* finding set at once (cross-finding corroboration, instruction-aware judgment), unlike Verify which investigates one finding in isolation. No tool-calling needed here — one structured reasoning call, with hard safety clamps on confidence adjustments regardless of what the model outputs. Deterministic keyword-matching fallback preserved for fully offline use
- [ ] Multi-agent coordinator + specialist subagents (Strix-style) — Verify and Refine are both genuinely agentic now, but there's no formal `Coordinator` class dispatching between them; the SAVR loop itself plays that role as a fixed sequence

### Local static analysis rules
- [x] Hard-coded secrets (quoted **and** unquoted `KEY=value` style — the unquoted case was a real bug, fixed)
- [x] `.env` / `.env.local` file scanning (pathlib treats these as having no extension by default — fixed)
- [x] Hardcoded JWT signing secrets
- [x] CORS wildcard / reflected-origin misconfiguration
- [x] React `dangerouslySetInnerHTML` (XSS risk)
- [x] Dynamic command execution (`eval`, `exec`, `child_process.exec`)
- [x] Debug mode enabled, TLS verification disabled, cleartext HTTP targets
- [x] OpenAPI contract gaps (undocumented/unauthenticated operations)
- [x] Broken-symlink / junction safety (a Linux venv's `lib64 -> lib` symlink used to crash the whole scan on Windows with `WinError 1920` — the ignore-list check now runs before the filesystem `stat()` call that could raise, with a try/except as a second line of defense)

### Integrated external tools
14 tools total — see the [full table](#integrated-tools) for sandbox-vs-host status and gating.
- [x] **Semgrep**, **Bandit** — SAST
- [x] **Gitleaks**, **Trufflehog** — secret scanning (Trufflehog additionally verifies whether a matched credential is still live against its provider's API)
- [x] **Trivy** — dependency CVE scanning
- [x] **Retire.js**, **ESLint** (security ruleset), **ast-grep** — frontend/structural SAST
- [x] **httpx**, **katana** — recon / tech fingerprinting / crawling *(authorization-gated)*
- [x] **Nmap**, **Nuclei**, **Nikto**, **ffuf** — recon/DAST/content-discovery *(authorization-gated; host-installed only — not yet ported into the sandbox image, see [Roadmap](#roadmap))*
- [x] **OWASP ZAP** — spider + passive scan by default, active scan opt-in *(authorization-gated, connects to an externally-run daemon; host-only)*
- [x] **sqlmap** — real SQL injection confirmation, kept structurally outside the automatic scan path; only reachable via an explicit `dexter exploit` command with a named parameter
- [x] **jwt_tool** — JWT weakness testing, same exploit-gating pattern as sqlmap; takes the token directly rather than a target+param
- [ ] **Metasploit** — deliberately not auto-wired; no generic "just run it" invocation exists for an exploit framework the way it does for the tools above

### Safety & authorization
- [x] Explicit authorization list (`dexter authorize <target>`) required before any live-target tool runs
- [x] Active-exploitation tools (sqlmap, jwt_tool) structurally separated from the automatic scan registry — enforced by a unit test, not just convention
- [x] Confirmation prompt before any exploit-tier action in the interactive dashboard
- [x] `venv`/`node_modules`/`.git`/`site-packages` excluded from Semgrep and Bandit scans (previously flooded results with third-party library findings the user has no ability to fix)

### Reliability & LLM infrastructure
- [x] Multi-key provider pool with automatic rotation and cooldown persistence across sessions
- [x] Local model fallback tier (Ollama / llama.cpp — anything OpenAI-compatible) when all pooled keys are exhausted
- [x] `.env`-file based key management (`~/.dexter/.env`) instead of re-typing keys per session
- [x] Human-language report generation (`--format human`) alongside technical Markdown/JSON

### Developer experience
- [x] `dexter tools` — live installed/missing status for every integrated tool (checks inside the active sandbox container when `DEXTER_SANDBOX=1`, host PATH otherwise)
- [x] `dexter sandbox build` / `dexter sandbox status` — build/inspect the Docker image, with live streaming build output
- [x] Interactive `wakeupdexter` REPL with `/tool <target>` slash commands per adapter
- [x] Live per-stage and per-tool progress output during a scan (not a silent wait)
- [x] 65 automated tests, all isolated from external network/tool/Docker availability for fast, deterministic CI runs
- [x] Fixed: the `scan` command in `wakeupdexter` used to run every target through `pathlib.Path()`, which corrupts URLs on Windows (`https://example.com/` → `https:\example.com`) — a URL could be authorized correctly and still get reported "not authorized" on scan because the corrupted string no longer matched. URLs now pass through unchanged; only local paths get `Path()`-ified.

### Not yet built
- [ ] Full tool parity inside the sandbox — Nmap, Nuclei, Nikto, ffuf, ZAP, sqlmap, jwt_tool currently still run host-side even when `DEXTER_SANDBOX=1`; only the file-scanning tools + httpx/katana are containerized so far
- [ ] Formal four-rung verifier ladder as a named, distinct structure (current Verify stage covers the same intent — deterministic check → agentic investigation → offline fallback — but isn't formalized into four explicit named rungs)
- [x] Cross-tool finding correlation/deduplication (findings from different tools on the same line/topic are now merged, with confidence boosted by corroboration)
- [ ] Historical run diffing ("+2 high severity since last scan")
- [ ] Web dashboard — exists on the `backup-web-platform` branch (FastAPI + Celery + Postgres + React), shelved in favor of the CLI-first direction, not deleted
- [ ] Browser-driven verification (Chromium/agent-browser are installable in the sandbox via `--with-browser`, but no tool adapter uses them yet — needed for auth-flow/DOM-based-XSS checks that a static/HTTP-only tool can't see)

---

## Usage & Commands

You can scan a public GitHub repo directly by URL — Dexter downloads the current source tree via GitHub's own archive endpoint (no `git clone` needed, no API rate limits since it doesn't use the REST API) and scans it exactly like a local directory:

```bash
dexter --target https://github.com/owner/repo -n
```

Not full web scraping by design — it fetches a repo's source tree, which is a well-defined operation, not an open-ended crawler. If you need to scan a private repo or a specific branch, clone it locally and point Dexter at that path instead.

```bash
dexter --target ./app --scan-mode standard
dexter -n -t ./app --instruction "Prioritize authentication and access control"
dexter --target-list ./targets.txt --run-name ci-scan
dexter report ci-scan --format human
dexter report ci-scan --format markdown --output report.md
dexter view ci-scan
dexter tools
dexter auth
dexter authorize <target>
dexter exploit sqlmap "<url>" --param id
dexter exploit jwt_tool "<jwt>"
dexter sandbox build [--with-browser]
dexter sandbox status
wakeupdexter
```

**Inside `wakeupdexter`:**

```
scan <path-or-url> [instructions]              full SAVR loop — local rules + every installed tool
/semgrep, /bandit, /gitleaks, /trivy <path>    run one tool directly
/nmap, /nuclei, /nikto, /zap, /ffuf <target>   run one live-target tool (needs authorize first)
exploit sqlmap <url> --param <name>            explicit exploitation step, asks for confirmation
authorize <target>                             allow a live target for gated tools (URL or local path)
/tools                                         show installed/missing tool status
runs · report [run] [human] · view [run] · pool
```

Exit status is non-zero when findings are present — `-n` mode is CI-safe.

---

## LLM Provider Setup

Create `~/.dexter/.env` (Windows: `%USERPROFILE%\.dexter\.env`) so you never retype keys:

```
DEXTER_LLM_KEYS=key-one,key-two,key-three
```

| Variable | Purpose |
|---|---|
| `DEXTER_LLM_KEYS` | Comma-separated key pool. A 429 cools that key down and rotates to the next automatically. |
| `DEXTER_LLM_BASE_URL` | Any OpenAI-compatible endpoint — Groq (default), Ollama's hosted API, or your own. |
| `DEXTER_LLM_LOCAL_URL` | Fallback tier when every pooled key is cooling — point at local Ollama or a `llama.cpp` server. |
| `DEXTER_LLM_COOLDOWN_SECONDS` | Cooldown duration per key (default 5 hours). |

`dexter auth` shows live status of every key and the local fallback.

> **Never commit a real key.** If one ends up in `.env` inside a scanned project (rather than `~/.dexter/.env`), Dexter's own Gitleaks/Trufflehog adapters will (correctly) flag it — that's not a false positive, rotate it.

---

## Integrated Tools

| Tool | Type | Gate | Sandboxed? |
|---|---|---|---|
| Semgrep | SAST | none | Yes |
| Bandit | Python SAST | none | Yes |
| Gitleaks | Secrets | none | Yes |
| Trufflehog | Secrets (+ live-credential verification) | none | Yes |
| Trivy | Dependency CVEs | none | Yes |
| Retire.js | Frontend dependency CVEs | none | Yes |
| ESLint | JS/TS SAST (security ruleset only) | none | Yes |
| ast-grep | Structural pattern SAST | none | Yes |
| httpx | Recon / tech fingerprint | authorization | Yes |
| katana | Web crawler | authorization | Yes |
| ffuf | Content discovery | authorization | No — host-only |
| Nmap | Port/service recon | authorization | No — host-only |
| Nuclei | Template-based DAST | authorization | No — host-only |
| Nikto | Web misconfig | authorization | No — host-only (Perl-based, needs Strawberry Perl on Windows) |
| OWASP ZAP | DAST | authorization + running daemon | No — host-only |
| sqlmap | Exploitation | authorization + explicit `exploit` command | No — host-only |
| jwt_tool | JWT weakness testing | explicit `exploit` command | No — host-only |
| Metasploit | Exploitation | — | Not auto-wired, by design |
| Chromium / agent-browser | Browser automation | `--with-browser` build flag | Yes (installed, not yet used by any adapter) |

---

## Authorization & Safety Model

Dexter treats "authorized targets only" as enforced behavior, not a suggestion:

- Live-target tools (Nmap, Nuclei, Nikto, ZAP, ffuf, httpx, katana) refuse to run against anything not explicitly added via `dexter authorize <target>`.
- Exploitation-tier tools (sqlmap, jwt_tool) are kept **structurally outside** the automatic scan registry — a dedicated test asserts this at the code level, so it can't silently regress.
- Exploit-tier actions require an explicit, separate command — never triggered by a normal `scan`.
- Metasploit has no automatic invocation at all, because there is no safe generic "just run it" behavior for an exploit framework the way there is for a scanner.
- The Docker sandbox adds a further isolation layer: even an authorized scan's tools run inside a disposable container with the target mounted read-only, not directly against your host filesystem.

**Only test systems you own or have explicit written permission to assess** — this applies identically whether a scan runs sandboxed or on the host.

---

## Repository Layout

```
containers/
└── Dockerfile            sandbox image (Kali-based; semgrep, bandit, gitleaks,
                           trivy, trufflehog, httpx, katana, ffuf, retire, eslint,
                           ast-grep, tree-sitter, jwt_tool; Chromium optional)
src/dexter/
├── cli.py                one-shot CLI entry point
├── dashboard.py          wakeupdexter interactive REPL
├── loop.py               the SAVR loop itself; opens/tears down the sandbox per target
├── agentic_verify.py     ReAct tool-calling verification agent
├── tools.py              external tool adapters + registry (sandbox-aware)
├── sandbox.py            per-run Docker container lifecycle
├── scanner.py            local static-analysis rules
├── provider_pool.py      LLM key rotation + tool-calling support
├── authorization.py      authorized-target list
├── report.py             human-language report generation
├── env_file.py           ~/.dexter/.env loader
├── models.py / storage.py
└── wordlists/common.txt  bundled ffuf content-discovery wordlist
tests/                    65 tests, isolated from network/tool/Docker availability
```

---

## Roadmap

- [ ] Port Nmap, Nuclei, Nikto, ffuf, sqlmap, jwt_tool into the sandbox image for full tool parity in containerized mode
- [x] Cross-tool finding correlation & deduplication
- [ ] Agentic Analyze and Refine stages
- [ ] Multi-agent coordinator spawning per-stage subagents
- [ ] Historical run diffing across scans
- [ ] Browser-driven verification using the (already installable) Chromium/agent-browser sandbox tooling
- [ ] Metasploit resource-script passthrough
- [ ] Revisit the web dashboard (currently on `backup-web-platform`)

---

## LLM efficiency — the verify cache

Every agentic-Verify result is cached by finding fingerprint (title + file + evidence) in `~/.dexter/verify_cache.json`. Rescanning the same codebase reuses prior verifications instead of re-spending an LLM call — measured on the demo codebase, a first scan made 11 LLM calls; an immediate rescan of unchanged code made only 2 (Refine and Report still reason over the whole finding set each time; per-finding Verify calls came entirely from cache).

```bash
dexter cache status
dexter cache clear
```

## Live progress

Every blocking operation — an external tool subprocess, an LLM round-trip — shows an animated in-place spinner with elapsed time, so a multi-minute Nuclei scan or a slow LLM call never looks like a hang. Automatically disabled when output isn't a real terminal (CI, redirected output).

## Team

| Name | Role |
|---|---|
| Kartik R. Pagariya | — |
| Vikrant K. Kadam | — |
| Aditya U. Dengale | — |
| Pranali D. Yelavikar | — |
| Dr. Parikshit Mahalne | Project Guide |

**VIT — AI & Data Science, Final Year Project**

---

<div align="center">

*Only test systems you own or have explicit written permission to assess.*

</div>
