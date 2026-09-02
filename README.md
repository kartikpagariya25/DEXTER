```
 ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗
 ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗
 ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝
 ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗
 ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║
 ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

        local-first, agentic application security assessment CLI
```

<div align="center">

![version](https://img.shields.io/badge/version-0.8.0-red?style=flat-square)
![python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square)
![tests](https://img.shields.io/badge/tests-43%20passing-brightgreen?style=flat-square)
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
│ 9 tools  │───▶│ base     │───▶│ real agent   │───▶│ instruction- │
│ + rules  │    │confidence│    │ reads code,  │    │ aware        │
│          │    │ per rule │    │ checks       │    │ confidence   │
│          │    │          │    │ entropy,     │    │ boost        │
│          │    │          │    │ greps repo   │    │              │
└──────────┘    └──────────┘    └──────────────┘    └──────────────┘
```

The **Verify** stage isn't a lookup table — it's a real tool-calling agent (ReAct pattern) that investigates ambiguous findings before deciding, the same way an agentic coding assistant investigates a bug before fixing it. It reads surrounding code, computes the entropy of a suspected secret, and searches the codebase for related usage — then gives a plain-English verdict, not just a severity label.

---

## Quickstart

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -e ".[dev]"

dexter --target ./your-project -n --instruction "prioritize secrets and access control"
wakeupdexter                     # interactive command center
```

Full setup, tool installation links, and every environment variable are in [Usage](#usage--commands) below.

---

## Table of Contents

- [Architecture](#architecture)
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
  + 9 ext tools    per finding  loop (tools:     aware boost      (technical or
  (file + live-                 read_lines,      + circuit        human-language)
  target, auth-                 entropy, grep)   breaker
  gated)                        + offline
                                 fallback
```

Both entry points — the one-shot `dexter` command (CI-friendly, non-zero exit on findings) and the interactive `wakeupdexter` dashboard — call the exact same `run_savr()` engine, matching the "loop logic is never duplicated across interfaces" principle from the original project synopsis.

---

## Project Status

### Core engine
- [x] SAVR loop (Scan → Analyze → Verify → Refine → Report) as a real, shared engine
- [x] Circuit breaker on the Refine stage (bounded iterations, converges instead of looping forever)
- [x] Confidence + verification fields on every finding (not just severity)
- [x] Shared engine used identically by `dexter` (CLI) and `wakeupdexter` (REPL)
- [x] Zero external Python runtime dependencies (pure stdlib `urllib`, `subprocess`, `xml.etree`)

### Agentic verification (real ReAct loop, not a fixed pipeline)
- [x] Tool-calling support in the LLM provider layer (OpenAI-style `tools` / `tool_calls`)
- [x] Verify-stage agent with three safe, read-only tools: `read_lines`, `shannon_entropy`, `grep_codebase`
- [x] Circuit breaker on the tool-calling loop (max iterations, tested against a runaway-model scenario)
- [x] Deterministic offline fallback when no LLM is reachable — Dexter still fully functions with zero API keys
- [x] Plain-English reasoning attached to every agentically-verified finding
- [ ] Analyze stage made agentic (cross-tool deduplication/correlation currently has no logic yet — findings from different tools on the same issue are not merged)
- [ ] Refine stage made agentic (currently keyword-matching against `--instruction`, not model-driven)
- [ ] Multi-agent coordinator + specialist subagents (Strix-style) — current agent scope is the Verify stage only, not a full coordinator spawning subagents per SAVR stage

### Local static analysis rules
- [x] Hard-coded secrets (quoted **and** unquoted `KEY=value` style — the unquoted case was a real bug, fixed)
- [x] `.env` / `.env.local` file scanning (pathlib treats these as having no extension by default — fixed)
- [x] Hardcoded JWT signing secrets
- [x] CORS wildcard / reflected-origin misconfiguration
- [x] React `dangerouslySetInnerHTML` (XSS risk)
- [x] Dynamic command execution (`eval`, `exec`, `child_process.exec`)
- [x] Debug mode enabled, TLS verification disabled, cleartext HTTP targets
- [x] OpenAPI contract gaps (undocumented/unauthenticated operations)

### Integrated external tools
- [x] **Semgrep** — SAST, many languages
- [x] **Bandit** — Python-specific SAST
- [x] **Gitleaks** — entropy-based secret scanning
- [x] **Trivy** — dependency CVE scanning
- [x] **Nmap** — port/service recon *(authorization-gated)*
- [x] **Nuclei** — template-based DAST *(authorization-gated)*
- [x] **Nikto** — web server misconfiguration scanning *(authorization-gated)*
- [x] **OWASP ZAP** — spider + passive scan by default, active scan opt-in *(authorization-gated, connects to an externally-run daemon)*
- [x] **ffuf** — content/path discovery with a bundled wordlist *(authorization-gated)*
- [x] **sqlmap** — real SQL injection confirmation, kept structurally outside the automatic scan path; only reachable via an explicit `dexter exploit` command with a named parameter and a typed confirmation
- [ ] **Metasploit** — deliberately not auto-wired; no generic "just run it" invocation exists for an exploit framework the way it does for the tools above. A resource-script passthrough (you supply the `.rc` file, Dexter just executes and captures output) is a scoped, honest way to add this later
- [ ] OSV-Scanner, Checkov, Grype, Gobuster, Wapiti, WhatWeb, OpenVAS — evaluated, mostly overlap with tools already integrated, not built

### Safety & authorization
- [x] Explicit authorization list (`dexter authorize <target>`) required before any live-target tool runs
- [x] Active-exploitation tools (sqlmap) structurally separated from the automatic scan registry — enforced by a unit test, not just convention
- [x] Confirmation prompt before any exploit-tier action in the interactive dashboard

### Reliability & LLM infrastructure
- [x] Multi-key provider pool with automatic rotation and cooldown persistence across sessions
- [x] Local model fallback tier (Ollama / llama.cpp — anything OpenAI-compatible) when all pooled keys are exhausted
- [x] `.env`-file based key management (`~/.dexter/.env`) instead of re-typing keys per session
- [x] Human-language report generation (`--format human`) alongside technical Markdown/JSON

### Developer experience
- [x] `dexter tools` — live installed/missing status for every integrated tool
- [x] Interactive `wakeupdexter` REPL with `/tool <target>` slash commands per adapter
- [x] Live per-stage and per-tool progress output during a scan (not a silent wait)
- [x] 43 automated tests, all isolated from external network/tool availability for fast, deterministic CI runs

### Not yet built
- [ ] Docker sandboxing for tool execution — every tool currently runs via a direct host subprocess, not a container. Stated as a first-class architectural constraint in the original project synopsis; genuinely outstanding
- [ ] Formal four-rung verifier ladder as a named, distinct structure (current Verify stage covers the same intent — deterministic check → agentic investigation → offline fallback — but isn't formalized into four explicit named rungs)
- [ ] Cross-tool finding correlation/deduplication (Semgrep and a local rule flagging the same line currently show up as two findings, not one merged one)
- [ ] Historical run diffing ("+2 high severity since last scan")
- [ ] Web dashboard — exists on the `backup-web-platform` branch (FastAPI + Celery + Postgres + React), shelved in favor of the CLI-first direction, not deleted

---

## Usage & Commands

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
wakeupdexter
```

**Inside `wakeupdexter`:**

```
scan <path> [instructions]                     full SAVR loop — local rules + every installed tool
/semgrep, /bandit, /gitleaks, /trivy <path>    run one tool directly
/nmap, /nuclei, /nikto, /zap, /ffuf <target>   run one live-target tool (needs authorize first)
exploit sqlmap <url> --param <name>            explicit exploitation step, asks for confirmation
authorize <target>                             allow a live target for gated tools
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

---

## Integrated Tools

| Tool | Type | Gate | Status |
|---|---|---|---|
| Semgrep | SAST | none | ✅ Live-tested |
| Bandit | Python SAST | none | ✅ Live-tested |
| Gitleaks | Secrets | none | ✅ Live-tested |
| Trivy | Dependency CVEs | none | ✅ Live-tested |
| Nmap | Recon | authorization | ✅ Live-tested |
| Nuclei | DAST | authorization | ✅ Built |
| Nikto | Web misconfig | authorization | ✅ Built (Perl-based, needs Strawberry Perl on Windows) |
| OWASP ZAP | DAST | authorization + running daemon | ✅ Live-tested (passive mode) |
| ffuf | Content discovery | authorization | ✅ Live-tested |
| sqlmap | Exploitation | authorization + explicit `exploit` command | ✅ Live-tested against a real injectable endpoint |
| Metasploit | Exploitation | — | ❌ Not auto-wired, by design |

---

## Authorization & Safety Model

Dexter treats "authorized targets only" as enforced behavior, not a suggestion:

- Live-target tools (Nmap, Nuclei, Nikto, ZAP, ffuf) refuse to run against anything not explicitly added via `dexter authorize <target>`.
- Exploitation-tier tools (sqlmap) are kept **structurally outside** the automatic scan registry — a dedicated test asserts this at the code level, so it can't silently regress.
- Exploit-tier actions require an explicit, separate command and a typed confirmation — never triggered by a normal `scan`.
- Metasploit has no automatic invocation at all, because there is no safe generic "just run it" behavior for an exploit framework the way there is for a scanner.

---

## Repository Layout

```
src/dexter/
├── cli.py              one-shot CLI entry point
├── dashboard.py         wakeupdexter interactive REPL
├── loop.py               the SAVR loop itself
├── agentic_verify.py     ReAct tool-calling verification agent
├── tools.py              external tool adapters + registry
├── scanner.py            local static-analysis rules
├── provider_pool.py     LLM key rotation + tool-calling support
├── authorization.py      authorized-target list
├── report.py             human-language report generation
├── env_file.py           ~/.dexter/.env loader
├── models.py / storage.py
└── wordlists/common.txt  bundled ffuf content-discovery wordlist
tests/                    43 tests, isolated from network/tool availability
```

---

## Roadmap

- [ ] Docker sandbox isolation for tool execution
- [ ] Cross-tool finding correlation & deduplication
- [ ] Agentic Analyze and Refine stages
- [ ] Multi-agent coordinator spawning per-stage subagents
- [ ] Historical run diffing across scans
- [ ] Metasploit resource-script passthrough
- [ ] Revisit the web dashboard (currently on `backup-web-platform`)

---

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
