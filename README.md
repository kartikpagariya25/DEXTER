# Dexter CLI

Dexter is a local-first application security assessment CLI. Every scan runs through the SAVR loop — Scan, Analyze, Verify, Refine — combining local rule checks with real external security tools, so findings come with a confidence score and a verification status, not just a severity label.

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

No external Python dependencies. External security tools (below) are optional — Dexter detects what's installed and skips the rest with no error.

## Setting up API keys properly

Don't type keys into every shell session. Create `~/.dexter/.env` (Windows: `%USERPROFILE%\.dexter\.env`) — Dexter loads it automatically on startup:

```
DEXTER_LLM_KEYS=key-one,key-two,key-three
```

- `DEXTER_LLM_KEYS` — comma-separated pool. If a key hits a 429, it's cooled down for `DEXTER_LLM_COOLDOWN_SECONDS` (default 5 hours) and Dexter rotates to the next key automatically. Cooldown state persists in `~/.dexter/key_state.json`.
- `GROQ_API_KEY` / `LLM_API_KEY` — single-key alias if you don't need a pool.
- `DEXTER_LLM_BASE_URL` — defaults to Groq's OpenAI-compatible endpoint. Point it at any other OpenAI-compatible provider (e.g. Ollama's hosted API) to pool keys from a different provider entirely.
- `DEXTER_LLM_LOCAL_URL` / `DEXTER_LLM_LOCAL_MODEL` — if every pooled key is cooling down, Dexter tries local Ollama (default `http://localhost:11434/v1`) before falling back to a rules-only summary.

Environment variables set in your shell always override the `.env` file. Check status any time:

```bash
dexter auth
```

## External security tools (optional, auto-detected)

```bash
dexter tools
```

Shows what's installed. Nothing here is required — Dexter's built-in rules always run regardless.

| Tool | Install | Covers |
|---|---|---|
| Semgrep | `pip install semgrep` | SAST, many languages |
| Bandit | `pip install bandit` | Python-specific SAST |
| Gitleaks | https://github.com/gitleaks/gitleaks/releases | Secrets, entropy-based |
| Trivy | https://github.com/aquasecurity/trivy/releases | Dependency CVEs (needs a lockfile, e.g. `package-lock.json`) |
| Nmap | https://nmap.org/download.html | Port/service recon — **requires authorization**, see below |
| Nuclei | https://github.com/projectdiscovery/nuclei/releases | Live URL scanning — **requires authorization**, see below |
| Nikto | https://github.com/sullo/nikto | Live URL scanning — **requires authorization**, see below (Perl-based; needs Strawberry Perl on Windows) |
| OWASP ZAP | https://www.zaproxy.org/download/ | Live URL DAST — **requires authorization + a running ZAP daemon**, see below |
| ffuf | https://github.com/ffuf/ffuf/releases | Content discovery (hidden paths/files) — **requires authorization**, bundled wordlist |

Trivy downloads a ~110MB vulnerability database on first use — needs internet, only happens once.

## OWASP ZAP setup (different from the other tools)

Every other tool here is a one-shot CLI Dexter runs and reads the output of. ZAP isn't — it's a long-running daemon with a REST API, and **Dexter connects to it rather than launching it**. Start ZAP yourself before scanning:

```bash
# Standalone (needs Java 17+):
zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# Or Docker:
docker run -u zap -p 8080:8080 zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Then `dexter tools` will show `zap` as installed once the daemon is reachable at `http://localhost:8080` (override with `DEXTER_ZAP_URL`). If you set an API key on the daemon, set `DEXTER_ZAP_API_KEY` to match.

By default Dexter runs ZAP's spider + **passive** scan only (fast — checks headers, cookies, CSP, information disclosure). Full **active** scanning (real attack payloads, much slower, can take many minutes) is opt-in:

```bash
set DEXTER_ZAP_ACTIVE_SCAN=1
```

Like Nmap/Nuclei/Nikto, ZAP only runs against `dexter authorize`'d targets.

## Authorization for live-target tools

Nmap, Nuclei, Nikto, ZAP, and ffuf actively probe a running target. Dexter won't run them against a host or URL unless it's been explicitly authorized:

```bash
dexter authorize scanme.nmap.org
dexter authorize https://your-authorized-target.test
dexter authorize --list
dexter authorize --revoke <target>
```

Scanning an unauthorized target still runs (local checks + any file-based tools that apply), it just skips the live-target tools and tells you why.

## Tools evaluated but not integrated (yet, or by design)

Two internal research docs (Semgrep/Nmap/Nuclei/ZAP/etc. cross-platform tool studies) fed the current tool list. Rather than integrate everything named, here's the honest state:

- **sqlmap** — integrated, but deliberately **not** part of the normal `scan`/`run_adapters` path. A normal scan of an authorized target will never fire it. It's only reachable via the explicit `dexter exploit` command below, requires you to name the exact parameter (matches responsible manual sqlmap usage — no blind-fuzzing a whole target), and `wakeupdexter`'s `exploit` command asks for a typed `yes` confirmation before running.
- **Metasploit** — not wired as an auto-invoking adapter. Unlike the other tools, there's no sensible generic "just run it against a target" behavior — Metasploit requires picking a specific exploit module and payload before it does anything meaningful. Install and run it standalone (`msfconsole`) for now; a resource-script passthrough (you write the `.rc` file naming the exact module, Dexter just executes it and captures output) is a reasonable, well-scoped follow-up if wanted.

## Active exploitation (sqlmap)

```bash
dexter authorize http://your-authorized-target.test/page?id=1
dexter exploit sqlmap "http://your-authorized-target.test/page?id=1" --param id
```

In `wakeupdexter`:
```
exploit sqlmap <url> --param id
```
This asks for a typed `yes` before running — it is never triggered by a normal `scan`.
- **ffuf** — reasonable P1 addition (content discovery), needs a wordlist file which isn't bundled. Doable if wanted.
- **OSV-Scanner, Checkov, Grype, Gobuster, Wapiti, WhatWeb, OpenVAS** — P2 in both research docs; mostly overlap with what Trivy/Nuclei already cover. Not integrated; can be added individually if a specific gap shows up.

## Usage

```bash
dexter --target ./app --scan-mode standard
dexter -n -t ./app --instruction "Prioritize authentication and access control"
dexter --target-list ./targets.txt --run-name ci-scan
dexter report ci-scan --format human      # plain-language summary
dexter report ci-scan --format markdown --output report.md
dexter view ci-scan
dexter tools
dexter auth
dexter authorize <target>
wakeupdexter
```

## `wakeupdexter` — the interactive command center

```
scan <path> [instructions]              full SAVR loop: local rules + every installed tool
/semgrep, /bandit, /gitleaks, /trivy <path>   run one tool directly
/nmap, /nuclei, /nikto <host-or-url>    run one live-target tool (needs authorize first)
/tools                                  show which external tools are installed
authorize <target>                      allow a live URL target for Nuclei/Nikto
runs                                    list saved assessments
report [run] [human]                    print a report — add "human" for plain-language
view [run]                              open the local browser viewer
pool                                    show LLM provider/key pool status
```

Exit status is non-zero when findings are present, which makes `-n` suitable for CI. Only test systems you own or have explicit written permission to assess.

## The SAVR loop

1. **Scan** — local rule checks (secrets, JWT hardcoding, CORS wildcards, XSS patterns, dynamic execution, debug flags, TLS, naive SQLi, OpenAPI gaps) plus every installed external tool applicable to the target type.
2. **Analyze** — each finding starts with a confidence score: local rules set a base value per rule, external tools report their own.
3. **Verify** — deterministic facts are marked verified outright. Everything else runs through a real tool-calling verification agent: it can read surrounding code, compute the entropy of a suspected secret, and grep the codebase for related usage before deciding — the same tool-calling ("ReAct") pattern used by agentic coding tools, applied here to security verification. Its tools are deliberately read-only and local; it never invokes live-target or exploit tools on its own. If no LLM is configured, Dexter falls back to a deterministic placeholder-pattern heuristic so it still works fully offline. External tool findings are trusted at their own reported confidence level.
4. **Refine** — `--instruction` keywords give matching findings a one-time confidence boost, capped by a circuit breaker.

## Development

```bash
pytest
python -m compileall -q src
```
