from __future__ import annotations

import os
import shlex
import shutil
import sys
import textwrap
from datetime import datetime
from pathlib import Path

from .authorization import authorize, is_authorized, list_authorized
from .env_file import load_env
from .loop import _verify, insight_summary, run_savr
from .models import Run
from .provider_pool import pool_status
from .report import generate_human_report
from .storage import list_runs, load_run, save_run, safe_run_id
from .tools import run_single_adapter, run_single_exploit, tool_status

load_env()


# ---------------------------------------------------------------------------
# Terminal setup — enables ANSI/VT100 + 24-bit color on Windows cmd/PowerShell.
# Without this, cmd.exe silently prints raw escape codes as garbage text.
# ---------------------------------------------------------------------------
def _enable_ansi_on_windows() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:
        pass


_enable_ansi_on_windows()


def _rgb(r: int, g: int, b: int) -> str:
    return f"\033[38;2;{r};{g};{b}m"


class Theme:
    red = "\033[38;5;196m"
    crimson = "\033[38;5;160m"
    ember = "\033[38;5;202m"
    dark_red = "\033[38;5;124m"
    maroon = "\033[38;5;88m"
    green = "\033[38;5;42m"
    white = "\033[97m"
    grey = "\033[38;5;250m"
    muted = "\033[38;5;245m"
    dim = "\033[38;5;238m"
    bold = "\033[1m"
    reset = "\033[0m"

    @staticmethod
    def sev(level: str) -> str:
        return {
            "critical": "\033[1;38;5;196m",
            "high": "\033[38;5;196m",
            "medium": "\033[38;5;208m",
            "low": "\033[38;5;178m",
        }.get(level, Theme.muted)


# Fiery left-to-right gradient stops: bright red -> ember -> dark red -> maroon -> smoldering black-red
_GRADIENT_STOPS = [
    (255, 64, 64),
    (255, 128, 40),
    (214, 48, 42),
    (150, 24, 24),
    (70, 12, 12),
]


def _gradient_color(t: float) -> str:
    t = max(0.0, min(1.0, t))
    seg = t * (len(_GRADIENT_STOPS) - 1)
    i = min(int(seg), len(_GRADIENT_STOPS) - 2)
    f = seg - i
    r0, g0, b0 = _GRADIENT_STOPS[i]
    r1, g1, b1 = _GRADIENT_STOPS[i + 1]
    r = int(r0 + (r1 - r0) * f)
    g = int(g0 + (g1 - g0) * f)
    b = int(b0 + (b1 - b0) * f)
    return _rgb(r, g, b)


BANNER_LINES = [
    r" ██████╗ ███████╗██╗  ██╗████████╗███████╗██████╗ ",
    r" ██╔══██╗██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗",
    r" ██║  ██║█████╗   ╚███╔╝    ██║   █████╗  ██████╔╝",
    r" ██║  ██║██╔══╝   ██╔██╗    ██║   ██╔══╝  ██╔══██╗",
    r" ██████╔╝███████╗██╔╝ ██╗   ██║   ███████╗██║  ██║",
    r" ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",
]

def _render_banner() -> None:
    width = max(len(line) for line in BANNER_LINES)
    for line in BANNER_LINES:
        out = []
        for x, ch in enumerate(line):
            if ch == " ":
                out.append(" ")
            else:
                out.append(f"{_gradient_color(x / width)}{ch}{Theme.reset}")
        print("".join(out))


def _enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "xterm") != "dumb"


def _clear() -> None:
    print("\033[2J\033[H", end="")


def _term_size() -> tuple[int, int]:
    try:
        size = shutil.get_terminal_size()
        return size.columns, size.lines
    except OSError:
        return 100, 30


def _width() -> int:
    cols, _ = _term_size()
    return max(60, min(cols - 2, 140))


def _strip_len(text: str) -> int:
    import re

    return len(re.sub(r"\033\[[0-9;]*m", "", text))


def _pad(text: str, width: int) -> str:
    visible = _strip_len(text)
    return text if visible >= width else text + " " * (width - visible)


def _rule(width: int, char: str = "─", color: str = "") -> str:
    c = color or Theme.dim
    return f"{c}{char * width}{Theme.reset}"


def _kv(label: str, value: str, label_color: str = "") -> str:
    color = label_color or Theme.green
    return f"{color}{Theme.bold}{label}:{Theme.reset} {value}"


def _wrap(text: str, width: int, indent: str = "") -> list[str]:
    wrapped: list[str] = []
    for para in text.splitlines() or [""]:
        if not para.strip():
            wrapped.append("")
            continue
        wrapped.extend(textwrap.wrap(para, width=width, initial_indent=indent, subsequent_indent=indent) or [""])
    return wrapped


def _bar(label: str, value: int, total: int, width: int = 16) -> str:
    filled = min(int(width * value / total) if total else 0, width)
    bar = f"{Theme.red}{'━' * filled}{Theme.dim}{'━' * (width - filled)}{Theme.reset}"
    return f"{bar} {Theme.white}{value:>2}{Theme.reset} {Theme.muted}{label}{Theme.reset}"


def _section(title: str, width: int) -> None:
    label = f" {title} "
    fill = max(width - _strip_len(label), 0)
    left = fill // 2
    right = fill - left
    print(f"\n{Theme.dark_red}{'═' * left}{Theme.reset}{Theme.bold}{Theme.red}{label}{Theme.reset}{Theme.dark_red}{'═' * right}{Theme.reset}")


def _finding_card(finding: dict, width: int) -> None:
    sev = finding.get("severity", "info")
    print(f"\n{Theme.sev(sev)}{Theme.bold}▣ {finding.get('title', 'Untitled finding')}{Theme.reset}")
    print(_kv("Severity", f"{Theme.sev(sev)}{Theme.bold}{sev.upper()}{Theme.reset}"))
    if finding.get("cvss") is not None:
        print(_kv("CVSS Score", f"{Theme.ember}{Theme.bold}{finding['cvss']}{Theme.reset}"))
    if finding.get("cwe"):
        print(_kv("CWE", f"{Theme.grey}{finding['cwe']}{Theme.reset}"))
    if finding.get("file"):
        loc = finding["file"] + (f":{finding['line']}" if finding.get("line") else "")
        print(_kv("Location", f"{Theme.grey}{loc}{Theme.reset}"))
    print(_kv("Category", f"{Theme.grey}{finding.get('category', '')}{Theme.reset}"))
    verification = finding.get("verification", "unverified")
    confidence = finding.get("confidence", 0.5)
    print(_kv("Verification", f"{Theme.grey}{verification} · confidence {confidence:.2f}{Theme.reset}"))
    if finding.get("description"):
        print(f"{Theme.green}{Theme.bold}Description:{Theme.reset}")
        for line in _wrap(finding["description"], width - 2, indent="  "):
            print(f"{Theme.white}{line}{Theme.reset}")
    if finding.get("evidence"):
        print(f"{Theme.green}{Theme.bold}Evidence:{Theme.reset} {Theme.dim}{finding['evidence'][:width - 12]}{Theme.reset}")
    if finding.get("remediation"):
        print(f"{Theme.green}{Theme.bold}Remediation:{Theme.reset}")
        for line in _wrap(finding["remediation"], width - 2, indent="  "):
            print(f"{Theme.white}{line}{Theme.reset}")


def _input_box(width: int) -> str:
    top = f"{Theme.dark_red}╭{'─' * width}╮{Theme.reset}"
    bot = f"{Theme.dark_red}╰{'─' * width}╯{Theme.reset}"
    print(top)
    prompt_prefix = f"{Theme.dark_red}│{Theme.reset} {Theme.red}{Theme.bold}❯{Theme.reset} "
    print(prompt_prefix, end="", flush=True)
    try:
        command = input()
    except (EOFError, KeyboardInterrupt):
        print()
        raise
    # move cursor up one line and redraw with the closing border + right edge
    inner_text = f" ❯ {command}"
    print(f"\033[1A\033[2K{Theme.dark_red}│{Theme.reset} {Theme.red}{Theme.bold}❯{Theme.reset} {Theme.white}{_pad(command, width - 4)}{Theme.reset}{Theme.dark_red}│{Theme.reset}")
    print(bot)
    return command


def _meta_bar(target: str, findings_count: int, runs_count: int) -> None:
    import os as _os

    has_keys = bool(_os.environ.get("DEXTER_LLM_KEYS") or _os.environ.get("GROQ_API_KEY") or _os.environ.get("LLM_API_KEY"))
    provider_label = "llm analyst configured" if has_keys else "local rules only"
    left = f"{Theme.grey}{target}{Theme.reset}"
    mid = f"{Theme.dark_red}{provider_label}{Theme.reset}"
    right = f"{Theme.crimson}{findings_count} finding(s){Theme.reset}  {Theme.dim}·{Theme.reset}  {Theme.grey}{runs_count} run(s) saved{Theme.reset}"
    width = _width()
    gap1 = max(width // 3 - _strip_len(left), 2)
    gap2 = max(width // 3 - _strip_len(mid), 2)
    print(f"{left}{' ' * gap1}{mid}{' ' * gap2}{right}")


def _render(findings: list[dict], runs: list[dict], target: str = "no target selected", first: bool = False) -> None:
    w = _width()
    counts = {level: sum(item.get("severity") == level for item in findings) for level in ("critical", "high", "medium", "low")}
    total = sum(counts.values())

    _clear()
    if first:
        # Full banner only on the very first frame — redrawing a
        # giant ASCII header after every command reads as noisy duplication.
        _render_banner()
        print(f"  {Theme.muted}local-first application security assessment{Theme.reset}")
    else:
        print(f"{Theme.red}{Theme.bold}▶ DEXTER{Theme.reset}  {Theme.muted}local-first application security assessment{Theme.reset}")

    _section("SESSION", w)
    print(_kv("Target", f"{Theme.white}{target[: w - 12]}{Theme.reset}"))
    print(_kv("Status", f"{Theme.white}{'FINDINGS DETECTED' if findings else 'READY'}{Theme.reset}"))
    print(_kv("Engine", f"{Theme.grey}dexter core · agentic verify (LLM optional){Theme.reset}"))

    _section("RISK OVERVIEW", w)
    for level in ("critical", "high", "medium", "low"):
        print(_bar(level.upper(), counts[level], total))

    _section(f"RECENT RUNS ({len(runs)})", w)
    if runs:
        for run in runs[:5]:
            rid = run.get("run_id", "")[: w - 30]
            n = len(run.get("findings", []))
            status = run.get("status", "")
            print(f"{Theme.white}{rid:<28}{Theme.reset} {Theme.red}{n:>3}{Theme.reset} findings  {Theme.muted}{status}{Theme.reset}")
    else:
        print(f"{Theme.muted}no saved runs yet{Theme.reset}")

    _section(f"FINDINGS ({len(findings)})", w)
    if findings:
        for finding in findings[-5:]:
            _finding_card(finding, w)
    else:
        print(f"{Theme.muted}no findings in the active session — run a scan to begin{Theme.reset}")

    print()
    print(_rule(w))
    _meta_bar(target, len(findings), len(runs))


def _run_exploit(name: str, target: str, param: str) -> tuple[list[dict], str] | None:
    if not is_authorized(target):
        print(f"{Theme.red}{target} is not authorized.{Theme.reset} run: {Theme.white}authorize {target}{Theme.reset}")
        input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        return None
    print(f"\n{Theme.red}{Theme.bold}⚠ EXPLOITATION{Theme.reset} — {name} will actively attempt to exploit parameter '{param}' on {target}")
    confirm = input(f"{Theme.white}Type 'yes' to proceed: {Theme.reset}").strip().lower()
    if confirm != "yes":
        print(f"{Theme.muted}cancelled{Theme.reset}")
        input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        return None
    try:
        results = run_single_exploit(name, target, param)
    except (ValueError, RuntimeError) as exc:
        print(f"{Theme.red}{exc}{Theme.reset}")
        input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        return None
    run = Run.create(safe_run_id(f"run-{name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"), [target], "exploit")
    run.findings = results
    run.status = "completed"
    save_run(run)
    print(f"{Theme.green}✓{Theme.reset} {name} complete — {Theme.red}{len(results)}{Theme.reset} finding(s)\n")
    return [f.to_dict() for f in results], target


def _run_single_tool(name: str, target: str) -> tuple[list[dict], str] | None:
    print(f"\n{Theme.red}{Theme.bold}▸{Theme.reset} running {Theme.white}{name}{Theme.reset} on {Theme.grey}{target}{Theme.reset}...")
    if name in {"nuclei", "nikto", "nmap", "zap", "ffuf"} and not is_authorized(target):
        print(f"{Theme.red}{target} is not authorized.{Theme.reset} run: {Theme.white}authorize {target}{Theme.reset}")
        input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        return None
    try:
        results = run_single_adapter(name, target)
    except (ValueError, RuntimeError) as exc:
        print(f"{Theme.red}{exc}{Theme.reset}")
        input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        return None
    for finding in results:
        _verify(finding)
    run = Run.create(safe_run_id(f"run-{name}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"), [target], "tool-only")
    run.findings = results
    run.status = "completed"
    save_run(run)
    print(f"{Theme.green}✓{Theme.reset} {name} complete — {Theme.red}{len(results)}{Theme.reset} finding(s)\n")
    return [f.to_dict() for f in results], target


STAGE_LABELS = {
    "scan": "scanning target",
    "analyze": "analyzing findings",
    "verify": "attempting verification",
    "refine": "refining confidence",
    "report": "requesting analyst summary",
}


def _scan(target: str, instructions: str = "") -> list[dict]:
    print(f"\n{Theme.red}{Theme.bold}▸{Theme.reset} {Theme.white}scanning{Theme.reset} {Theme.grey}{target}{Theme.reset} {Theme.dim}...{Theme.reset}")

    def on_stage(name: str) -> None:
        if ":" in name:
            _, tool = name.split(":", 1)
            print(f"{Theme.dim}    running {tool}...{Theme.reset}")
        else:
            label = STAGE_LABELS.get(name, name)
            print(f"{Theme.dark_red}  [{name.upper()}]{Theme.reset} {Theme.muted}{label}...{Theme.reset}")

    run_id = safe_run_id(f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    try:
        run = run_savr([target], instructions, "standard", run_id, on_stage=on_stage)
    except KeyboardInterrupt:
        print(f"\n{Theme.red}scan interrupted{Theme.reset} — no run was saved. Live-target tools can take several minutes.")
        return []
    save_run(run)
    print(f"{Theme.green}✓{Theme.reset} {Theme.white}scan complete{Theme.reset} — {Theme.red}{len(run.findings)}{Theme.reset} finding(s)")
    print(f"{Theme.muted}{insight_summary(run)}{Theme.reset}\n")
    return [finding.to_dict() for finding in run.findings]


def launch() -> int:
    if not _enabled():
        print("wakeupdexter needs an interactive terminal. Run it from PowerShell or Command Prompt.")
        return 2
    findings: list[dict] = []
    target = "no target selected"
    _render(findings, list_runs(), target, first=True)
    while True:
        try:
            w = _width()
            print()
            print(f"{Theme.muted}scan <path> · /tool <target> · authorize · exploit · pool · tools · runs · report · view · help · exit{Theme.reset}")
            command = _input_box(w).strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Theme.muted}session closed.{Theme.reset}")
            return 0
        if not command:
            _render(findings, list_runs(), target)
            continue
        try:
            parts = shlex.split(command)
        except ValueError as exc:
            print(f"{Theme.red}parse error:{Theme.reset} {exc}")
            input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
            _render(findings, list_runs(), target)
            continue
        action = parts[0].lower()
        if action in {"exit", "quit", "q"}:
            print(f"{Theme.muted}dexter session closed.{Theme.reset}")
            return 0
        if action == "help":
            w = _width()
            _section("COMMANDS", w)
            for cmd, desc in [
                ("scan <path> [instructions]", "full SAVR loop — local rules + every installed tool"),
                ("/semgrep, /bandit, /gitleaks, /trivy <path>", "run one tool directly"),
                ("/nmap, /nuclei, /nikto, /zap, /ffuf <host-or-url>", "run one live-target tool (needs authorize first)"),
                ("exploit sqlmap <url> --param <name>", "explicit exploitation step — asks for confirmation, never runs from scan"),
                ("/tools", "show which external tools are installed"),
                ("authorize <target>", "allow a live URL target for Nuclei/Nikto"),
                ("runs", "list saved assessments"),
                ("report [run] [human]", "print a report — add 'human' for plain-language"),
                ("view [run]", "open the local browser viewer"),
                ("pool", "show LLM provider/key pool status"),
                ("clear", "clear the active findings"),
                ("exit", "leave Dexter"),
            ]:
                print(f"{Theme.white}{Theme.bold}{cmd:<16}{Theme.reset} {Theme.muted}{desc}{Theme.reset}")
            input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
        elif action == "clear":
            findings, target = [], "no target selected"
        elif action == "exploit" and len(parts) >= 4 and parts[3] == "--param":
            tool_name, tool_target, param = parts[1], parts[2], parts[4] if len(parts) > 4 else ""
            result = _run_exploit(tool_name, tool_target, param)
            if result is not None:
                findings, target = result, tool_target
        elif action == "exploit":
            print(f"{Theme.red}usage:{Theme.reset} exploit sqlmap <url> --param <name>")
            input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        elif action.startswith("/"):
            tool_name = action[1:]
            if tool_name == "tools":
                w = _width()
                _section("TOOL STATUS", w)
                for row in tool_status():
                    state = "installed" if row["installed"] else "missing"
                    print(f"{Theme.white}{row['name']:<10}{Theme.reset} {Theme.grey}{state:<10} {row['target_kind']}{Theme.reset}")
                input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
            elif len(parts) > 1:
                tool_target = parts[1] if parts[1].startswith("http") else str(Path(parts[1]).expanduser())
                result = _run_single_tool(tool_name, tool_target)
                if result is not None:
                    findings, target = result, tool_target
            else:
                print(f"{Theme.red}usage:{Theme.reset} /{tool_name} <path-or-url>")
                input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        elif action == "authorize" and len(parts) > 1:
            authorize(parts[1])
            print(f"{Theme.green}✓{Theme.reset} authorized: {parts[1]}")
            input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        elif action == "scan" and len(parts) > 1:
            target = parts[1] if parts[1].startswith("http") else str(Path(parts[1]).expanduser())
            instructions = " ".join(parts[2:])
            findings = _scan(target, instructions)
        elif action == "pool":
            w = _width()
            _section("PROVIDER POOL", w)
            print(pool_status())
            input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
        elif action == "runs":
            w = _width()
            saved = list_runs()
            _section("SAVED ASSESSMENTS", w)
            if saved:
                for run in saved[:10]:
                    print(f"{Theme.white}{run.get('run_id', ''):<28}{Theme.reset} {Theme.red}{len(run.get('findings', [])):>3}{Theme.reset} findings  {Theme.muted}{run.get('status', '')}{Theme.reset}")
            else:
                print(f"{Theme.muted}no saved runs yet{Theme.reset}")
            input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
        elif action == "report":
            try:
                run_arg = parts[1] if len(parts) > 1 and parts[1] != "human" else None
                run = load_run(run_arg)
                if len(parts) > 1 and parts[-1] == "human":
                    print("\n" + generate_human_report(run))
                else:
                    print("\n" + _markdown(run))
            except FileNotFoundError as exc:
                print(f"{Theme.red}{exc}{Theme.reset}")
            input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
        elif action == "view":
            print(f"{Theme.muted}run{Theme.reset} {Theme.white}dexter view{Theme.reset} {Theme.muted}in another terminal to open the browser viewer.{Theme.reset}")
            input(f"\n{Theme.muted}press enter to return...{Theme.reset}")
        else:
            print(f"{Theme.red}unknown command.{Theme.reset} type {Theme.white}help{Theme.reset} for commands.")
            input(f"\n{Theme.muted}press enter to continue...{Theme.reset}")
        _render(findings, list_runs(), target)


def _markdown(run: dict) -> str:
    lines = [f"# Dexter Security Report: {run.get('run_id')}", f"Target: {', '.join(run.get('targets', []))}", "", run.get("summary", "")]
    for finding in run.get("findings", []):
        verification = finding.get("verification", "unverified")
        confidence = finding.get("confidence", 0.5)
        lines.extend([f"## [{finding['severity'].upper()}] {finding['title']}", f"Verification: {verification} (confidence {confidence:.2f})", finding["description"], f"Evidence: `{finding['evidence']}`", f"Remediation: {finding['remediation']}", ""])
    return "\n".join(lines)