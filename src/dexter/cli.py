from __future__ import annotations

import argparse
import html
import secrets
import sys
import threading
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__
from .authorization import authorize, is_authorized, list_authorized, revoke
from .dashboard import launch
from .env_file import load_env
from .loop import insight_summary, run_savr
from .provider_pool import pool_status
from .report import generate_human_report
from .storage import data_dir, load_run, save_run, safe_run_id
from .tools import is_live_target, run_single_exploit, tool_status

load_env()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dexter", description="Local-first application security assessment CLI")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--target", "-t", action="append", help="Local directory, OpenAPI JSON, or authorized URL")
    parser.add_argument("--target-list", type=Path, help="File containing one target per line")
    parser.add_argument("--instruction", default="")
    parser.add_argument("--instruction-file", type=Path)
    parser.add_argument("--scan-mode", choices=["quick", "standard"], default="standard")
    parser.add_argument("--non-interactive", "-n", action="store_true")
    parser.add_argument("--run-name", default="")
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("wakeupdexter", help="Launch the interactive Dexter command center")
    view = subparsers.add_parser("view", help="Open a local run viewer")
    view.add_argument("run", nargs="?")
    view.add_argument("--host", default="127.0.0.1")
    view.add_argument("--port", type=int, default=0)
    view.add_argument("--no-open", action="store_true")
    report = subparsers.add_parser("report", help="Export a run report")
    report.add_argument("run", nargs="?")
    report.add_argument("--format", choices=["json", "markdown", "human"], default="markdown")
    report.add_argument("--output", type=Path)
    config = subparsers.add_parser("config", help="Show local configuration location")
    config.add_argument("action", choices=["path"], default="path")
    subparsers.add_parser("auth", help="Show LLM provider/key pool status")
    subparsers.add_parser("tools", help="Show which external security tools are installed")
    authorize_cmd = subparsers.add_parser("authorize", help="Manage authorized targets for live-target tools (Nuclei, Nikto, ZAP, ffuf, sqlmap)")
    authorize_cmd.add_argument("target", nargs="?")
    authorize_cmd.add_argument("--list", action="store_true")
    authorize_cmd.add_argument("--revoke", action="store_true")
    exploit_cmd = subparsers.add_parser("exploit", help="Explicit, separate step for active exploitation tools (never runs from a normal scan)")
    exploit_cmd.add_argument("tool", choices=["sqlmap"])
    exploit_cmd.add_argument("target")
    exploit_cmd.add_argument("--param", required=True, help="Exact parameter name to test — required, no blind-fuzzing a whole target")
    return parser


def markdown_report(run: dict) -> str:
    counts = {level: sum(f["severity"] == level for f in run["findings"]) for level in ("critical", "high", "medium", "low")}
    lines = [f"# Dexter Security Report: {run['run_id']}", "", f"- Target(s): {', '.join(run['targets'])}", f"- Status: {run['status']}", f"- Findings: {counts}", "", "## Analyst Summary", run.get("summary", "") or "No summary available.", "", "## Findings"]
    for finding in run["findings"]:
        location = f" ({finding['file']}:{finding['line']})" if finding.get("file") else ""
        verification = finding.get("verification", "unverified")
        confidence = finding.get("confidence", 0.5)
        lines.extend([f"### [{finding['severity'].upper()}] {finding['title']}", f"**Category:** {finding['category']}  ", f"**Location:** {location or 'target-level'}  ", f"**Verification:** {verification} (confidence {confidence:.2f})  ", f"**Evidence:** `{finding['evidence']}`", "", finding["description"], "", f"**Remediation:** {finding['remediation']}", ""])
    return "\n".join(lines)


def serve(run: dict, host: str, port: int, no_open: bool) -> None:
    token = secrets.token_urlsafe(24)
    run_json = html.escape(__import__("json").dumps(run, indent=2))
    page = f"<html><head><title>Dexter {html.escape(run['run_id'])}</title><style>body{{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border-bottom:1px solid #ddd;text-align:left}}.high,.critical{{color:#b42318}}.medium{{color:#b54708}}pre{{white-space:pre-wrap}}</style></head><body><h1>Dexter Security Run</h1><p><b>{html.escape(run['run_id'])}</b> | {html.escape(', '.join(run['targets']))}</p><table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>{''.join(f"<tr><td class='{f['severity']}'>{html.escape(f['severity'])}</td><td>{html.escape(f['title'])}</td><td><code>{html.escape(f['evidence'])}</code></td><td>{html.escape(f['remediation'])}</td></tr>" for f in run['findings'])}</table><h2>Analyst summary</h2><pre>{html.escape(run.get('summary',''))}</pre><details><summary>Raw run data</summary><pre>{run_json}</pre></details></body></html>"

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != f"/?token={token}":
                self.send_error(403, "Invalid viewer token")
                return
            body = page.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *_args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://{host}:{server.server_port}/?token={token}"
    print(f"Dexter viewer: {url}")
    if not no_open:
        threading.Timer(0.15, webbrowser.open, args=(url,)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nViewer stopped.")
    finally:
        server.server_close()


def _print_stage(name: str) -> None:
    if ":" in name:
        stage, tool = name.split(":", 1)
        print(f"   running {tool}...")
    else:
        print(f"-> {name}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "wakeupdexter":
        return launch()
    if args.command == "view":
        try:
            serve(load_run(args.run), args.host, args.port, args.no_open)
            return 0
        except FileNotFoundError as exc:
            parser.error(str(exc))
    if args.command == "report":
        try:
            run = load_run(args.run)
        except FileNotFoundError as exc:
            parser.error(str(exc))
        if args.format == "json":
            content = __import__("json").dumps(run, indent=2)
        elif args.format == "human":
            content = generate_human_report(run)
        else:
            content = markdown_report(run)
        if args.output:
            args.output.write_text(content, encoding="utf-8")
            print(args.output)
        else:
            print(content)
        return 0
    if args.command == "config":
        print(data_dir())
        return 0
    if args.command == "auth":
        print(pool_status())
        return 0
    if args.command == "tools":
        for row in tool_status():
            status = "installed" if row["installed"] else "not found on PATH"
            print(f"{row['name']:<10} {status:<20} {row['target_kind']}")
        return 0
    if args.command == "authorize":
        if args.list or not args.target:
            targets = list_authorized()
            print("\n".join(targets) if targets else "No authorized targets yet.")
            return 0
        if args.revoke:
            revoke(args.target)
            print(f"Revoked: {args.target}")
        else:
            authorize(args.target)
            print(f"Authorized: {args.target}")
        return 0
    if args.command == "exploit":
        try:
            findings = run_single_exploit(args.tool, args.target, args.param)
        except (ValueError, RuntimeError) as exc:
            parser.error(str(exc))
        for finding in findings:
            print(f"[{finding.severity.upper()}] {finding.title}\n  evidence: {finding.evidence}")
        return 1 if findings else 0
    targets = list(args.target or [])
    if args.target_list:
        targets.extend(line.strip() for line in args.target_list.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#"))
    if not targets:
        parser.error("at least one --target or --target-list is required")
    instructions = args.instruction
    if args.instruction_file:
        instructions += "\n" + args.instruction_file.read_text(encoding="utf-8")
    for target in targets:
        if is_live_target(target) and not is_authorized(target):
            print(f"Note: {target} is not authorized — live-target tools (Nmap, Nuclei, Nikto, ZAP, ffuf) will be skipped. Run: dexter authorize {target}")
    run_id = safe_run_id(args.run_name or f"run-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    run = run_savr(targets, instructions, args.scan_mode, run_id, on_stage=_print_stage)
    path = save_run(run)
    print(f"Run saved: {path}")
    print(insight_summary(run))
    for finding in run.findings:
        print(f"[{finding.severity.upper()}] {finding.title} ({finding.verification}, confidence {finding.confidence:.2f}): {finding.evidence}")
    if not args.non_interactive:
        print(f"View with: dexter view {run_id}")
    return 1 if run.findings else 0


if __name__ == "__main__":
    sys.exit(main())
