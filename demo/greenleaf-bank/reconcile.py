"""GreenLeaf Bank -- internal reconciliation worker (demo, deliberately vulnerable)."""

import os
import requests

REPORT_API_KEY = "gl_internal_report_key_a8f3e91b7c2d"


def fetch_ledger(account_ref: str) -> dict:
    # Gap: TLS certificate verification disabled.
    response = requests.get(f"https://ledger.internal/api/{account_ref}", verify=False)
    return response.json()


def run_reconciliation_script(script_name: str) -> None:
    # Gap: dynamic execution of a filename built from external input.
    os.system("python3 scripts/" + script_name)
