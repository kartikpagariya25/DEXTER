#!/usr/bin/env python3
"""Sanity-checks a vLLM (or any OpenAI-compatible) endpoint before pointing
Dexter at it: reachability, a plain chat completion, and — the part that
silently breaks agentic Verify if missed — real tool-calling support.

Usage:
    python scripts/check_vllm.py http://localhost:8000/v1 [api_key]
"""
import json
import sys
import urllib.error
import urllib.request


def post(url, api_key, body):
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def main():
    if len(sys.argv) < 2:
        print("usage: check_vllm.py <base_url> [api_key]")
        sys.exit(1)
    base_url = sys.argv[1].rstrip("/")
    api_key = sys.argv[2] if len(sys.argv) > 2 else None

    print(f"Checking {base_url} ...")

    try:
        models_req = urllib.request.Request(f"{base_url}/models", headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
        with urllib.request.urlopen(models_req, timeout=10) as resp:
            models = json.loads(resp.read().decode())
        model_id = models["data"][0]["id"]
        print(f"  [ok] reachable, model: {model_id}")
    except Exception as exc:
        print(f"  [FAIL] not reachable: {exc}")
        sys.exit(1)

    try:
        result = post(f"{base_url}/chat/completions", api_key, {
            "model": model_id,
            "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        })
        print(f"  [ok] chat completion works: {result['choices'][0]['message']['content']!r}")
    except Exception as exc:
        print(f"  [FAIL] chat completion failed: {exc}")
        sys.exit(1)

    try:
        result = post(f"{base_url}/chat/completions", api_key, {
            "model": model_id,
            "messages": [{"role": "user", "content": "What's the weather in Pune?"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get the current weather for a city",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]},
                },
            }],
            "tool_choice": "auto",
        })
        tool_calls = result["choices"][0]["message"].get("tool_calls")
        if tool_calls:
            print(f"  [ok] tool-calling works: model called {tool_calls[0]['function']['name']}")
        else:
            print("  [WARN] server responded but did not call the tool — check --enable-auto-tool-choice")
            print("         and --tool-call-parser match your model family (e.g. llama3_json for Llama 3.x).")
            print("         Dexter's agentic Verify will silently fall back to the offline heuristic without this.")
    except Exception as exc:
        print(f"  [FAIL] tool-calling request failed: {exc}")
        sys.exit(1)

    print("\nLooks good. Point Dexter at it with:")
    print(f"  DEXTER_LLM_LOCAL_URL={base_url}")
    print(f"  DEXTER_LLM_LOCAL_MODEL={model_id}")
    if api_key:
        print(f"  DEXTER_LLM_LOCAL_API_KEY={api_key}")


if __name__ == "__main__":
    main()
