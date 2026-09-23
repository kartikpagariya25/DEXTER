#!/usr/bin/env bash
# Starts a vLLM OpenAI-compatible server for a gated Llama model, wired
# for Dexter's agentic Verify/Refine stages (real tool-calling required).
#
# Requires: HF_TOKEN in the environment (a Hugging Face access token with
# access granted to the gated model). Run on Linux/WSL2 with an NVIDIA GPU
# — vLLM does not run natively on Windows.
#
# Usage:
#   HF_TOKEN=hf_xxx MODEL=meta-llama/Llama-3.1-8B-Instruct ./run_vllm_llama.sh

set -euo pipefail

: "${HF_TOKEN:?Set HF_TOKEN to a Hugging Face access token with access to the gated model}"
MODEL="${MODEL:-meta-llama/Llama-3.1-8B-Instruct}"
PORT="${PORT:-8000}"
TOOL_PARSER="${TOOL_PARSER:-llama3_json}"
LOCAL_API_KEY="${DEXTER_LLM_LOCAL_API_KEY:-}"

echo "Starting vLLM server"
echo "  model:       $MODEL"
echo "  port:        $PORT"
echo "  tool parser: $TOOL_PARSER"
echo "  auth:        $([ -n "$LOCAL_API_KEY" ] && echo enabled || echo disabled)"

export HUGGING_FACE_HUB_TOKEN="$HF_TOKEN"

ARGS=(
  --port "$PORT"
  --enable-auto-tool-choice
  --tool-call-parser "$TOOL_PARSER"
)

if [ -n "$LOCAL_API_KEY" ]; then
  ARGS+=(--api-key "$LOCAL_API_KEY")
fi

vllm serve "$MODEL" "${ARGS[@]}"
