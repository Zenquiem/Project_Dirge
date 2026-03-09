#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[run_pipeline] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="$ROOT_DIR/artifacts/logs"
mkdir -p "$LOG_DIR"

MODE="container"     # container | native
SKIP_IDA=0
SKIP_GDB=0
STRICT=0
NO_BUDGET=0

usage(){
  cat <<EOF
Usage:
  scripts/run_pipeline.sh [options]

Options:
  --native           run on host directly (no container)
  --container        run via scripts/run_container.sh (default)
  --skip-ida         skip skills/pwn-ida-slice
  --skip-gdb         skip skills/pwn-gdb-evidence
  --strict           verifier warnings treated as errors
  --no-budget        verifier skips budget checks
  -h, --help         show help

Env (passed through):
  PWN_INPUT_FILE / PWN_INPUT_TEXT / PWN_RUN_ARGS / PWN_GDB_TIMEOUT
  IDA_SLICE_PROVIDER / IDA_MCP_CLI / IDA_MCP_URL

Examples:
  scripts/run_pipeline.sh
  PWN_INPUT_TEXT=\$'1\\nAAAA\\n' scripts/run_pipeline.sh
  scripts/run_pipeline.sh --native --strict
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --native) MODE="native"; shift ;;
    --container) MODE="container"; shift ;;
    --skip-ida) SKIP_IDA=1; shift ;;
    --skip-gdb) SKIP_GDB=1; shift ;;
    --strict) STRICT=1; shift ;;
    --no-budget) NO_BUDGET=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown arg: $1" ;;
  esac
done

ts="$(date -u +%Y%m%dT%H%M%SZ)"
PIPE_LOG="$LOG_DIR/pipeline_${ts}.log"

run_cmd(){
  local title="$1"; shift
  echo "== $title ==" | tee -a "$PIPE_LOG"
  echo "+ $*" | tee -a "$PIPE_LOG"

  if [[ "$MODE" == "container" ]]; then
    "$ROOT_DIR/scripts/run_container.sh" -- "$@" 2>&1 | tee -a "$PIPE_LOG"
  else
    (cd "$ROOT_DIR" && "$@") 2>&1 | tee -a "$PIPE_LOG"
  fi

  echo "" | tee -a "$PIPE_LOG"
}

echo "[run_pipeline] mode=$MODE ts=$ts" | tee "$PIPE_LOG"

# Stage 1: Recon
run_cmd "Stage 1: pwn-recon" bash skills/pwn-recon/run.sh

# Stage 2: IDA Slice
if [[ "$SKIP_IDA" -eq 0 ]]; then
  run_cmd "Stage 2: pwn-ida-slice" bash skills/pwn-ida-slice/run.sh
else
  echo "== Stage 2: pwn-ida-slice (skipped) ==" | tee -a "$PIPE_LOG"
  echo "" | tee -a "$PIPE_LOG"
fi

# Stage 3: GDB Evidence
if [[ "$SKIP_GDB" -eq 0 ]]; then
  run_cmd "Stage 3: pwn-gdb-evidence" bash skills/pwn-gdb-evidence/run.sh
else
  echo "== Stage 3: pwn-gdb-evidence (skipped) ==" | tee -a "$PIPE_LOG"
  echo "" | tee -a "$PIPE_LOG"
fi

# Verifier
VER_ARGS=()
if [[ "$STRICT" -eq 1 ]]; then VER_ARGS+=(--strict); fi
if [[ "$NO_BUDGET" -eq 1 ]]; then VER_ARGS+=(--no-budget); fi

run_cmd "Verifier" python3 scripts/verifier.py "${VER_ARGS[@]}"

echo "[run_pipeline] DONE (see $PIPE_LOG)"
