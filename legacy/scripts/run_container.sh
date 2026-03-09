#!/usr/bin/env bash
set -euo pipefail

die(){ echo "[run_container] ERROR: $*" >&2; exit 1; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ENGINE="${CONTAINER_ENGINE:-}"
IMAGE="${PWN_AGENT_IMAGE:-pwn-agent:latest}"
WORKDIR_IN_CONTAINER="${PWN_WORKDIR_IN_CONTAINER:-/workspace}"
NAME_PREFIX="${PWN_CONTAINER_NAME_PREFIX:-pwn-agent}"

MEM_LIMIT="${PWN_CONTAINER_MEM:-4g}"
CPU_LIMIT="${PWN_CONTAINER_CPUS:-2}"
PIDS_LIMIT="${PWN_CONTAINER_PIDS:-512}"

ENABLE_PTRACE="${PWN_CONTAINER_PTRACE:-1}"
ENABLE_INIT="${PWN_CONTAINER_INIT:-1}"
STOP_TIMEOUT="${PWN_CONTAINER_STOP_TIMEOUT:-5}"

# /tmp tmpfs (safer for pwntools/patchelf/python temp usage)
ENABLE_TMPFS="${PWN_CONTAINER_TMPFS:-1}"
TMPFS_SIZE="${PWN_CONTAINER_TMPFS_SIZE:-1g}"

# Optional: make /workspace/challenge writable for patching binaries (default: keep immutable)
CHALLENGE_RW="${PWN_CONTAINER_CHALLENGE_RW:-0}"

# Env passthrough (whitelist)
DEFAULT_PASSTHROUGH=(
  PWN_INPUT_FILE PWN_INPUT_TEXT PWN_RUN_ARGS PWN_GDB_TIMEOUT PWN_INPUT_MODE GDB_BIN
  IDA_SLICE_PROVIDER IDA_SLICE_DEPTH IDA_MAX_SINKS IDA_MCP_CLI IDA_MCP_URL
  PWN_AGENT_IMAGE CONTAINER_ENGINE
  PWN_CONTAINER_MEM PWN_CONTAINER_CPUS PWN_CONTAINER_PIDS
  PWN_CONTAINER_PTRACE PWN_CONTAINER_INIT PWN_CONTAINER_STOP_TIMEOUT
  PWN_CONTAINER_TMPFS PWN_CONTAINER_TMPFS_SIZE
  PWN_CONTAINER_CHALLENGE_RW
)
USER_PASSTHROUGH="${PWN_ENV_PASSTHROUGH:-}"

usage(){
  cat <<EOF
Usage:
  scripts/run_container.sh [--image IMG] [--] <command...>

Notes:
  - Repo is mounted read-only at $WORKDIR_IN_CONTAINER
  - state/ and artifacts/ are mounted read-write (overlay)
  - /tmp is tmpfs by default (size=$TMPFS_SIZE)
  - challenge/ is read-only by default; set PWN_CONTAINER_CHALLENGE_RW=1 to allow patching
  - Env vars forwarded via whitelist; extend with PWN_ENV_PASSTHROUGH="FOO,BAR"

EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then usage; exit 0; fi
if [[ "${1:-}" == "--image" ]]; then
  IMAGE="${2:-}"; [[ -n "$IMAGE" ]] || die "--image needs a value"
  shift 2
fi
if [[ "${1:-}" == "--" ]]; then shift; fi
[[ $# -ge 1 ]] || die "no command provided"
CMD=("$@")

# choose engine
if [[ -z "$ENGINE" ]]; then
  if command -v docker >/dev/null 2>&1; then ENGINE="docker"
  elif command -v podman >/dev/null 2>&1; then ENGINE="podman"
  else die "neither docker nor podman found"
  fi
fi

# ensure dirs
mkdir -p "$ROOT_DIR/artifacts" "$ROOT_DIR/state" "$ROOT_DIR/challenge"
mkdir -p "$ROOT_DIR/artifacts/tmp" "$ROOT_DIR/artifacts/cores" "$ROOT_DIR/artifacts/logs"
[[ -f "$ROOT_DIR/state/state.json" ]] || echo "{}" > "$ROOT_DIR/state/state.json"

USER_OPT=(--user "$(id -u):$(id -g)")
NET_OPT=(--network none)
RES_OPT=( --memory "$MEM_LIMIT" --cpus "$CPU_LIMIT" --pids-limit "$PIDS_LIMIT" )

SEC_OPT=()
if [[ "$ENABLE_PTRACE" == "1" ]]; then
  SEC_OPT+=(--cap-add SYS_PTRACE --security-opt seccomp=unconfined)
fi

INIT_OPT=()
if [[ "$ENABLE_INIT" == "1" ]]; then INIT_OPT+=(--init); fi

STOP_OPT=()
if [[ -n "$STOP_TIMEOUT" ]]; then STOP_OPT+=(--stop-timeout "$STOP_TIMEOUT"); fi

# tmpfs for /tmp
TMPFS_OPT=()
if [[ "$ENABLE_TMPFS" == "1" ]]; then
  TMPFS_OPT+=(--tmpfs "/tmp:rw,nosuid,nodev,mode=1777,size=$TMPFS_SIZE")
fi

# base env: set TMPDIR to a rw location in mounted artifacts
ENV_OPT=( -e "TERM=dumb" -e "PYTHONUNBUFFERED=1" -e "TMPDIR=$WORKDIR_IN_CONTAINER/artifacts/tmp" )

# Forward whitelisted vars by name (more robust than -e VAR=VALUE for spaces)
for v in "${DEFAULT_PASSTHROUGH[@]}"; do
  if [[ -n "${!v-}" ]]; then
    ENV_OPT+=( -e "$v" )
  fi
done
if [[ -n "$USER_PASSTHROUGH" ]]; then
  IFS=',' read -r -a extra <<< "$USER_PASSTHROUGH"
  for v in "${extra[@]}"; do
    v="$(echo "$v" | xargs)"
    [[ -n "$v" ]] || continue
    if [[ -n "${!v-}" ]]; then
      ENV_OPT+=( -e "$v" )
    fi
  done
fi

# mounts:
# 1) repo read-only
# 2) state/artifacts read-write overlay mounts
MOUNTS=(
  --mount "type=bind,src=$ROOT_DIR,dst=$WORKDIR_IN_CONTAINER,readonly"
  --mount "type=bind,src=$ROOT_DIR/state,dst=$WORKDIR_IN_CONTAINER/state"
  --mount "type=bind,src=$ROOT_DIR/artifacts,dst=$WORKDIR_IN_CONTAINER/artifacts"
)

# optional: make challenge writable (for patching). This overlays /workspace/challenge on top of RO repo mount.
if [[ "$CHALLENGE_RW" == "1" ]]; then
  MOUNTS+=( --mount "type=bind,src=$ROOT_DIR/challenge,dst=$WORKDIR_IN_CONTAINER/challenge" )
fi

NAME="${NAME_PREFIX}-$(date -u +%Y%m%dT%H%M%SZ)-$$"

set -x
"$ENGINE" run --rm -t \
  --name "$NAME" \
  "${INIT_OPT[@]}" \
  "${STOP_OPT[@]}" \
  "${TMPFS_OPT[@]}" \
  "${USER_OPT[@]}" \
  "${MOUNTS[@]}" \
  -w "$WORKDIR_IN_CONTAINER" \
  "${NET_OPT[@]}" \
  "${RES_OPT[@]}" \
  "${SEC_OPT[@]}" \
  "${ENV_OPT[@]}" \
  "$IMAGE" \
  "${CMD[@]}"
