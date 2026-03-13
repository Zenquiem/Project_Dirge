#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF_DIR="$ROOT_DIR/scripts"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

anchor_path() {
  local raw="${1:-}"
  if [[ -z "$raw" ]]; then
    return 0
  fi
  if [[ "$raw" == *"://"* ]]; then
    printf '%s' "$raw"
  else
    python3 - "$ROOT_DIR" "$raw" <<'PY'
import os, sys
root, raw = sys.argv[1], sys.argv[2]
if os.path.isabs(raw):
    print(raw)
else:
    print(os.path.abspath(os.path.join(root, raw)))
PY
  fi
}

sanitize_session() {
  local raw="${1:-shared}"
  raw="$(printf '%s' "$raw" | tr -cs 'A-Za-z0-9_.-' '_' | sed 's/^[_.-]*//; s/[_.-]*$//')"
  printf '%s' "${raw:-shared}"
}

PYTHON_BIN="$(anchor_path "$PYTHON_BIN")"

find_codex_bin() {
  local raw="${CODEX_BIN_REAL:-}"
  if [[ -n "$raw" ]]; then
    raw="$(anchor_path "$raw")"
    if [[ -x "$raw" ]]; then
      printf '%s' "$raw"
      return 0
    fi
  fi
  if command -v codex >/dev/null 2>&1; then
    command -v codex
    return 0
  fi
  for fb in "$HOME/.npm-global/bin/codex" "$HOME/.local/bin/codex"; do
    if [[ -x "$fb" ]]; then
      printf '%s' "$fb"
      return 0
    fi
  done
  return 1
}

find_java_home() {
  for cand in "${JAVA_HOME:-}" "${JDK_HOME:-}" "$ROOT_DIR/.tools/jdk"/* "$ROOT_DIR/.tools/java"/* /usr/lib/jvm/*; do
    [[ -n "$cand" ]] || continue
    [[ -d "$cand" ]] || continue
    if [[ -x "$cand/bin/java" ]]; then
      printf '%s' "$cand"
      return 0
    fi
  done
  return 1
}

normalize_cmd_string() {
  python3 - "$ROOT_DIR" "$1" <<'PY'
import os, shlex, sys
root = sys.argv[1]
raw = sys.argv[2]
parts = shlex.split(raw)
if not parts:
    print('')
    raise SystemExit(0)
flag_takes_value = {'-W', '-X', '--check-hash-based-pycs', '-O'}
out = []
i = 0
while i < len(parts):
    cur = parts[i]
    out.append(cur)
    if i == 0:
        i += 1
        continue
    prev = parts[i - 1] if i > 0 else ''
    if prev in flag_takes_value:
        i += 1
        continue
    if cur in flag_takes_value:
        if i + 1 < len(parts):
            out.append(parts[i + 1])
            i += 2
            continue
    if cur == '-m':
        if i + 1 < len(parts):
            out.append(parts[i + 1])
            i += 2
            continue
    if cur == '-S':
        if i + 1 < len(parts):
            payload = parts[i + 1]
            payload_parts = shlex.split(payload)
            for idx, token in enumerate(payload_parts):
                if (token.startswith('./') or token.startswith('../') or '/' in token) and not os.path.isabs(token):
                    payload_parts[idx] = os.path.abspath(os.path.join(root, token))
            out.append(' '.join(payload_parts))
            i += 2
            continue
    if (cur.startswith('./') or cur.startswith('../') or '/' in cur) and not os.path.isabs(cur):
        out[-1] = os.path.abspath(os.path.join(root, cur))
    i += 1
print('\n'.join(out))
PY
}

resolve_gdb_cfg() {
  local raw="${DIRGE_GDB_MCP_CMD:-}"
  local cwd_raw="${DIRGE_GDB_MCP_CWD:-.}"
  local cwd_abs="$(anchor_path "$cwd_raw")"
  local enabled="false"
  local cmd=""
  local args="[]"

  if [[ -n "$raw" ]]; then
    mapfile -t toks < <(normalize_cmd_string "$raw")
    if [[ ${#toks[@]} -gt 0 ]]; then
      cmd="${toks[0]}"
      if [[ ${#toks[@]} -gt 1 ]]; then
        args="[$(printf '"%s", ' "${toks[@]:1}" | sed 's/, $//')]"
      fi
      enabled="true"
    fi
  elif command -v gdb-mcp >/dev/null 2>&1 || [[ -x "$HOME/.local/bin/gdb-mcp" ]]; then
    cmd="$PYTHON_BIN"
    args="[\"$ROOT_DIR/scripts/gdb_mcp_launcher.py\"]"
    cwd_abs="$ROOT_DIR"
    enabled="true"
  fi

  printf '%s\n%s\n%s\n%s\n' "$cmd" "$args" "$cwd_abs" "$enabled"
}

SESSION_TAG="$(sanitize_session "${DIRGE_SESSION_ID:-${PWN_SESSION_ID:-${SESSION_ID:-shared}}}")"
CODEX_BIN="$(find_codex_bin || true)"
if [[ -z "$CODEX_BIN" ]]; then
  echo "[codex_with_mcp] codex not found" >&2
  exit 2
fi

SUBCOMMAND="${1:-exec}"
if [[ $# -gt 0 ]]; then shift; fi
if [[ "$SUBCOMMAND" == "exec" ]]; then
  if [[ -z "${OPENAI_API_KEY:-}" ]]; then
    src_home="${CODEX_HOME:-}"
    src_home="$(anchor_path "$src_home")"
    if [[ -z "$src_home" || ! -f "$src_home/auth.json" ]]; then
      echo "[codex_with_mcp] missing auth material for exec" >&2
      exit 2
    fi
  fi
fi

SOURCE_CODEX_HOME="$(anchor_path "${CODEX_HOME:-}")"
CODEX_RUNTIME_HOME="$(anchor_path "${CODEX_RUNTIME_HOME:-artifacts/codex/runtime-home/$SESSION_TAG}")"
GHIDRA_RUNTIME_ROOT="$(anchor_path "${GHIDRA_RUNTIME_ROOT:-artifacts/ghidra/runtime-root}")"
GHIDRA_SESSION_ROOT="$(anchor_path "${GHIDRA_SESSION_ROOT:-$GHIDRA_RUNTIME_ROOT/$SESSION_TAG}")"
GHIDRA_MCP_PROJECT_PATH="$(anchor_path "${GHIDRA_MCP_PROJECT_PATH:-$GHIDRA_SESSION_ROOT/project}")"
GHIDRA_MCP_HOME="$(anchor_path "${GHIDRA_MCP_HOME:-$GHIDRA_SESSION_ROOT/home}")"
GHIDRA_MCP_XDG_CONFIG_HOME="$(anchor_path "${GHIDRA_MCP_XDG_CONFIG_HOME:-$GHIDRA_MCP_HOME/.config}")"
GHIDRA_MCP_XDG_CACHE_HOME="$(anchor_path "${GHIDRA_MCP_XDG_CACHE_HOME:-$GHIDRA_MCP_HOME/.cache}")"
GHIDRA_MCP_XDG_DATA_HOME="$(anchor_path "${GHIDRA_MCP_XDG_DATA_HOME:-$GHIDRA_MCP_HOME/.local/share}")"
MCP_JSONLINE_BRIDGE="$(anchor_path "${MCP_JSONLINE_BRIDGE:-scripts/mcp_jsonline_bridge.py}")"
MCP_JSONLINE_BRIDGE_LOG="$(anchor_path "${MCP_JSONLINE_BRIDGE_LOG:-artifacts/bridge-rel.log}")"
PYGHIDRA_HOTFIX_DIR="$(anchor_path "${PYGHIDRA_HOTFIX_DIR:-scripts/pyghidra_hotfix}")"
GHIDRA_MCP_BIN="${GHIDRA_MCP_BIN:-}"
if [[ -z "$GHIDRA_MCP_BIN" ]]; then
  GHIDRA_MCP_BIN="$ROOT_DIR/scripts/pyghidra_mcp_launcher.py"
else
  GHIDRA_MCP_BIN="$(anchor_path "$GHIDRA_MCP_BIN")"
fi
GHIDRA_INSTALL_DIR_VALUE="${GHIDRA_INSTALL_DIR:-$ROOT_DIR/.ghidra-current}"
GHIDRA_INSTALL_DIR_VALUE="$(anchor_path "$GHIDRA_INSTALL_DIR_VALUE")"
if [[ ! -x "$GHIDRA_INSTALL_DIR_VALUE/support/analyzeHeadless" ]]; then
  if [[ -e "$ROOT_DIR/.ghidra-current/support/analyzeHeadless" ]]; then
    GHIDRA_INSTALL_DIR_VALUE="$ROOT_DIR/.ghidra-current"
  fi
fi
JAVA_DISCOVERED="$(find_java_home || true)"
if [[ -n "$JAVA_DISCOVERED" ]]; then
  export JAVA_HOME="$JAVA_DISCOVERED"
  export JDK_HOME="$JAVA_DISCOVERED"
fi
export CODEX_HOME="$CODEX_RUNTIME_HOME"
export HOME="$GHIDRA_MCP_HOME"
export XDG_CONFIG_HOME="$GHIDRA_MCP_XDG_CONFIG_HOME"
export XDG_CACHE_HOME="$GHIDRA_MCP_XDG_CACHE_HOME"
export XDG_DATA_HOME="$GHIDRA_MCP_XDG_DATA_HOME"
mkdir -p "$CODEX_RUNTIME_HOME" "$GHIDRA_MCP_PROJECT_PATH" "$GHIDRA_MCP_HOME" "$GHIDRA_MCP_XDG_CONFIG_HOME" "$GHIDRA_MCP_XDG_CACHE_HOME" "$GHIDRA_MCP_XDG_DATA_HOME"

mapfile -t GDB_CFG < <(resolve_gdb_cfg)
GDB_CMD="${GDB_CFG[0]}"
GDB_ARGS="${GDB_CFG[1]}"
GDB_CWD="${GDB_CFG[2]}"
GDB_ENABLED="${GDB_CFG[3]}"

exec "$CODEX_BIN" \
  -C "$ROOT_DIR" \
  -c 'approval_policy="never"' \
  -c 'sandbox_mode="workspace-write"' \
  -c 'sandbox_workspace_write.network_access=true' \
  -c 'web_search="disabled"' \
  -c "mcp_servers.pyghidra-mcp.command=\"$PYTHON_BIN\"" \
  -c "mcp_servers.pyghidra-mcp.args=[\"$MCP_JSONLINE_BRIDGE\",\"--\",\"$GHIDRA_MCP_BIN\",\"--project-path\",\"$GHIDRA_MCP_PROJECT_PATH\",\"--project-name\",\"my_project\",\"-t\",\"stdio\"]" \
  -c 'mcp_servers.pyghidra-mcp.startup_timeout_sec=55' \
  -c "mcp_servers.pyghidra-mcp.env={GHIDRA_INSTALL_DIR=\"$GHIDRA_INSTALL_DIR_VALUE\",HOME=\"$GHIDRA_MCP_HOME\",XDG_CONFIG_HOME=\"$GHIDRA_MCP_XDG_CONFIG_HOME\",XDG_CACHE_HOME=\"$GHIDRA_MCP_XDG_CACHE_HOME\",XDG_DATA_HOME=\"$GHIDRA_MCP_XDG_DATA_HOME\",MCP_JSONLINE_BRIDGE_LOG=\"$MCP_JSONLINE_BRIDGE_LOG\",PYTHONPATH=\"$PYGHIDRA_HOTFIX_DIR${PYTHONPATH:+:$PYTHONPATH}\",PYGHIDRA_CHROMA_FALLBACK=\"1\",JAVA_HOME=\"${JAVA_HOME:-}\",JDK_HOME=\"${JDK_HOME:-}\",DISPLAY=\"\"}" \
  -c 'mcp_servers.pyghidra-mcp.enabled=true' \
  -c "mcp_servers.gdb.command=\"$GDB_CMD\"" \
  -c "mcp_servers.gdb.args=$GDB_ARGS" \
  -c "mcp_servers.gdb.cwd=\"$GDB_CWD\"" \
  -c "mcp_servers.gdb.enabled=$GDB_ENABLED" \
  "$SUBCOMMAND" "$@"
