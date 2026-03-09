#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CODEX_BIN="${CODEX_BIN_REAL:-/home/zenduk/.npm-global/bin/codex}"
SOURCE_CODEX_HOME="${CODEX_HOME:-}"
SESSION_TAG_RAW="${DIRGE_SESSION_ID:-${PWN_SESSION_ID:-${SESSION_ID:-shared}}}"
SESSION_TAG="$(printf '%s' "$SESSION_TAG_RAW" | tr -cs 'A-Za-z0-9_.-' '_' | sed 's/^[_.-]*//; s/[_.-]*$//')"
if [[ -z "$SESSION_TAG" ]]; then
  SESSION_TAG="shared"
fi
CODEX_RUNTIME_HOME="${CODEX_RUNTIME_HOME:-/tmp/project_dirge_codex_home_${UID:-1000}_${SESSION_TAG}}"
PYTHON_BIN="${PYTHON_BIN:-/usr/bin/python3}"

GHIDRA_MCP_BIN="${GHIDRA_MCP_BIN:-/home/zenduk/.venvs/pyghidra-mcp/bin/pyghidra-mcp}"
GHIDRA_RUNTIME_ROOT="${GHIDRA_RUNTIME_ROOT:-/tmp/project_dirge_ghidra}"
GHIDRA_SESSION_ROOT="${GHIDRA_SESSION_ROOT:-$GHIDRA_RUNTIME_ROOT/$SESSION_TAG}"
GHIDRA_MCP_PROJECT_PATH="${GHIDRA_MCP_PROJECT_PATH:-$GHIDRA_SESSION_ROOT/project}"
GHIDRA_MCP_PROJECT_NAME="${GHIDRA_MCP_PROJECT_NAME:-my_project}"
GHIDRA_INSTALL_DIR_VALUE="${GHIDRA_INSTALL_DIR:-/opt/ghidra/current}"
GHIDRA_MCP_HOME="${GHIDRA_MCP_HOME:-$GHIDRA_SESSION_ROOT/home}"
GHIDRA_MCP_XDG_CONFIG_HOME="${GHIDRA_MCP_XDG_CONFIG_HOME:-$GHIDRA_MCP_HOME/.config}"
GHIDRA_MCP_XDG_CACHE_HOME="${GHIDRA_MCP_XDG_CACHE_HOME:-$GHIDRA_MCP_HOME/.cache}"
GHIDRA_MCP_FORCE_UNLOCK="${GHIDRA_MCP_FORCE_UNLOCK:-1}"
MCP_JSONLINE_BRIDGE="${MCP_JSONLINE_BRIDGE:-$ROOT_DIR/scripts/mcp_jsonline_bridge.py}"
MCP_JSONLINE_BRIDGE_LOG="${MCP_JSONLINE_BRIDGE_LOG:-/tmp/project_dirge_pyghidra_bridge.log}"
PYGHIDRA_SERVER_NAME="${PYGHIDRA_SERVER_NAME:-pyghidra-mcp}"
PYGHIDRA_HOTFIX_DIR="${PYGHIDRA_HOTFIX_DIR:-$ROOT_DIR/scripts/pyghidra_hotfix}"
PYGHIDRA_MCP_PYTHONPATH="$PYGHIDRA_HOTFIX_DIR"
if [[ -n "${PYTHONPATH:-}" ]]; then
  PYGHIDRA_MCP_PYTHONPATH="$PYGHIDRA_MCP_PYTHONPATH:$PYTHONPATH"
fi
JAVA_TOOL_OPTIONS_VALUE="${JAVA_TOOL_OPTIONS:-}"
if [[ "$JAVA_TOOL_OPTIONS_VALUE" != *"-Djava.awt.headless=true"* ]]; then
  if [[ -n "$JAVA_TOOL_OPTIONS_VALUE" ]]; then
    JAVA_TOOL_OPTIONS_VALUE="$JAVA_TOOL_OPTIONS_VALUE -Djava.awt.headless=true"
  else
    JAVA_TOOL_OPTIONS_VALUE="-Djava.awt.headless=true"
  fi
fi
DIRGE_DISABLE_MCP="${DIRGE_DISABLE_MCP:-0}"

if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "[codex_with_mcp] python executable not found: $PYTHON_BIN" >&2
  exit 2
fi

if [[ "$DIRGE_DISABLE_MCP" != "1" ]]; then
  if [[ "$GHIDRA_MCP_PROJECT_PATH" == *"://"* ]]; then
    echo "[codex_with_mcp] invalid GHIDRA_MCP_PROJECT_PATH schema: $GHIDRA_MCP_PROJECT_PATH" >&2
    GHIDRA_MCP_PROJECT_PATH="$GHIDRA_SESSION_ROOT/project"
  fi
  if [[ "$GHIDRA_MCP_PROJECT_PATH" != /* ]]; then
    GHIDRA_MCP_PROJECT_PATH="$ROOT_DIR/$GHIDRA_MCP_PROJECT_PATH"
  fi
  GHIDRA_MCP_PROJECT_PATH="${GHIDRA_MCP_PROJECT_PATH%/}"
  [[ -z "$GHIDRA_MCP_PROJECT_PATH" ]] && GHIDRA_MCP_PROJECT_PATH="$GHIDRA_SESSION_ROOT/project"

  if [[ ! -x "$GHIDRA_MCP_BIN" ]]; then
    echo "[codex_with_mcp] pyghidra-mcp not executable: $GHIDRA_MCP_BIN" >&2
    exit 2
  fi

  if [[ ! -f "$MCP_JSONLINE_BRIDGE" ]]; then
    echo "[codex_with_mcp] missing bridge script: $MCP_JSONLINE_BRIDGE" >&2
    exit 2
  fi

  if [[ ! -x "$GHIDRA_INSTALL_DIR_VALUE/support/analyzeHeadless" ]]; then
    echo "[codex_with_mcp] invalid GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR_VALUE" >&2
    echo "[codex_with_mcp] expected executable: $GHIDRA_INSTALL_DIR_VALUE/support/analyzeHeadless" >&2
    exit 2
  fi

  mkdir -p "$GHIDRA_MCP_PROJECT_PATH" "$GHIDRA_MCP_XDG_CONFIG_HOME" "$GHIDRA_MCP_XDG_CACHE_HOME"
  if [[ -n "$MCP_JSONLINE_BRIDGE_LOG" ]]; then
    : >"$MCP_JSONLINE_BRIDGE_LOG" 2>/dev/null || true
  fi
fi

# 在 workspace-write 沙箱下，原始 CODEX_HOME（通常位于 /home）不可写会引发 rollout/channel 异常。
# 这里复制最小认证态到可写 runtime 目录，避免阶段性假失败。
if [[ -n "$SOURCE_CODEX_HOME" && "$SOURCE_CODEX_HOME" != "$CODEX_RUNTIME_HOME" ]]; then
  mkdir -p "$CODEX_RUNTIME_HOME"
  chmod 700 "$CODEX_RUNTIME_HOME" 2>/dev/null || true
  copied_any=0
  for f in auth.json config.toml version.json .personality_migration; do
    if [[ -f "$SOURCE_CODEX_HOME/$f" ]]; then
      cp -f "$SOURCE_CODEX_HOME/$f" "$CODEX_RUNTIME_HOME/$f" 2>/dev/null || true
      copied_any=1
    fi
  done
  if [[ "$copied_any" == "1" ]]; then
    export CODEX_HOME="$CODEX_RUNTIME_HOME"
  fi
fi

# 保证当前工作区被标记为 trusted，避免 mcp 在 exec 中被禁用（表现为 "mcp startup: no servers"）。
ACTIVE_CODEX_HOME="${CODEX_HOME:-$SOURCE_CODEX_HOME}"
if [[ -n "$ACTIVE_CODEX_HOME" ]]; then
  mkdir -p "$ACTIVE_CODEX_HOME" 2>/dev/null || true
  CFG_PATH="$ACTIVE_CODEX_HOME/config.toml"
  touch "$CFG_PATH" 2>/dev/null || true
  if [[ -w "$CFG_PATH" ]] && ! grep -F "[projects.\"$ROOT_DIR\"]" "$CFG_PATH" >/dev/null 2>&1; then
    printf '\n[projects."%s"]\ntrust_level = "trusted"\n' "$ROOT_DIR" >> "$CFG_PATH"
  fi
fi

if [[ "$DIRGE_DISABLE_MCP" != "1" ]]; then
  LOCK_A="$GHIDRA_MCP_PROJECT_PATH/$GHIDRA_MCP_PROJECT_NAME.lock"
  LOCK_B="$GHIDRA_MCP_PROJECT_PATH/$GHIDRA_MCP_PROJECT_NAME.lock~"
  if [[ "$GHIDRA_MCP_FORCE_UNLOCK" == "1" ]]; then
    if [[ -f "$LOCK_A" || -f "$LOCK_B" ]]; then
      if ! pgrep -fa "pyghidra-mcp.*$GHIDRA_MCP_PROJECT_PATH" >/dev/null 2>&1; then
        rm -f "$LOCK_A" "$LOCK_B" || true
        echo "[codex_with_mcp] removed stale ghidra lock files" >&2
      fi
    fi
  fi
fi

# 保留进程级变量用于本地调试命令复用。
export GHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR_VALUE"
export HOME="$GHIDRA_MCP_HOME"
export XDG_CONFIG_HOME="$GHIDRA_MCP_XDG_CONFIG_HOME"
export XDG_CACHE_HOME="$GHIDRA_MCP_XDG_CACHE_HOME"
export TMPDIR="${TMPDIR:-/tmp}"
export PYTHONPATH="$PYGHIDRA_MCP_PYTHONPATH"
export PYGHIDRA_CHROMA_FALLBACK="1"
export JAVA_TOOL_OPTIONS="$JAVA_TOOL_OPTIONS_VALUE"

if [[ "$DIRGE_DISABLE_MCP" == "1" ]]; then
  exec "$CODEX_BIN" \
    -C "$ROOT_DIR" \
    -c 'approval_policy="never"' \
    -c 'sandbox_mode="workspace-write"' \
    -c 'sandbox_workspace_write.network_access=true' \
    -c 'web_search="disabled"' \
    "$@"
fi

exec "$CODEX_BIN" \
  -C "$ROOT_DIR" \
  -c 'approval_policy="never"' \
  -c 'sandbox_mode="workspace-write"' \
  -c 'sandbox_workspace_write.network_access=true' \
  -c 'web_search="disabled"' \
  -c "mcp_servers.$PYGHIDRA_SERVER_NAME.command=\"$PYTHON_BIN\"" \
  -c "mcp_servers.$PYGHIDRA_SERVER_NAME.args=[\"$MCP_JSONLINE_BRIDGE\",\"--\",\"$GHIDRA_MCP_BIN\",\"--project-path\",\"$GHIDRA_MCP_PROJECT_PATH\",\"--project-name\",\"$GHIDRA_MCP_PROJECT_NAME\",\"-t\",\"stdio\"]" \
  -c "mcp_servers.$PYGHIDRA_SERVER_NAME.startup_timeout_sec=55" \
  -c "mcp_servers.$PYGHIDRA_SERVER_NAME.env={GHIDRA_INSTALL_DIR=\"$GHIDRA_INSTALL_DIR_VALUE\",HOME=\"$GHIDRA_MCP_HOME\",XDG_CONFIG_HOME=\"$GHIDRA_MCP_XDG_CONFIG_HOME\",XDG_CACHE_HOME=\"$GHIDRA_MCP_XDG_CACHE_HOME\",MCP_JSONLINE_BRIDGE_LOG=\"$MCP_JSONLINE_BRIDGE_LOG\",PYTHONPATH=\"$PYGHIDRA_MCP_PYTHONPATH\",PYGHIDRA_CHROMA_FALLBACK=\"1\",JAVA_TOOL_OPTIONS=\"$JAVA_TOOL_OPTIONS_VALUE\",DISPLAY=\"\"}" \
  -c "mcp_servers.$PYGHIDRA_SERVER_NAME.enabled=true" \
  -c 'mcp_servers.ida-pro-mcp.transport="stdio"' \
  -c 'mcp_servers.ida-pro-mcp.command="/usr/bin/python3"' \
  -c 'mcp_servers.ida-pro-mcp.args=["-m","ida_pro_mcp.server","--ida-rpc","http://127.0.0.1:13337"]' \
  -c 'mcp_servers.ida-pro-mcp.enabled=false' \
  -c 'mcp_servers.gdb.command="/home/zenduk/桌面/mcp/GDB-MCP/.venv/bin/python"' \
  -c 'mcp_servers.gdb.args=["server.py"]' \
  -c 'mcp_servers.gdb.cwd="/home/zenduk/桌面/mcp/GDB-MCP"' \
  -c 'mcp_servers.gdb.enabled=true' \
  "$@"
