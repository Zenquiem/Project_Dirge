#!/usr/bin/env bash
set -euo pipefail

echo "[pwn-gdb-evidence] MCP-only mode." >&2
echo "[pwn-gdb-evidence] 本地 gdb 批处理路径已停用，请在 Codex 会话中通过 GDB MCP 采集并更新 state/artifacts。" >&2
echo "[pwn-gdb-evidence] 旧实现位置: legacy/skills/pwn-gdb-evidence/run.sh" >&2
exit 2
