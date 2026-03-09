#!/usr/bin/env bash
set -euo pipefail

echo "[pwn-ida-slice] MCP-only mode." >&2
echo "[pwn-ida-slice] 本地 objdump/fallback 路径已停用，请在 Codex 会话中通过 pyghidra-mcp 采集并更新 state/artifacts。" >&2
echo "[pwn-ida-slice] 兼容说明：阶段名 ida_slice 保留，静态后端已切换为 Ghidra MCP。" >&2
echo "[pwn-ida-slice] 旧实现位置: legacy/skills/pwn-ida-slice/run.sh" >&2
exit 2
