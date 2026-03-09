#!/usr/bin/env python3
from __future__ import annotations

from .base import MCPAdapter


class GDBAdapter(MCPAdapter):
    name = "gdb_mcp_via_codex"

    def build_prompt(self, context):
        return (
            "请基于 MCP-only 执行 L2 GDB Evidence。"
            "必须更新 state.dynamic_evidence 与 artifacts/gdb。"
            "禁止仓库遍历/环境排查命令（ls/rg/find/sed/cat/ps/kill）。"
            f"会话ID: {context.get('session_id','')}。"
            f"二进制: {context.get('binary_path','')}。"
            "必须提取 mappings.pie_base 并写入 state.latest_bases.pie_base。"
        )
