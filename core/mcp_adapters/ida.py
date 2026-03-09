#!/usr/bin/env python3
from __future__ import annotations

from .base import MCPAdapter


class IDAAdapter(MCPAdapter):
    # 保持类名不变，仅为兼容现有调用链；静态后端已切到 Ghidra MCP。
    name = "static_slice_mcp_via_codex"

    def build_prompt(self, context):
        return (
            "请基于 MCP-only 执行 L1 静态切片（阶段名 ida_slice）。"
            "静态后端使用 pyghidra-mcp，优先最小工具链：import_binary -> decompile_function -> list_cross_references -> gen_callgraph。"
            "必须更新 state.static_analysis 与 artifacts/ida。"
            "禁止仓库遍历/环境排查命令（ls/rg/find/sed/cat/ps/kill）。"
            f"会话ID: {context.get('session_id','')}。"
            f"二进制: {context.get('binary_path','')}。"
            "输出需包含调用链、sink callsite、可验证 hypothesis（<=3）。"
        )
