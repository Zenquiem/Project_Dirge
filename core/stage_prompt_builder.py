from __future__ import annotations

import os
from typing import Callable, Dict


def build_stage_prompt(
    stage: str,
    context: Dict[str, str],
    *,
    root_dir: str,
    ida_prompt_builder: Callable[[Dict[str, str]], str],
    gdb_prompt_builder: Callable[[Dict[str, str]], str],
    exploit_stage_level_fn: Callable[[str], int],
    contract_hint: str = "",
) -> str:
    extra = f" {contract_hint.strip()}" if contract_hint.strip() else ""
    digest = str(context.get("state_digest", "")).strip()
    digest_hint = f" 当前状态摘要: {digest}。" if digest else ""
    bin_rel = str(context.get("binary_path", "")).strip()
    bin_abs = str(context.get("binary_path_abs", "")).strip()
    if (not bin_abs) and bin_rel:
        if os.path.isabs(bin_rel):
            bin_abs = bin_rel
        else:
            bin_abs = os.path.abspath(os.path.join(root_dir, bin_rel))

    strict_mcp_hint = (
        "仅允许 MCP 调用与最小落盘；禁止仓库遍历/环境排查命令"
        "（ls/rg/find/sed/cat/ps/kill/history）。"
        "禁止先做 MCP 资源探测（list_mcp_resources/list_mcp_resource_templates）。"
        "直接调用本阶段约定工具并在一次回复内完成。"
        "禁止调用 session_api.py stop 或写 stop.requested.json。"
    )

    if stage == "bundle_l0_l4":
        return (
            "一次完成 L0->L2（MCP-only，最小查询）。"
            "仅保留必要证据：protections、hypotheses、pie_base、evidence_id。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN={context.get('binary_path','')}。"
            f"{digest_hint}{extra}"
        )

    if stage == "bundle_l0_l2":
        return (
            "一次完成 L0->L2（MCP-only，最小查询）。"
            "必须更新 protections/io_profile/static_analysis/dynamic_evidence/latest_bases.pie_base。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN={context.get('binary_path','')}。"
            f"{digest_hint}{extra}"
        )

    if stage == "recon":
        return (
            "执行 L0 Recon（MCP-only，禁止大输出）。"
            "仅收集 protections 与 IO 轮廓，避免重复探测。"
            "按固定顺序执行："
            "1) import_binary(binary_path)；"
            "2) list_project_binaries（按 file_path 精确匹配拿 canonical binary_name）；"
            "若第2步未匹配到目标，允许再调用一次 list_project_binaries 刷新后继续。"
            "若第二次仍未匹配，直接选 basename 相同的最新条目作为 canonical binary_name 并继续，不再刷新。"
            "3) list_project_binary_metadata(binary_name)；"
            "4) import-ready 门控：若 metadata.analysis_complete!=true，轮询 metadata（最多 3 次）直到 true；"
            "若仍为 false，立即以 'analysis pending' 失败返回，不要继续切片相关调用。"
            "5) list_imports(binary_name, query='puts|system|read|gets|fgets|scanf|printf|__stack_chk_fail|setvbuf|alarm|signal|write', limit<=24)。"
            "禁止重试同一失败参数，禁止额外工具扩展。"
            "调用预算：最多 7 次 MCP 调用，拿到最小证据后立即结束。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN_REL={bin_rel} BIN_ABS={bin_abs}。"
            f"{digest_hint}{extra}"
        )

    if stage == "ida_slice":
        base = ida_prompt_builder(context)
        base += (
            " 切片前必须校验 import-ready：list_project_binary_metadata(canonical binary_name) 且 analysis_complete=true；"
            " 若不满足，直接返回 'analysis pending' 并结束本阶段，禁止盲目反编译重试。"
            " 先生成或复用 symbol_map（name->0xaddr），后续 xref/callsite 查询优先使用 address。"
            " 对歧义符号禁止反复按名字重试，必须切到 0x 地址查询。"
        )
        sym_map = str(context.get("symbol_map", "")).strip()
        if sym_map:
            base += f" 已有 symbol_map: {sym_map}。"
        active_hids = str(context.get("active_hypothesis_ids", "")).strip()
        if active_hids:
            base += f" 当前活跃 hypothesis: {active_hids}。"
        if digest_hint:
            base += digest_hint
        if extra:
            base += extra
        return base

    if stage == "gdb_evidence":
        base = gdb_prompt_builder(context)
        base += " 限制输出：回溯<=8帧，栈窗<=32 qword，仅关键寄存器与 mappings。"
        repl_hint = str(context.get("repl_cmd_exec_hint", "")).strip().lower() in {"1", "true", "yes"}
        if repl_hint:
            base += (
                " 目标疑似 REPL/命令执行：不要默认 cyclic 崩溃探测。"
                "优先验证输入语义/回显边界、可执行表达式形态、命令执行路径（如 child_process/exec/eval）与输出噪声过滤。"
            )
        mutation_manifest = str(context.get("mutation_manifest", "")).strip()
        mutation_ids = str(context.get("mutation_input_ids", "")).strip()
        if mutation_manifest:
            base += f" 本轮输入变异清单: {mutation_manifest}。"
        if mutation_ids:
            base += f" 请优先尝试输入 ID: {mutation_ids}。"
        if digest_hint:
            base += digest_hint
        if extra:
            base += extra
        return base

    if exploit_stage_level_fn(stage) >= 0:
        allow_remote_exp = str(context.get("allow_remote_exp", "")).strip().lower() in {"1", "true", "yes"}
        repl_hint = str(context.get("repl_cmd_exec_hint", "")).strip().lower() in {"1", "true", "yes"}
        nxoff_hint = str(context.get("nxoff_libc_free_hint", "")).strip().lower() in {"1", "true", "yes"}
        remote_hint = (
            "允许在脚本里预留远程连接参数（host/port），但自动流程不主动远程交互。"
            if allow_remote_exp
            else "仅写本地脚本，不做远程交互。"
        )
        repl_extra = ""
        if repl_hint:
            repl_extra = (
                " 题型疑似 JS/REPL 命令执行：优先生成表达式注入链（console.log/require('child_process').execSync）。"
                "先打 marker 再读 flag，默认同时尝试 /flag、flag、./flag；避免依赖 /bin/bash。"
            )
        nxoff_extra = ""
        if nxoff_hint:
            nxoff_extra = (
                " 目标疑似 NX=off 且已可控 RIP：优先输出不依赖 libc 基址的可执行链"
                "（direct_execve/ret2win/短链），不要先盲打 ret2libc 偏移。"
            )
        return (
            f"请基于已有证据执行 {stage} 阶段并更新本地 exp 文件。"
            f"会话ID: {context.get('session_id','')}。"
            f"二进制: {context.get('binary_path','')}。"
            f"exp 路径: {context.get('exp_path','')}。"
            "优先保证环境同构：若题目目录可识别 loader/libc bundle，先按该对齐运行；"
            "若无 bundle 再回退 process(binary) 语义，并保持两种启动方式可切换。"
            "I/O 读取必须避免吞字节：recvuntil 超时分支不得清空未消费缓冲；"
            "关键泄露禁止用不稳定的 recvuntil+recvline 链式解析。"
            "泄露解析禁止写死长度阈值（例如 >=40）；必须按分隔符解析并兼容 32~64 字节波动。"
            "进入远程全链路前先核对关键偏移三元组（system/pop rdi/binsh）并输出校验日志。"
            "若存在 secret/校验字段，优先按明确终止符读取（例如 b'\\x01\\n'，drop=False）后再解析。"
            "若远端 stage1 频繁 EOF，先做 stage1 成功率基线测试；低于阈值时停止硬撞并请求额外提示。"
            "远端提示流可能不先发固定菜单，需支持主动发送轻量触发（如 n）并重同步。"
            "实现必须按里程碑逐点自检并输出可定位日志：libc leak -> secret leak -> fake meta 生效 -> 可分配到目标记录/栈地址。"
            "最终触发前，必须重新等待关键菜单提示（如 'Note:'）后再发最后一次分配；"
            "若提示缺失则立即停止并打印最近 I/O 窗口，不要盲目继续撞偏移。"
            "shell 成功判定以 marker/flag 输出为准，不要依赖 id 或 /dev/null 权限。"
            f"{repl_extra}"
            f"{nxoff_extra}"
            f"{remote_hint} 并更新 state.session.exp.status='updated'。"
            f"{digest_hint}{extra}"
        )

    raise RuntimeError(f"unknown stage: {stage}")
