#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class LoopDecision:
    stage_order: List[str]
    notes: List[str]


def exploit_stage_level(stage: str) -> int:
    s = str(stage).strip().lower()
    if not s.startswith("exploit_l"):
        return -1
    tail = s[len("exploit_l") :]
    return int(tail) if tail.isdigit() else -1


def terminal_exploit_stage(stages: List[str]) -> str:
    best = ""
    best_lv = -1
    for st in stages:
        lv = exploit_stage_level(st)
        if lv > best_lv:
            best_lv = lv
            best = st
    return best if best_lv >= 0 else ""


def strip_exploit_stages(stages: List[str]) -> List[str]:
    return [x for x in stages if exploit_stage_level(x) < 0]


def _dedup_keep_order(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def choose_stage_plan(
    base_stage_order: List[str],
    state: Dict[str, Any],
    no_progress_loops: int,
    decision_cfg: Dict[str, Any],
    enable_exploit: bool,
) -> LoopDecision:
    notes: List[str] = []
    order = [str(x) for x in base_stage_order]
    terminal_stage = terminal_exploit_stage(order)

    adaptive = bool(decision_cfg.get("enable_adaptive_stage_order", True))
    if not adaptive:
        if not enable_exploit:
            order = strip_exploit_stages(order)
        return LoopDecision(stage_order=_dedup_keep_order(order), notes=notes)

    protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    hypos = static.get("hypotheses", []) if isinstance(static.get("hypotheses", []), list) else []
    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
    capabilities = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}

    has_protections = bool(str(protections.get("arch", "")).strip()) and (protections.get("pie", None) is not None)
    has_hypotheses = len(hypos) > 0
    has_evidence = len(evid) > 0
    has_crash = bool(capabilities.get("has_crash", False))
    crash_stable = bool(capabilities.get("crash_stable", False))
    control_rip = bool(capabilities.get("control_rip", False)) or str(capabilities.get("rip_control", "")).strip().lower() == "yes"

    skip_recon_if_known = bool(decision_cfg.get("skip_recon_if_protections_known", True))
    prefer_gdb_when_hypos = bool(decision_cfg.get("prefer_gdb_when_hypotheses_exist", True))
    force_ida_after_no_progress = int(decision_cfg.get("force_ida_after_no_progress_loops", 2) or 2)
    prioritize_gdb_when_crash_unstable = bool(decision_cfg.get("prioritize_gdb_when_crash_unstable", True))
    prefer_exploit_when_rip_control = bool(decision_cfg.get("prefer_exploit_when_rip_control", True))

    if skip_recon_if_known and has_protections and "recon" in order:
        order = [x for x in order if x != "recon"]
        notes.append("protections 已知，跳过 recon")

    if has_hypotheses and prefer_gdb_when_hypos and "gdb_evidence" in order and "ida_slice" in order:
        ida_idx = order.index("ida_slice")
        gdb_idx = order.index("gdb_evidence")
        if gdb_idx > ida_idx:
            order.pop(gdb_idx)
            order.insert(ida_idx, "gdb_evidence")
            notes.append("已有 hypotheses，优先 gdb_evidence")

    if (not has_hypotheses) and "ida_slice" in order and "gdb_evidence" in order:
        ida_idx = order.index("ida_slice")
        gdb_idx = order.index("gdb_evidence")
        if ida_idx > gdb_idx:
            order.pop(ida_idx)
            order.insert(gdb_idx, "ida_slice")
            notes.append("hypotheses 为空，优先 ida_slice")

    if (not has_evidence) and "gdb_evidence" in order:
        notes.append("evidence 为空，本轮保留 gdb_evidence")

    if has_crash and (not crash_stable) and prioritize_gdb_when_crash_unstable and "gdb_evidence" in order:
        order = [x for x in order if x != "gdb_evidence"]
        order.insert(0, "gdb_evidence")
        notes.append("crash 尚不稳定，前置 gdb_evidence 以补充聚类样本")

    if control_rip and enable_exploit and prefer_exploit_when_rip_control and terminal_stage:
        order = [x for x in order if x != terminal_stage]
        insert_at = len(order)
        if "gdb_evidence" in order:
            insert_at = order.index("gdb_evidence") + 1
        order.insert(insert_at, terminal_stage)
        notes.append(f"已具备 RIP 控制信号，提前 {terminal_stage} 生成/校验本地脚本")

    if no_progress_loops >= force_ida_after_no_progress and "ida_slice" in order:
        order = [x for x in order if x != "ida_slice"]
        order.insert(0, "ida_slice")
        notes.append(f"连续无进展 {no_progress_loops} 轮，强制 ida_slice 前置")

    if terminal_stage and (not control_rip or not prefer_exploit_when_rip_control):
        order = [x for x in order if x != terminal_stage] + [terminal_stage]
    if not enable_exploit:
        order = strip_exploit_stages(order)

    return LoopDecision(stage_order=_dedup_keep_order(order), notes=notes)
