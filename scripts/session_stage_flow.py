#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Set

from session_loop_policy import (
    evaluate_stage_failure_flow,
    update_codex_unhealthy_state,
    update_timeout_circuit_state,
)


@dataclass(frozen=True)
class PostStageFlowOutcome:
    loop_l0_timeout_like_failure: bool
    terminal_attempted_this_loop: bool
    should_continue: bool
    should_break: bool


def apply_post_stage_flow(
    *,
    ok: bool,
    stage: str,
    err: str,
    log_rel: str,
    log_abs: str,
    state_path: str,
    session_id: str,
    loop_idx: int,
    loop_end: int,
    terminal_stage: str,
    loop_stage_order: List[str],
    stop_on_stage_failure: bool,
    fuse_triggered: bool,
    force_terminal_stage: bool,
    exploit_rewrite_enabled: bool,
    enable_exploit: bool,
    failure_category: str,
    loop_l0_timeout_like_failure: bool,
    skip_static_stages_this_loop: Set[str],
    notes: List[str],
    metrics: Any,
    stage_timeout_circuit_enabled: bool,
    stage_timeout_circuit_stages: Set[str],
    stage_timeout_circuit_failure_categories: Set[str],
    stage_timeout_failure_streak: Dict[str, int],
    stage_timeout_skip_remaining: Dict[str, int],
    stage_timeout_circuit_consecutive_failures: int,
    stage_timeout_circuit_cooldown_loops: int,
    codex_unhealthy_enabled: bool,
    codex_unhealthy_stages: Set[str],
    codex_unhealthy_failure_categories: Set[str],
    codex_unhealthy_failure_streak: Dict[str, int],
    codex_unhealthy_skip_remaining: Dict[str, int],
    codex_unhealthy_consecutive_failures: int,
    codex_unhealthy_cooldown_loops: int,
    ida_fail_open_enabled: bool,
    ida_fail_open_categories: Set[str],
    ida_fail_open_write_blocker: bool,
    auto_continue_mcp_failure_set: Set[str],
    append_file_fn: Callable[[str, str], None],
    write_ida_dual_evidence_bundle_fn: Callable[[str, str, int], str],
    write_ida_blocker_report_fn: Callable[..., str],
) -> PostStageFlowOutcome:
    timeout_circuit_update = update_timeout_circuit_state(
        enabled=stage_timeout_circuit_enabled,
        ok=ok,
        stage=stage,
        failure_category=failure_category,
        enabled_stages=set(stage_timeout_circuit_stages),
        failure_categories=set(stage_timeout_circuit_failure_categories),
        failure_streak=stage_timeout_failure_streak,
        skip_remaining_loops=stage_timeout_skip_remaining,
        consecutive_failures=stage_timeout_circuit_consecutive_failures,
        cooldown_loops=stage_timeout_circuit_cooldown_loops,
        loop_idx=loop_idx,
        loop_end=loop_end,
        gdb_evidence_successes=int(metrics.stage_success.get("gdb_evidence", 0) or 0),
    )
    if timeout_circuit_update.activated:
        metrics.timeout_circuit_activations += 1
        append_file_fn(log_abs, f"[run_session] {timeout_circuit_update.note}\n")

    codex_unhealthy_update = update_codex_unhealthy_state(
        enabled=codex_unhealthy_enabled,
        ok=ok,
        stage=stage,
        failure_category=failure_category,
        enabled_stages=set(codex_unhealthy_stages),
        failure_categories=set(codex_unhealthy_failure_categories),
        failure_streak=codex_unhealthy_failure_streak,
        skip_remaining_loops=codex_unhealthy_skip_remaining,
        consecutive_failures=codex_unhealthy_consecutive_failures,
        cooldown_loops=codex_unhealthy_cooldown_loops,
    )
    if codex_unhealthy_update.activated:
        append_file_fn(log_abs, f"[run_session] {codex_unhealthy_update.note}\n")

    if ok and stage in {"ida_slice", "gdb_evidence"}:
        ida_dual_rel = write_ida_dual_evidence_bundle_fn(state_path, session_id, loop_idx)
        if ida_dual_rel:
            append_file_fn(log_abs, f"[run_session] ida dual evidence bundle -> {ida_dual_rel}\n")

    terminal_attempted_this_loop = bool(stage == terminal_stage)
    next_loop_l0_timeout_like_failure = bool(loop_l0_timeout_like_failure)
    if ok or (not stop_on_stage_failure):
        return PostStageFlowOutcome(
            loop_l0_timeout_like_failure=next_loop_l0_timeout_like_failure,
            terminal_attempted_this_loop=terminal_attempted_this_loop,
            should_continue=False,
            should_break=False,
        )

    stage_failure_flow = evaluate_stage_failure_flow(
        stage=stage,
        failure_category=failure_category,
        stop_on_stage_failure=stop_on_stage_failure,
        fuse_triggered=fuse_triggered,
        ida_fail_open_enabled=ida_fail_open_enabled,
        ida_fail_open_categories=set(ida_fail_open_categories),
        ida_fail_open_write_blocker=ida_fail_open_write_blocker,
        auto_continue_mcp_failure_set=set(auto_continue_mcp_failure_set),
        exploit_rewrite_enabled=exploit_rewrite_enabled,
        enable_exploit=enable_exploit,
        terminal_stage=terminal_stage,
        loop_stage_order=list(loop_stage_order),
        force_terminal_stage=force_terminal_stage,
    )
    blocker_rel = ""
    if stage_failure_flow.loop_l0_timeout_like_failure:
        next_loop_l0_timeout_like_failure = True
    for st_next in stage_failure_flow.skip_static_stages:
        skip_static_stages_this_loop.add(st_next)
    if stage_failure_flow.skip_static_stages and skip_static_stages_this_loop:
        notes.append("static-stage cooldown in-loop: " + ",".join(sorted(skip_static_stages_this_loop)))
    if stage_failure_flow.write_ida_blocker:
        blocker_rel = write_ida_blocker_report_fn(
            state_path=state_path,
            session_id=session_id,
            loop_idx=loop_idx,
            reason=err or failure_category,
            log_rel=log_rel,
        )
    if stage_failure_flow.note:
        note = stage_failure_flow.note
        if blocker_rel:
            note += f" [{blocker_rel}]"
        notes.append(note)
    return PostStageFlowOutcome(
        loop_l0_timeout_like_failure=next_loop_l0_timeout_like_failure,
        terminal_attempted_this_loop=terminal_attempted_this_loop,
        should_continue=bool(stage_failure_flow.action == "continue"),
        should_break=bool(stage_failure_flow.action == "break"),
    )
