#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, List


@dataclass(frozen=True)
class HintGateEvaluation:
    triggered: bool
    rewrite_triggered: bool
    reasons: List[str]


@dataclass(frozen=True)
class TimeoutGateEvaluation:
    applicable: bool
    triggered: bool
    blind_mode: bool
    timeout_streak: int
    reason: str


@dataclass(frozen=True)
class ExploitRewriteStopEvaluation:
    stop_reason: str
    keep_rewriting_note: str


@dataclass(frozen=True)
class LoopControlDecision:
    should_break: bool
    note: str


@dataclass(frozen=True)
class StageFailureFlowDecision:
    action: str
    note: str
    skip_static_stages: list[str]
    loop_l0_timeout_like_failure: bool
    write_ida_blocker: bool


@dataclass(frozen=True)
class CooldownUpdateDecision:
    activated: bool
    note: str


def evaluate_hint_gate(
    *,
    enabled: bool,
    loop_terminal_unsolved: bool,
    no_progress_loops: int,
    no_progress_threshold: int,
    no_new_evidence_sec: float,
    no_new_evidence_threshold: float,
    rewrite_elapsed_sec: float,
    rewrite_request_hint_after_wall_sec: float,
    loop_idx: int,
    last_trigger_loop: int,
) -> HintGateEvaluation:
    reasons: List[str] = []
    rewrite_triggered = False
    if enabled and loop_terminal_unsolved:
        if no_progress_threshold > 0 and no_progress_loops >= no_progress_threshold:
            reasons.append(f"no_progress_loops={no_progress_loops}>={no_progress_threshold}")
        if no_new_evidence_threshold > 0 and no_new_evidence_sec >= no_new_evidence_threshold:
            reasons.append(f"no_new_evidence={int(no_new_evidence_sec)}s>={int(no_new_evidence_threshold)}s")
        if rewrite_request_hint_after_wall_sec > 0 and rewrite_elapsed_sec >= rewrite_request_hint_after_wall_sec:
            rewrite_triggered = True
            reasons.append(
                "exploit_rewrite_elapsed="
                f"{int(rewrite_elapsed_sec)}s>={int(rewrite_request_hint_after_wall_sec)}s"
            )
    triggered = bool(reasons and loop_idx != last_trigger_loop)
    return HintGateEvaluation(triggered=triggered, rewrite_triggered=rewrite_triggered, reasons=reasons)


def evaluate_timeout_no_evidence_gate(
    *,
    enabled: bool,
    loop_rc124_failures: int,
    blind_mode: bool,
    blind_only: bool,
    require_no_progress: bool,
    loop_progress: bool,
    prev_timeout_streak: int,
    consecutive_loops: int,
) -> TimeoutGateEvaluation:
    applicable = bool(enabled and int(loop_rc124_failures or 0) > 0)
    if applicable and blind_only and (not blind_mode):
        applicable = False
    if applicable and require_no_progress and loop_progress:
        applicable = False

    timeout_streak = int(prev_timeout_streak or 0) + 1 if applicable else 0
    triggered = bool(applicable and timeout_streak >= int(consecutive_loops or 0))
    reason = ""
    if triggered:
        reason = (
            f"consecutive rc=124 timeout loops={timeout_streak}>="
            f"{int(consecutive_loops or 0)} with no-evidence progress"
        )
    return TimeoutGateEvaluation(
        applicable=applicable,
        triggered=triggered,
        blind_mode=bool(blind_mode),
        timeout_streak=timeout_streak,
        reason=reason,
    )


def evaluate_exploit_rewrite_stop(
    *,
    rewrite_elapsed_sec: float,
    max_wall_sec: float,
    same_error_streak: int,
    same_error_limit: int,
    last_error: str,
    non_actionable_verify_streak: int,
    non_actionable_verify_limit: int,
    extra_used: int,
    extra_loops_budget: int,
    is_timeout_like_error: Callable[[str], bool],
) -> ExploitRewriteStopEvaluation:
    keep_rewriting_note = ""
    if max_wall_sec > 0 and rewrite_elapsed_sec >= max_wall_sec:
        return ExploitRewriteStopEvaluation(
            stop_reason=f"exploit rewrite wall-time limit hit: {rewrite_elapsed_sec:.1f}s >= {max_wall_sec:.1f}s",
            keep_rewriting_note="",
        )
    if same_error_limit > 0 and same_error_streak >= same_error_limit:
        if is_timeout_like_error(last_error):
            keep_rewriting_note = "same-error streak reached but error is timeout-like; keep rewriting until wall/loop budget"
        else:
            return ExploitRewriteStopEvaluation(
                stop_reason=(
                    "exploit rewrite same-error streak limit hit: "
                    f"{same_error_streak}>={same_error_limit}"
                ),
                keep_rewriting_note="",
            )
    if non_actionable_verify_limit > 0 and non_actionable_verify_streak >= non_actionable_verify_limit:
        return ExploitRewriteStopEvaluation(
            stop_reason=(
                "exploit rewrite non-actionable verify streak limit hit: "
                f"{non_actionable_verify_streak}>={non_actionable_verify_limit}"
            ),
            keep_rewriting_note=keep_rewriting_note,
        )
    if extra_loops_budget >= 0 and extra_used >= extra_loops_budget:
        return ExploitRewriteStopEvaluation(
            stop_reason=f"exploit rewrite extra-loops limit hit: {extra_used}>={extra_loops_budget}",
            keep_rewriting_note=keep_rewriting_note,
        )
    return ExploitRewriteStopEvaluation(stop_reason="", keep_rewriting_note=keep_rewriting_note)


def evaluate_objective_stop(
    *,
    objective_enabled: bool,
    objective_stop_on_achieved: bool,
    target_achieved: bool,
    force_terminal_stage: bool,
    terminal_attempted_this_loop: bool,
    terminal_stage: str,
    score: int,
) -> LoopControlDecision:
    if not (objective_enabled and objective_stop_on_achieved and target_achieved):
        return LoopControlDecision(should_break=False, note="")
    if force_terminal_stage and (not terminal_attempted_this_loop):
        return LoopControlDecision(
            should_break=False,
            note=f"目标达成，但本轮未触达 {terminal_stage}，继续下一轮",
        )
    return LoopControlDecision(
        should_break=True,
        note=f"目标达成，提前停止 (score={score})",
    )


def evaluate_no_progress_stop(
    *,
    no_progress_loops: int,
    stop_after_no_progress: int,
    force_terminal_stage: bool,
    terminal_attempted_this_loop: bool,
    terminal_stage: str,
    exploit_rewrite_enabled: bool,
    loop_terminal_unsolved: bool,
) -> LoopControlDecision:
    if no_progress_loops < stop_after_no_progress:
        return LoopControlDecision(should_break=False, note="")
    if force_terminal_stage and (not terminal_attempted_this_loop):
        return LoopControlDecision(
            should_break=False,
            note=f"连续无进展，但本轮未触达 {terminal_stage}，继续下一轮",
        )
    if exploit_rewrite_enabled and loop_terminal_unsolved:
        return LoopControlDecision(
            should_break=False,
            note=f"连续 {stop_after_no_progress} 轮无新增 evidence/hypothesis，但 exploit 未验证成功，继续重写",
        )
    return LoopControlDecision(
        should_break=True,
        note=f"连续 {stop_after_no_progress} 轮无新增 evidence/hypothesis，提前停止",
    )


def evaluate_stage_failure_stop(
    *,
    stage_failed: bool,
    stop_on_stage_failure: bool,
    force_terminal_stage: bool,
    terminal_attempted_this_loop: bool,
    terminal_stage: str,
    exploit_rewrite_enabled: bool,
    enable_exploit: bool,
) -> LoopControlDecision:
    if not (stage_failed and stop_on_stage_failure):
        return LoopControlDecision(should_break=False, note="")
    if force_terminal_stage and terminal_attempted_this_loop:
        return LoopControlDecision(should_break=False, note=f"{terminal_stage} 已执行，本轮结束")
    if exploit_rewrite_enabled and enable_exploit and terminal_stage:
        return LoopControlDecision(should_break=False, note="本轮阶段失败但仍未完成 exploit rewrite 预算，继续下一轮")
    return LoopControlDecision(should_break=True, note="")


def evaluate_stage_failure_flow(
    *,
    stage: str,
    failure_category: str,
    stop_on_stage_failure: bool,
    fuse_triggered: bool,
    ida_fail_open_enabled: bool,
    ida_fail_open_categories: set[str],
    ida_fail_open_write_blocker: bool,
    auto_continue_mcp_failure_set: set[str],
    exploit_rewrite_enabled: bool,
    enable_exploit: bool,
    terminal_stage: str,
    loop_stage_order: list[str],
    force_terminal_stage: bool,
) -> StageFailureFlowDecision:
    if not stop_on_stage_failure:
        return StageFailureFlowDecision("none", "", [], False, False)
    if fuse_triggered:
        return StageFailureFlowDecision("break", "成本熔断触发，停止后续阶段", [], False, False)
    if stage == "ida_slice" and ida_fail_open_enabled and (failure_category in ida_fail_open_categories):
        return StageFailureFlowDecision(
            "continue",
            f"ida_slice 失败({failure_category})，fail-open 继续到后续阶段",
            [],
            False,
            bool(ida_fail_open_write_blocker),
        )
    if failure_category == "mcp_transient" and stage in auto_continue_mcp_failure_set:
        return StageFailureFlowDecision(
            "continue",
            f"{stage} 发生 mcp_transient，按恢复策略继续后续阶段",
            [],
            False,
            False,
        )
    if failure_category in {"mcp_transient", "timeout"}:
        loop_l0_timeout_like_failure = stage in {"recon", "ida_slice", "gdb_evidence"}
        skip_static_stages: list[str] = []
        if stage in {"recon", "ida_slice"}:
            skip_static_stages = [
                st_next
                for st_next in loop_stage_order
                if st_next != stage and st_next in {"recon", "ida_slice"}
            ]
        if (
            exploit_rewrite_enabled
            and enable_exploit
            and terminal_stage
            and stage != terminal_stage
            and terminal_stage in loop_stage_order
        ):
            return StageFailureFlowDecision(
                "continue",
                f"{stage} 失败({failure_category})，rewrite 模式继续推进到 {terminal_stage}",
                skip_static_stages,
                loop_l0_timeout_like_failure,
                False,
            )
        return StageFailureFlowDecision(
            "break",
            f"{stage} 失败({failure_category})，停止后续阶段以避免无效等待",
            skip_static_stages,
            loop_l0_timeout_like_failure,
            False,
        )
    if force_terminal_stage and stage != terminal_stage and terminal_stage in loop_stage_order:
        return StageFailureFlowDecision(
            "continue",
            f"{stage} 失败，但继续推进到 {terminal_stage}",
            [],
            False,
            False,
        )
    return StageFailureFlowDecision("break", "", [], False, False)

def update_timeout_circuit_state(
    *,
    enabled: bool,
    ok: bool,
    stage: str,
    failure_category: str,
    enabled_stages: set[str],
    failure_categories: set[str],
    failure_streak: Dict[str, int],
    skip_remaining_loops: Dict[str, int],
    consecutive_failures: int,
    cooldown_loops: int,
    loop_idx: int,
    loop_end: int,
    gdb_evidence_successes: int,
) -> CooldownUpdateDecision:
    if not (enabled and (stage in enabled_stages)):
        return CooldownUpdateDecision(False, "")
    if (not ok) and (failure_category in failure_categories):
        streak_now = int(failure_streak.get(stage, 0) or 0) + 1
        failure_streak[stage] = streak_now
        if streak_now >= consecutive_failures:
            prev_remain = int(skip_remaining_loops.get(stage, 0) or 0)
            skip_remaining_loops[stage] = max(prev_remain, cooldown_loops)
            if stage in {"recon", "ida_slice"} and streak_now >= 2 and int(gdb_evidence_successes or 0) > 0:
                skip_remaining_loops[stage] = max(
                    int(skip_remaining_loops.get(stage, 0) or 0),
                    max(1, loop_end - loop_idx + 1),
                )
            if prev_remain <= 0:
                return CooldownUpdateDecision(
                    True,
                    "timeout circuit armed: "
                    f"stage={stage} streak={streak_now} cooldown_loops={skip_remaining_loops[stage]}",
                )
    else:
        failure_streak[stage] = 0
    return CooldownUpdateDecision(False, "")


def update_codex_unhealthy_state(
    *,
    enabled: bool,
    ok: bool,
    stage: str,
    failure_category: str,
    enabled_stages: set[str],
    failure_categories: set[str],
    failure_streak: Dict[str, int],
    skip_remaining_loops: Dict[str, int],
    consecutive_failures: int,
    cooldown_loops: int,
) -> CooldownUpdateDecision:
    if not (enabled and (stage in enabled_stages)):
        return CooldownUpdateDecision(False, "")
    if (not ok) and (failure_category in failure_categories):
        streak_now = int(failure_streak.get(stage, 0) or 0) + 1
        failure_streak[stage] = streak_now
        if streak_now >= consecutive_failures:
            prev_remain = int(skip_remaining_loops.get(stage, 0) or 0)
            skip_remaining_loops[stage] = max(prev_remain, cooldown_loops)
            if prev_remain <= 0:
                return CooldownUpdateDecision(
                    True,
                    "codex unhealthy cooldown armed: "
                    f"stage={stage} streak={streak_now} cooldown_loops={skip_remaining_loops[stage]}",
                )
    else:
        failure_streak[stage] = 0
    return CooldownUpdateDecision(False, "")

