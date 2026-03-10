#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Set

from session_loop_policy import (
    evaluate_exploit_rewrite_stop,
    evaluate_hint_gate,
    evaluate_no_progress_stop,
    evaluate_objective_stop,
    evaluate_stage_failure_stop,
    evaluate_timeout_no_evidence_gate,
)
from session_strategy_route import apply_strategy_route_switch


@dataclass(frozen=True)
class LoopDecisionStateOutcome:
    no_progress_loops: int
    strategy_route_switch_count: int
    hint_gate_last_trigger_loop: int
    timeout_no_evidence_streak: int
    route_switch_applied: bool
    route_switch_report_rel: str
    hint_gate_triggered: bool
    rewrite_hint_gate_triggered: bool
    timeout_gate_triggered: bool


@dataclass(frozen=True)
class LoopStopDecisionOutcome:
    exploit_rewrite_stop_reason: str
    should_break: bool


def apply_loop_decision_state(
    *,
    after_loop_state: Dict[str, Any],
    state_path: str,
    session_id: str,
    loop_idx: int,
    terminal_stage: str,
    loop_stage_order: List[str],
    decision_report_rel: str,
    active_hypothesis_ids: List[str],
    notes: List[str],
    metrics: Any,
    post_obj: Any,
    loop_progress: bool,
    no_progress_loops: int,
    loop_terminal_unsolved: bool,
    terminal_unsolved_streak: int,
    no_new_evidence_sec: float,
    rewrite_elapsed_sec: float,
    hint_gate_enabled: bool,
    hint_gate_no_progress_loops: int,
    hint_gate_no_new_evidence_sec: float,
    exploit_rewrite_request_hint_after_wall_sec: float,
    hint_gate_last_trigger_loop: int,
    hint_gate_write_report: bool,
    hint_gate_stop_on_trigger: bool,
    exploit_rewrite_stop_on_request_hint: bool,
    timeout_gate_enabled: bool,
    timeout_gate_blind_only: bool,
    timeout_gate_require_no_progress: bool,
    timeout_gate_consecutive_loops: int,
    timeout_gate_write_report: bool,
    timeout_gate_stop_on_trigger: bool,
    timeout_no_evidence_streak: int,
    loop_rc124_failures: int,
    strategy_route_switch_enabled: bool,
    strategy_route_switch_no_progress_loops: int,
    strategy_route_switch_terminal_unsolved_loops: int,
    strategy_route_switch_weak_only: bool,
    exploit_precheck_weak_strategies: Set[str],
    strategy_route_switch_cycle: List[str],
    blind_mode_enabled: bool,
    blind_mode_route_switch_lock: bool,
    blind_mode_default_strategy_hint: str,
    strategy_route_switch_count: int,
    strategy_route_switch_reset_no_progress: bool,
    strategy_route_switch_request_hint_after: int,
    strategy_route_switch_write_report: bool,
    stage_timeout_circuit_enabled: bool,
    stage_timeout_circuit_stages: Set[str],
    stage_timeout_circuit_failure_categories: Set[str],
    stage_timeout_circuit_consecutive_failures: int,
    stage_timeout_circuit_cooldown_loops: int,
    stage_timeout_failure_streak: Dict[str, int],
    stage_timeout_skip_remaining: Dict[str, int],
    codex_unhealthy_enabled: bool,
    codex_unhealthy_stages: Set[str],
    codex_unhealthy_failure_categories: Set[str],
    codex_unhealthy_consecutive_failures: int,
    codex_unhealthy_cooldown_loops: int,
    codex_unhealthy_failure_streak: Dict[str, int],
    codex_unhealthy_skip_remaining: Dict[str, int],
    adaptive_stage_order_enabled: bool,
    detect_blind_mode_fn: Callable[[Dict[str, Any]], bool],
    detect_lua_runtime_exec_hint_fn: Callable[[Dict[str, Any]], bool],
    detect_repl_cmd_exec_hint_fn: Callable[[Dict[str, Any]], bool],
    write_strategy_route_switch_report_fn: Callable[..., str],
    write_hint_request_gate_report_fn: Callable[..., str],
    write_timeout_no_evidence_gate_report_fn: Callable[..., str],
    normalize_strategy_hint_fn: Callable[[Any], str],
    normalize_strategy_hint_cycle_fn: Callable[..., List[str]],
    pick_next_strategy_hint_fn: Callable[..., Any],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    sync_meta_fn: Callable[[str, Dict[str, Any]], None],
    utc_now_fn: Callable[[], str],
) -> LoopDecisionStateOutcome:
    progress = after_loop_state.setdefault("progress", {})
    progress["loop_seq"] = int(progress.get("loop_seq", 0) or 0) + 1
    decision_state = progress.setdefault("decision", {})
    decision_state["adaptive_stage_order"] = bool(adaptive_stage_order_enabled)
    decision_state["last_stage_plan"] = loop_stage_order
    decision_state["last_decision_report"] = decision_report_rel
    decision_state["last_active_hypothesis_ids"] = active_hypothesis_ids
    decision_state["last_loop_had_progress"] = bool(loop_progress)
    decision_state["timeout_circuit"] = {
        "enabled": bool(stage_timeout_circuit_enabled),
        "stages": sorted(stage_timeout_circuit_stages),
        "failure_categories": sorted(stage_timeout_circuit_failure_categories),
        "consecutive_failures": int(stage_timeout_circuit_consecutive_failures),
        "cooldown_loops": int(stage_timeout_circuit_cooldown_loops),
        "failure_streak": {k: int(v) for k, v in stage_timeout_failure_streak.items() if str(k).strip()},
        "skip_remaining_loops": {
            k: int(v)
            for k, v in stage_timeout_skip_remaining.items()
            if str(k).strip() and int(v or 0) > 0
        },
    }
    decision_state["codex_unhealthy_cooldown"] = {
        "enabled": bool(codex_unhealthy_enabled),
        "stages": sorted(codex_unhealthy_stages),
        "failure_categories": sorted(codex_unhealthy_failure_categories),
        "consecutive_failures": int(codex_unhealthy_consecutive_failures),
        "cooldown_loops": int(codex_unhealthy_cooldown_loops),
        "failure_streak": {k: int(v) for k, v in codex_unhealthy_failure_streak.items() if str(k).strip()},
        "skip_remaining_loops": {
            k: int(v)
            for k, v in codex_unhealthy_skip_remaining.items()
            if str(k).strip() and int(v or 0) > 0
        },
    }

    next_no_progress_loops = 0 if loop_progress else int(no_progress_loops) + 1
    route_switch_outcome = apply_strategy_route_switch(
        after_loop_state=after_loop_state,
        decision_state=decision_state,
        notes=notes,
        session_id=session_id,
        loop_idx=loop_idx,
        enable_exploit=bool(terminal_stage),
        terminal_stage=terminal_stage,
        loop_terminal_unsolved=loop_terminal_unsolved,
        no_progress_loops=next_no_progress_loops,
        terminal_unsolved_streak=terminal_unsolved_streak,
        strategy_route_switch_enabled=strategy_route_switch_enabled,
        strategy_route_switch_no_progress_loops=strategy_route_switch_no_progress_loops,
        strategy_route_switch_terminal_unsolved_loops=strategy_route_switch_terminal_unsolved_loops,
        strategy_route_switch_weak_only=strategy_route_switch_weak_only,
        exploit_precheck_weak_strategies=exploit_precheck_weak_strategies,
        strategy_route_switch_cycle=strategy_route_switch_cycle,
        blind_mode_enabled=blind_mode_enabled,
        blind_mode_route_switch_lock=blind_mode_route_switch_lock,
        blind_mode_default_strategy_hint=blind_mode_default_strategy_hint,
        strategy_route_switch_count=strategy_route_switch_count,
        strategy_route_switch_reset_no_progress=strategy_route_switch_reset_no_progress,
        strategy_route_switch_request_hint_after=strategy_route_switch_request_hint_after,
        strategy_route_switch_write_report=strategy_route_switch_write_report,
        normalize_strategy_hint_fn=normalize_strategy_hint_fn,
        normalize_strategy_hint_cycle_fn=normalize_strategy_hint_cycle_fn,
        pick_next_strategy_hint_fn=pick_next_strategy_hint_fn,
        detect_blind_mode_fn=detect_blind_mode_fn,
        detect_lua_runtime_exec_hint_fn=detect_lua_runtime_exec_hint_fn,
        detect_repl_cmd_exec_hint_fn=detect_repl_cmd_exec_hint_fn,
        write_strategy_route_switch_report_fn=write_strategy_route_switch_report_fn,
        utc_now_fn=utc_now_fn,
    )
    next_no_progress_loops = route_switch_outcome.no_progress_loops
    next_strategy_route_switch_count = route_switch_outcome.strategy_route_switch_count
    route_switch_applied = route_switch_outcome.route_switch_applied
    route_switch_report_rel = route_switch_outcome.route_switch_report_rel

    hint_eval = evaluate_hint_gate(
        enabled=hint_gate_enabled,
        loop_terminal_unsolved=loop_terminal_unsolved,
        no_progress_loops=next_no_progress_loops,
        no_progress_threshold=hint_gate_no_progress_loops,
        no_new_evidence_sec=no_new_evidence_sec,
        no_new_evidence_threshold=hint_gate_no_new_evidence_sec,
        rewrite_elapsed_sec=rewrite_elapsed_sec,
        rewrite_request_hint_after_wall_sec=exploit_rewrite_request_hint_after_wall_sec,
        loop_idx=loop_idx,
        last_trigger_loop=hint_gate_last_trigger_loop,
    )
    hint_gate_triggered = bool(hint_eval.triggered)
    hint_gate_report_rel = ""
    hint_gate_reasons = list(hint_eval.reasons)
    rewrite_hint_gate_triggered = bool(hint_eval.rewrite_triggered)
    next_hint_gate_last_trigger_loop = int(hint_gate_last_trigger_loop)
    if hint_gate_triggered:
        next_hint_gate_last_trigger_loop = int(loop_idx)
        decision_state["recommend_external_hint"] = True
        notes.append(
            "hint gate triggered: "
            + "; ".join(hint_gate_reasons[:3])
            + " (recommend request WP/official hint)"
        )
        if hint_gate_write_report:
            hint_gate_report_rel = write_hint_request_gate_report_fn(
                session_id=session_id,
                loop_idx=loop_idx,
                no_progress_loops=next_no_progress_loops,
                no_new_evidence_sec=no_new_evidence_sec,
                reasons=hint_gate_reasons,
            )
            after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "hint_gate_report"
            ] = hint_gate_report_rel

    timeout_gate_report_rel = ""
    timeout_gate_blind_mode = bool(detect_blind_mode_fn(after_loop_state))
    timeout_eval = evaluate_timeout_no_evidence_gate(
        enabled=timeout_gate_enabled,
        loop_rc124_failures=loop_rc124_failures,
        blind_mode=timeout_gate_blind_mode,
        blind_only=timeout_gate_blind_only,
        require_no_progress=timeout_gate_require_no_progress,
        loop_progress=loop_progress,
        prev_timeout_streak=timeout_no_evidence_streak,
        consecutive_loops=timeout_gate_consecutive_loops,
    )
    timeout_gate_triggered = bool(timeout_eval.triggered)
    timeout_gate_reason = str(timeout_eval.reason or "")
    next_timeout_no_evidence_streak = int(timeout_eval.timeout_streak)
    if timeout_gate_triggered:
        decision_state["recommend_external_hint"] = True
        notes.append(
            "timeout/no-evidence gate triggered: "
            + timeout_gate_reason
            + " (recommend manual protocol/semantic breakthrough)"
        )
        if timeout_gate_write_report:
            timeout_gate_report_rel = write_timeout_no_evidence_gate_report_fn(
                session_id=session_id,
                loop_idx=loop_idx,
                consecutive_timeout_loops=timeout_gate_consecutive_loops,
                timeout_streak=next_timeout_no_evidence_streak,
                rc124_failures_in_loop=loop_rc124_failures,
                no_progress_loops=next_no_progress_loops,
                no_new_evidence_sec=no_new_evidence_sec,
                blind_mode=timeout_gate_blind_mode,
                reason=timeout_gate_reason,
            )
            after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "timeout_no_evidence_gate_report"
            ] = timeout_gate_report_rel

    decision_state["recommend_external_hint"] = bool(
        decision_state.get("recommend_external_hint", False) or hint_gate_triggered or timeout_gate_triggered
    )
    decision_state["no_progress_loops"] = next_no_progress_loops
    decision_state["strategy_route_switch"] = {
        "enabled": bool(strategy_route_switch_enabled),
        "no_progress_loops": int(strategy_route_switch_no_progress_loops),
        "terminal_unsolved_streak": int(strategy_route_switch_terminal_unsolved_loops),
        "weak_only": bool(strategy_route_switch_weak_only),
        "switch_count": int(next_strategy_route_switch_count),
        "cycle": [str(x) for x in strategy_route_switch_cycle],
        "last_applied": bool(route_switch_applied),
        "last_report": str(route_switch_report_rel or ""),
    }
    decision_state["hint_request_gate"] = {
        "enabled": bool(hint_gate_enabled),
        "no_progress_loops": int(hint_gate_no_progress_loops),
        "no_new_evidence_sec": float(hint_gate_no_new_evidence_sec),
        "last_no_new_evidence_sec": round(float(no_new_evidence_sec), 3),
        "rewrite_elapsed_sec": round(float(rewrite_elapsed_sec), 3),
        "rewrite_request_hint_after_wall_sec": float(exploit_rewrite_request_hint_after_wall_sec),
        "rewrite_triggered": bool(rewrite_hint_gate_triggered),
        "last_triggered": bool(hint_gate_triggered),
        "last_report": str(hint_gate_report_rel or ""),
        "stop_on_trigger": bool(hint_gate_stop_on_trigger),
        "stop_on_rewrite_wall": bool(exploit_rewrite_stop_on_request_hint),
    }
    decision_state["timeout_no_evidence_gate"] = {
        "enabled": bool(timeout_gate_enabled),
        "consecutive_timeout_loops": int(timeout_gate_consecutive_loops),
        "require_no_progress": bool(timeout_gate_require_no_progress),
        "blind_mode_only": bool(timeout_gate_blind_only),
        "stop_on_trigger": bool(timeout_gate_stop_on_trigger),
        "loop_rc124_failures": int(loop_rc124_failures),
        "timeout_streak": int(next_timeout_no_evidence_streak),
        "last_triggered": bool(timeout_gate_triggered),
        "last_report": str(timeout_gate_report_rel or ""),
    }
    metrics.no_progress_loops = next_no_progress_loops
    metrics.objective_score_latest = int(post_obj.score)
    if post_obj.target_achieved:
        metrics.objective_target_hits += 1
    save_json_fn(state_path, after_loop_state)
    sync_meta_fn(session_id, after_loop_state)

    return LoopDecisionStateOutcome(
        no_progress_loops=next_no_progress_loops,
        strategy_route_switch_count=next_strategy_route_switch_count,
        hint_gate_last_trigger_loop=next_hint_gate_last_trigger_loop,
        timeout_no_evidence_streak=next_timeout_no_evidence_streak,
        route_switch_applied=route_switch_applied,
        route_switch_report_rel=route_switch_report_rel,
        hint_gate_triggered=hint_gate_triggered,
        rewrite_hint_gate_triggered=rewrite_hint_gate_triggered,
        timeout_gate_triggered=timeout_gate_triggered,
    )


def evaluate_loop_stop(
    *,
    notes: List[str],
    after_loop_state: Dict[str, Any],
    state_path: str,
    session_id: str,
    terminal_stage: str,
    terminal_attempted_this_loop: bool,
    terminal_local_verified_this_loop: bool,
    loop_terminal_unsolved: bool,
    exploit_rewrite_enabled: bool,
    exploit_rewrite_until_success: bool,
    exploit_rewrite_write_report: bool,
    stage_results: List[Dict[str, Any]],
    base_max_loops: int,
    exploit_rewrite_extra_loops: int,
    rewrite_elapsed_sec: float,
    exploit_rewrite_same_error_streak: int,
    terminal_non_actionable_verify_streak: int,
    exploit_rewrite_last_error: str,
    exploit_rewrite_last_verify_report: str,
    exploit_rewrite_last_exp_path: str,
    metrics: Any,
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    sync_meta_fn: Callable[[str, Dict[str, Any]], None],
    loop_idx: int,
    loop_start: int,
    exploit_rewrite_max_wall_sec: float,
    exploit_rewrite_stop_on_same_error_streak: int,
    exploit_rewrite_stop_on_non_actionable_verify_streak: int,
    is_timeout_like_error_fn: Callable[[str], bool],
    objective_enabled: bool,
    objective_stop_on_achieved: bool,
    post_obj: Any,
    force_terminal_stage: bool,
    write_exploit_rewrite_report_fn: Callable[..., str],
    current_exploit_rewrite_stop_reason: str,
    stop_after_no_progress: int,
    no_progress_loops: int,
    stop_on_stage_failure: bool,
    enable_exploit: bool,
    hint_gate_triggered: bool,
    hint_gate_stop_on_trigger: bool,
    rewrite_hint_gate_triggered: bool,
    exploit_rewrite_stop_on_request_hint: bool,
    timeout_gate_triggered: bool,
    timeout_gate_stop_on_trigger: bool,
) -> LoopStopDecisionOutcome:
    if hint_gate_triggered and hint_gate_stop_on_trigger:
        if exploit_rewrite_until_success and loop_terminal_unsolved:
            notes.append("hint gate triggered, but continue until terminal exploit reaches shell/flag")
        else:
            notes.append("hint gate stop: reached no-progress/no-evidence threshold, stop automation early")
            return LoopStopDecisionOutcome(
                exploit_rewrite_stop_reason=str(current_exploit_rewrite_stop_reason or ""),
                should_break=True,
            )
    if hint_gate_triggered and rewrite_hint_gate_triggered and exploit_rewrite_stop_on_request_hint:
        if exploit_rewrite_until_success and loop_terminal_unsolved:
            notes.append("hint gate rewrite wall triggered, but continue until terminal exploit reaches shell/flag")
        else:
            notes.append("hint gate stop: exploit rewrite exceeded wall threshold, stop and request user hint")
            return LoopStopDecisionOutcome(
                exploit_rewrite_stop_reason=str(current_exploit_rewrite_stop_reason or ""),
                should_break=True,
            )
    if timeout_gate_triggered and timeout_gate_stop_on_trigger:
        if exploit_rewrite_until_success and loop_terminal_unsolved:
            notes.append("timeout/no-evidence gate triggered, but continue until terminal exploit reaches shell/flag")
        else:
            notes.append("timeout/no-evidence gate stop: stop automation early and hand over to manual solve")
            return LoopStopDecisionOutcome(
                exploit_rewrite_stop_reason=str(current_exploit_rewrite_stop_reason or ""),
                should_break=True,
            )

    objective_stop_eval = evaluate_objective_stop(
        objective_enabled=objective_enabled,
        objective_stop_on_achieved=objective_stop_on_achieved,
        target_achieved=bool(post_obj.target_achieved),
        force_terminal_stage=force_terminal_stage,
        terminal_attempted_this_loop=terminal_attempted_this_loop,
        terminal_stage=terminal_stage,
        score=int(post_obj.score),
    )
    if objective_stop_eval.note:
        notes.append(objective_stop_eval.note)
    if objective_stop_eval.should_break:
        return LoopStopDecisionOutcome(
            exploit_rewrite_stop_reason=str(current_exploit_rewrite_stop_reason or ""),
            should_break=True,
        )

    if exploit_rewrite_enabled and loop_terminal_unsolved and exploit_rewrite_write_report:
        loops_seen_progress = sorted(
            {
                int(x.get("loop", 0) or 0)
                for x in stage_results
                if isinstance(x, dict) and int(x.get("loop", 0) or 0) > 0
            }
        )
        exploit_rewrite_report_rel = write_exploit_rewrite_report_fn(
            session_id=session_id,
            terminal_stage=terminal_stage,
            reason="in_progress: terminal exploit unsolved",
            solved=False,
            loops_executed=len(loops_seen_progress),
            base_max_loops=base_max_loops,
            extra_loops_budget=exploit_rewrite_extra_loops,
            rewrite_elapsed_sec=rewrite_elapsed_sec,
            same_error_streak=exploit_rewrite_same_error_streak,
            non_actionable_verify_streak=terminal_non_actionable_verify_streak,
            last_error=exploit_rewrite_last_error,
            last_verify_report=exploit_rewrite_last_verify_report,
            exp_path=exploit_rewrite_last_exp_path,
            stage_results=stage_results,
            metrics=metrics,
        )
        after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
            "exploit_rewrite_report"
        ] = exploit_rewrite_report_rel
        save_json_fn(state_path, after_loop_state)
        sync_meta_fn(session_id, after_loop_state)

    if enable_exploit and terminal_attempted_this_loop and terminal_local_verified_this_loop:
        notes.append(f"{terminal_stage} 本轮已通过 verify（shell/flag marker 命中），停止自动重写")
        return LoopStopDecisionOutcome(
            exploit_rewrite_stop_reason=str(current_exploit_rewrite_stop_reason or ""),
            should_break=True,
        )

    next_stop_reason = str(current_exploit_rewrite_stop_reason or "")
    if exploit_rewrite_enabled and loop_terminal_unsolved:
        loops_used = int(loop_idx - loop_start + 1)
        extra_used = max(0, loops_used - base_max_loops)
        extra_loops_budget = int(exploit_rewrite_extra_loops)
        if exploit_rewrite_until_success:
            extra_used = 0
            extra_loops_budget = -1
        rewrite_stop_eval = evaluate_exploit_rewrite_stop(
            rewrite_elapsed_sec=rewrite_elapsed_sec,
            max_wall_sec=exploit_rewrite_max_wall_sec,
            same_error_streak=exploit_rewrite_same_error_streak,
            same_error_limit=exploit_rewrite_stop_on_same_error_streak,
            last_error=exploit_rewrite_last_error,
            non_actionable_verify_streak=terminal_non_actionable_verify_streak,
            non_actionable_verify_limit=exploit_rewrite_stop_on_non_actionable_verify_streak,
            extra_used=extra_used,
            extra_loops_budget=extra_loops_budget,
            is_timeout_like_error=is_timeout_like_error_fn,
        )
        if rewrite_stop_eval.keep_rewriting_note:
            notes.append(rewrite_stop_eval.keep_rewriting_note)
        if rewrite_stop_eval.stop_reason:
            next_stop_reason = rewrite_stop_eval.stop_reason
            notes.append(next_stop_reason)
            return LoopStopDecisionOutcome(
                exploit_rewrite_stop_reason=next_stop_reason,
                should_break=True,
            )

    no_progress_stop_eval = evaluate_no_progress_stop(
        no_progress_loops=no_progress_loops,
        stop_after_no_progress=stop_after_no_progress,
        force_terminal_stage=force_terminal_stage,
        terminal_attempted_this_loop=terminal_attempted_this_loop,
        terminal_stage=terminal_stage,
        exploit_rewrite_enabled=exploit_rewrite_enabled,
        loop_terminal_unsolved=loop_terminal_unsolved,
    )
    if no_progress_stop_eval.note:
        notes.append(no_progress_stop_eval.note)
    if no_progress_stop_eval.should_break:
        return LoopStopDecisionOutcome(
            exploit_rewrite_stop_reason=next_stop_reason,
            should_break=True,
        )

    stage_failure_stop_eval = evaluate_stage_failure_stop(
        stage_failed=bool(stage_results and (not stage_results[-1].get("ok", True))),
        stop_on_stage_failure=stop_on_stage_failure,
        force_terminal_stage=force_terminal_stage,
        terminal_attempted_this_loop=terminal_attempted_this_loop,
        terminal_stage=terminal_stage,
        exploit_rewrite_enabled=exploit_rewrite_enabled,
        enable_exploit=enable_exploit,
    )
    if stage_failure_stop_eval.note:
        notes.append(stage_failure_stop_eval.note)
    return LoopStopDecisionOutcome(
        exploit_rewrite_stop_reason=next_stop_reason,
        should_break=bool(stage_failure_stop_eval.should_break),
    )
