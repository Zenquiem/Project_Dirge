#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Set, Tuple


@dataclass(frozen=True)
class StrategyRouteSwitchOutcome:
    no_progress_loops: int
    strategy_route_switch_count: int
    route_switch_applied: bool
    route_switch_report_rel: str


def apply_strategy_route_switch(
    *,
    after_loop_state: Dict[str, Any],
    decision_state: Dict[str, Any],
    notes: List[str],
    session_id: str,
    loop_idx: int,
    enable_exploit: bool,
    terminal_stage: str,
    loop_terminal_unsolved: bool,
    no_progress_loops: int,
    terminal_unsolved_streak: int,
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
    normalize_strategy_hint_fn: Callable[[Any], str],
    normalize_strategy_hint_cycle_fn: Callable[..., List[str]],
    pick_next_strategy_hint_fn: Callable[..., Tuple[str, str, str, List[str]]],
    detect_blind_mode_fn: Callable[[Dict[str, Any]], bool],
    detect_lua_runtime_exec_hint_fn: Callable[[Dict[str, Any]], bool],
    detect_repl_cmd_exec_hint_fn: Callable[[Dict[str, Any]], bool],
    write_strategy_route_switch_report_fn: Callable[..., str],
    utc_now_fn: Callable[[], str],
) -> StrategyRouteSwitchOutcome:
    route_switch_report_rel = ""
    route_switch_applied = False
    next_no_progress_loops = int(no_progress_loops)
    next_strategy_route_switch_count = int(strategy_route_switch_count)

    if not (
        strategy_route_switch_enabled
        and enable_exploit
        and bool(terminal_stage)
        and loop_terminal_unsolved
        and (next_no_progress_loops >= strategy_route_switch_no_progress_loops)
        and (terminal_unsolved_streak >= strategy_route_switch_terminal_unsolved_loops)
    ):
        return StrategyRouteSwitchOutcome(
            no_progress_loops=next_no_progress_loops,
            strategy_route_switch_count=next_strategy_route_switch_count,
            route_switch_applied=False,
            route_switch_report_rel="",
        )

    exp_now = after_loop_state.setdefault("session", {}).setdefault("exp", {})
    current_hint = normalize_strategy_hint_fn(exp_now.get("strategy_hint", ""))
    current_strategy = normalize_strategy_hint_fn(exp_now.get("strategy", ""))
    weak_route = (
        (current_hint in exploit_precheck_weak_strategies)
        or (current_strategy in exploit_precheck_weak_strategies)
    )
    if strategy_route_switch_weak_only and (not weak_route):
        return StrategyRouteSwitchOutcome(
            no_progress_loops=next_no_progress_loops,
            strategy_route_switch_count=next_strategy_route_switch_count,
            route_switch_applied=False,
            route_switch_report_rel="",
        )

    route_cycle_runtime = list(strategy_route_switch_cycle)
    blind_route_lock_active = bool(
        blind_mode_enabled
        and detect_blind_mode_fn(after_loop_state)
        and blind_mode_route_switch_lock
    )
    lua_or_repl_hint = bool(
        detect_lua_runtime_exec_hint_fn(after_loop_state)
        or detect_repl_cmd_exec_hint_fn(after_loop_state)
    )
    if blind_route_lock_active:
        seed_hint = "js_shell_cmd_exec" if lua_or_repl_hint else blind_mode_default_strategy_hint
        route_cycle_runtime = normalize_strategy_hint_cycle_fn([seed_hint], state=after_loop_state)

    next_hint, from_hint, from_strategy, route_cycle_used = pick_next_strategy_hint_fn(
        after_loop_state,
        route_cycle_runtime,
    )
    if blind_route_lock_active and lua_or_repl_hint:
        if current_hint != "js_shell_cmd_exec":
            next_hint = "js_shell_cmd_exec"
        elif current_strategy != "js_shell_cmd_exec":
            next_hint = "js_shell_cmd_exec"
        else:
            next_hint = ""
    if not next_hint:
        return StrategyRouteSwitchOutcome(
            no_progress_loops=next_no_progress_loops,
            strategy_route_switch_count=next_strategy_route_switch_count,
            route_switch_applied=False,
            route_switch_report_rel="",
        )

    trigger_no_progress_loops = int(next_no_progress_loops)
    trigger_terminal_unsolved_streak = int(terminal_unsolved_streak)
    exp_now["strategy_hint"] = next_hint
    exp_now["force_regen_once"] = True
    reason = (
        "no progress + terminal unsolved streak: "
        f"no_progress_loops={trigger_no_progress_loops}, "
        f"terminal_unsolved_streak={trigger_terminal_unsolved_streak}"
    )
    exp_now["strategy_switch_reason"] = reason
    exp_now["strategy_switch_utc"] = utc_now_fn()
    next_strategy_route_switch_count += 1
    route_switch_applied = True
    if strategy_route_switch_reset_no_progress:
        next_no_progress_loops = 0
    recommend_hint = bool(
        strategy_route_switch_request_hint_after > 0
        and next_strategy_route_switch_count >= strategy_route_switch_request_hint_after
    )
    decision_state["recommend_external_hint"] = bool(recommend_hint)
    notes.append(
        f"strategy route switch loop={loop_idx}: {from_hint or from_strategy or 'unknown'} -> {next_hint}"
    )
    if recommend_hint:
        notes.append("strategy route switch reached hint threshold; recommend requesting WP/official hint")
    if strategy_route_switch_write_report:
        route_switch_report_rel = write_strategy_route_switch_report_fn(
            session_id=session_id,
            loop_idx=loop_idx,
            current_hint=from_hint,
            current_strategy=from_strategy,
            next_hint=next_hint,
            cycle=route_cycle_used,
            no_progress_loops=trigger_no_progress_loops,
            terminal_unsolved_streak=trigger_terminal_unsolved_streak,
            reason=reason,
            recommend_hint=recommend_hint,
        )
        after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
            "strategy_route_switch_report"
        ] = route_switch_report_rel

    return StrategyRouteSwitchOutcome(
        no_progress_loops=next_no_progress_loops,
        strategy_route_switch_count=next_strategy_route_switch_count,
        route_switch_applied=route_switch_applied,
        route_switch_report_rel=route_switch_report_rel,
    )
