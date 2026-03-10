#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class RunFinalizeOutcome:
    final_state: Dict[str, Any]
    exit_code: int
    acceptance_report_rel: str
    acceptance_passed: bool
    timeline_rel: str
    timing_rel: str
    exploit_rewrite_report_rel: str
    report_rel: str
    metrics_rel_out: str


def finalize_run_outputs(
    *,
    root_dir: str,
    state_path: str,
    session_id: str,
    loop_end: int,
    fast_mode: bool,
    enable_exploit: bool,
    allow_remote_exp: bool,
    exploit_rewrite_enabled: bool,
    exploit_rewrite_write_report: bool,
    terminal_stage: str,
    base_max_loops: int,
    exploit_rewrite_extra_loops: int,
    exploit_rewrite_started_monotonic: float,
    exploit_rewrite_same_error_streak: int,
    terminal_non_actionable_verify_streak: int,
    exploit_rewrite_last_error: str,
    exploit_rewrite_last_verify_report: str,
    exploit_rewrite_last_exp_path: str,
    exploit_rewrite_stop_reason: str,
    fuse_triggered: bool,
    fuse_reason: str,
    stop_requested: bool,
    has_fail: bool,
    max_codex_calls: int,
    max_prompt_chars: int,
    max_wall_time_sec: float,
    max_autofix_rounds: int,
    acceptance_cfg: Dict[str, Any],
    remote_prompt_cfg: Dict[str, Any],
    kpi_enabled: bool,
    per_session_abs: str,
    global_kpi_abs: str,
    metrics: Any,
    stage_results: List[Dict[str, Any]],
    notes: List[str],
    cap_cfg: Dict[str, Any],
    objective_cfg: Dict[str, Any],
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    infer_capabilities_fn: Callable[[Dict[str, Any], Dict[str, Any]], Any],
    evaluate_objectives_fn: Callable[[Dict[str, Any], Dict[str, Any], bool], Any],
    apply_objective_state_fn: Callable[[Dict[str, Any], Dict[str, Any], str], None],
    derive_final_session_status_fn: Callable[..., str],
    derive_final_rewrite_reason_fn: Callable[..., str],
    derive_final_exit_decision_fn: Callable[..., Any],
    write_exploit_rewrite_report_fn: Callable[..., str],
    write_cost_fuse_report_fn: Callable[..., str],
    write_acceptance_report_fn: Callable[..., Any],
    ensure_exploit_artifact_links_fn: Callable[..., Any],
    maybe_prepare_remote_prompt_fn: Callable[..., str],
    write_timeline_report_fn: Callable[..., str],
    write_timing_report_fn: Callable[..., str],
    write_summary_report_fn: Callable[..., None],
    merge_external_metric_counters_fn: Callable[[Any, str], None],
    refresh_global_kpi_fn: Callable[[str, Any], None],
    sync_meta_from_state_fn: Callable[..., None],
    sync_state_meta_cli_fn: Callable[..., None],
    repo_rel_fn: Callable[[str], str],
    monotonic_now_fn: Callable[[], float],
) -> RunFinalizeOutcome:
    final_state = load_json_fn(state_path)
    if bool(cap_cfg.get("enabled", True)):
        cap_inf_final = infer_capabilities_fn(final_state, cap_cfg)
        if cap_inf_final.changed:
            metrics.capability_updates += 1
    final_obj = evaluate_objectives_fn(final_state, objective_cfg, enable_exploit)
    apply_objective_state_fn(final_state, final_obj.to_dict(), "")
    metrics.objective_score_latest = int(final_obj.score)
    final_status = derive_final_session_status_fn(
        fuse_triggered=fuse_triggered,
        stop_requested=stop_requested,
        has_fail=has_fail,
    )
    final_state.setdefault("session", {})["status"] = final_status
    if fuse_triggered and fuse_reason:
        final_state["session"]["last_error"] = fuse_reason

    exploit_rewrite_report_rel = ""
    final_local_verify = bool(final_state.get("session", {}).get("exp", {}).get("local_verify_passed", False))
    if exploit_rewrite_enabled and enable_exploit and terminal_stage and (not final_local_verify):
        loops_seen = sorted(
            {
                int(x.get("loop", 0) or 0)
                for x in stage_results
                if isinstance(x, dict) and int(x.get("loop", 0) or 0) > 0
            }
        )
        loops_executed = len(loops_seen)
        rewrite_elapsed_final = 0.0
        if exploit_rewrite_started_monotonic > 0:
            rewrite_elapsed_final = max(0.0, monotonic_now_fn() - exploit_rewrite_started_monotonic)
        rewrite_reason = derive_final_rewrite_reason_fn(
            exploit_rewrite_stop_reason=exploit_rewrite_stop_reason,
            fuse_reason=fuse_reason,
            session_last_error=str(final_state.get("session", {}).get("last_error", "")).strip(),
            terminal_stage=terminal_stage,
        )
        if exploit_rewrite_write_report:
            exploit_rewrite_report_rel = write_exploit_rewrite_report_fn(
                session_id=session_id,
                terminal_stage=terminal_stage,
                reason=rewrite_reason,
                solved=False,
                loops_executed=loops_executed,
                base_max_loops=base_max_loops,
                extra_loops_budget=exploit_rewrite_extra_loops,
                rewrite_elapsed_sec=rewrite_elapsed_final,
                same_error_streak=exploit_rewrite_same_error_streak,
                non_actionable_verify_streak=terminal_non_actionable_verify_streak,
                last_error=exploit_rewrite_last_error,
                last_verify_report=exploit_rewrite_last_verify_report,
                exp_path=exploit_rewrite_last_exp_path,
                stage_results=stage_results,
                metrics=metrics,
            )
            final_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "exploit_rewrite_report"
            ] = exploit_rewrite_report_rel
            final_state.setdefault("summary", {}).setdefault("blockers", []).append(rewrite_reason)

    cost_fuse_report_rel = write_cost_fuse_report_fn(
        session_id=session_id,
        max_codex_calls=max_codex_calls,
        max_prompt_chars=max_prompt_chars,
        max_wall_time_sec=max_wall_time_sec,
        max_autofix_rounds=max_autofix_rounds,
        metrics=metrics,
        triggered=fuse_triggered,
        reason=fuse_reason,
    )
    final_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
        "cost_fuse_report"
    ] = cost_fuse_report_rel

    acceptance_report_rel, acceptance_passed = write_acceptance_report_fn(
        session_id=session_id,
        metrics=metrics,
        final_state=final_state,
        acceptance_cfg=acceptance_cfg,
        terminal_stage=terminal_stage,
    )
    final_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
        "acceptance_report"
    ] = acceptance_report_rel

    final_exit = derive_final_exit_decision_fn(
        fuse_triggered=fuse_triggered,
        stop_requested=stop_requested,
        has_fail=has_fail,
        acceptance_enabled=bool(acceptance_cfg.get("enabled", False)),
        acceptance_passed=acceptance_passed,
    )
    if final_exit.acceptance_failed:
        notes.append("acceptance gate 未通过")
        final_state.setdefault("summary", {}).setdefault("blockers", []).append("acceptance gate failed")
    exit_code = int(final_exit.exit_code)

    save_json_fn(state_path, final_state)

    if enable_exploit:
        ensure_exploit_artifact_links_fn(
            state_path=state_path,
            session_id=session_id,
            loop_idx=max(1, loop_end - 1),
        )
        final_state = load_json_fn(state_path)
    maybe_prepare_remote_prompt_fn(
        state=final_state,
        state_path=state_path,
        session_id=session_id,
        remote_prompt_cfg=remote_prompt_cfg,
        enable_exploit=enable_exploit,
        allow_remote_exp=allow_remote_exp,
        stage_results=stage_results,
        notes=notes,
    )
    final_state = load_json_fn(state_path)
    save_json_fn(state_path, final_state)

    timeline_rel = write_timeline_report_fn(session_id, stage_results, metrics, state=final_state)
    timing_rel = write_timing_report_fn(session_id, stage_results, metrics, state=final_state)
    final_state = load_json_fn(state_path)
    final_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
        "timeline_report"
    ] = timeline_rel
    final_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
        "timing_report"
    ] = timing_rel
    save_json_fn(state_path, final_state)

    report_rel = f"artifacts/reports/session_{session_id}_summary.md"
    write_summary_report_fn(f"{root_dir}/{report_rel}", session_id, stage_results, final_state, notes)

    if kpi_enabled:
        merge_external_metric_counters_fn(metrics, per_session_abs)
        metrics.save(per_session_abs)
        refresh_global_kpi_fn(global_kpi_abs, metrics)

    metrics_rel_out = repo_rel_fn(per_session_abs) if kpi_enabled else ""
    sync_meta_from_state_fn(
        session_id,
        final_state,
        report_rel=report_rel,
        metrics_rel=metrics_rel_out,
    )
    sync_state_meta_cli_fn(
        session_id,
        state_path=state_path,
        report_rel=report_rel,
        metrics_rel=metrics_rel_out,
    )
    return RunFinalizeOutcome(
        final_state=final_state,
        exit_code=exit_code,
        acceptance_report_rel=acceptance_report_rel,
        acceptance_passed=bool(acceptance_passed),
        timeline_rel=timeline_rel,
        timing_rel=timing_rel,
        exploit_rewrite_report_rel=exploit_rewrite_report_rel,
        report_rel=report_rel,
        metrics_rel_out=metrics_rel_out,
    )
