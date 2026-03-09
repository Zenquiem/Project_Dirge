#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class StageSpecCheckOutcome:
    ok: bool
    rc: int
    err: str
    stage_spec_errors: List[str]
    failure_category: str
    failure_recoverable: bool


@dataclass(frozen=True)
class StageStateMergeOutcome:
    after_state: Dict[str, Any]
    loop_rc124_failures: int


def apply_stage_spec_check(
    *,
    ok: bool,
    rc: int,
    err: str,
    stage: str,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage_log_rel: str,
    log_abs: str,
    is_exploit_stage: bool,
    exp_verify_report: str,
    failure_category: str,
    failure_recoverable: bool,
    load_json_fn: Callable[[str], Dict[str, Any]],
    append_file_fn: Callable[[str, str], None],
    normalize_latest_artifact_keys_fn: Callable[..., Dict[str, str]],
    ensure_exploit_artifact_links_fn: Callable[..., None],
    validate_stage_runner_spec_fn: Callable[[Dict[str, Any], Dict[str, Any]], List[str]],
    stage_spec: Dict[str, Any],
) -> StageSpecCheckOutcome:
    stage_spec_errors: List[str] = []
    if ok:
        normalize_latest_artifact_keys_fn(
            state_path=state_path,
            session_id=session_id,
            loop_idx=loop_idx,
            stage=stage,
            stage_log_rel=stage_log_rel,
        )
        if is_exploit_stage:
            ensure_exploit_artifact_links_fn(
                state_path=state_path,
                session_id=session_id,
                loop_idx=loop_idx,
                verify_report_hint=exp_verify_report,
            )
        state_for_spec = load_json_fn(state_path)
        stage_spec_errors = validate_stage_runner_spec_fn(state_for_spec, stage_spec)
        if stage_spec_errors:
            ok = False
            rc = 66
            err = "stage runner spec validation failed"
            failure_category = "stage_spec_violation"
            failure_recoverable = False
            append_file_fn(log_abs, "[run_session] stage runner spec errors:\n")
            for se in stage_spec_errors:
                append_file_fn(log_abs, f" - {se}\n")
    return StageSpecCheckOutcome(
        ok=bool(ok),
        rc=int(rc),
        err=str(err or ""),
        stage_spec_errors=stage_spec_errors,
        failure_category=str(failure_category or ""),
        failure_recoverable=bool(failure_recoverable),
    )


def apply_stage_result_state(
    *,
    state_path: str,
    stage: str,
    ok: bool,
    rc: int,
    err: str,
    contract_errors: List[str],
    failure_category: str,
    metrics: Any,
    loop_rc124_failures: int,
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    sync_meta_fn: Callable[[str, Dict[str, Any]], None],
    session_id: str,
) -> StageStateMergeOutcome:
    after_final = load_json_fn(state_path)
    if ok:
        metrics.bump_stage_success(stage)
        return StageStateMergeOutcome(after_state=after_final, loop_rc124_failures=int(loop_rc124_failures or 0))

    metrics.bump_stage_failure(stage)
    next_rc124 = int(loop_rc124_failures or 0)
    if int(rc or 0) == 124:
        next_rc124 += 1
    if failure_category in {"codex_missing", "mcp_transient", "timeout", "stage_runtime_error", "unknown"}:
        metrics.codex_errors += 1
    after_final.setdefault("session", {})["status"] = f"failed:{stage}"
    if err:
        after_final["session"]["last_error"] = err
    if contract_errors:
        after_final.setdefault("summary", {}).setdefault("blockers", []).append(
            f"{stage}: contract failed ({len(contract_errors)} errors)"
        )
    save_json_fn(state_path, after_final)
    sync_meta_fn(session_id, after_final)
    return StageStateMergeOutcome(after_state=after_final, loop_rc124_failures=next_rc124)
