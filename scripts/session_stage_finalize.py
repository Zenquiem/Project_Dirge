#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class StageFinalizeOutcome:
    stage_result: Dict[str, Any]


def finalize_stage_post_run(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    log_rel: str,
    ok: bool,
    rc: int,
    err: str,
    contract_errors: List[str],
    attempt_records: List[Dict[str, Any]],
    stage_spec_errors: List[str],
    failure_category: str,
    failure_recoverable: bool,
    before_snapshot_rel: str,
    stage_started_utc: str,
    stage_started_monotonic: float,
    is_exploit_stage: bool,
    exp_verify_ok: Any,
    exp_verify_report: str,
    exp_autofix_attempts: int,
    exp_autofix_last_error: str,
    stage_cache_hit: bool,
    stage_cache_ref: str,
    stage_cache_saved: str,
    bundled: bool,
    kpi_enabled: bool,
    metrics: Any,
    per_session_abs: str,
    global_kpi_abs: str,
    decision_report_rel: str,
    mutation_manifest_rel: str,
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    utc_now_fn: Callable[[], str],
    monotonic_now_fn: Callable[[], float],
    build_failure_context_fn: Callable[..., Dict[str, Any]],
    build_stage_tx_meta_doc_fn: Callable[..., Dict[str, Any]],
    write_tx_snapshot_fn: Callable[[str, int, str, str, Dict[str, Any]], str],
    write_tx_meta_fn: Callable[[str, int, str, Dict[str, Any]], str],
    root_dir: str,
    stage_spec: Dict[str, Any],
    write_stage_receipt_fn: Callable[..., str],
    register_stage_receipt_fn: Callable[[Dict[str, Any], str, str], None],
    write_failure_report_fn: Callable[[str, int, str, str, str, str, Dict[str, Any] | None], str],
    update_stage_timing_state_fn: Callable[..., None],
    write_realtime_kpi_snapshot_fn: Callable[..., None],
    build_stage_result_record_fn: Callable[..., Dict[str, Any]],
) -> StageFinalizeOutcome:
    after_snapshot_rel = write_tx_snapshot_fn(session_id, loop_idx, stage, "after", load_json_fn(state_path))
    stage_ended_utc = utc_now_fn()
    failure_context: Dict[str, Any] = {}
    if not ok:
        failure_context = build_failure_context_fn(
            stage=stage,
            rc=rc,
            err=err,
            failure_category=failure_category,
            attempt_records=attempt_records,
            log_rel=log_rel,
            exp_verify_report=(exp_verify_report if is_exploit_stage else ""),
        )

    tx_meta = build_stage_tx_meta_doc_fn(
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        started_utc=stage_started_utc,
        ended_utc=stage_ended_utc,
        ok=ok,
        rc=rc,
        err=err,
        contract_errors=contract_errors,
        attempt_records=attempt_records,
        stage_spec_errors=stage_spec_errors,
        failure_category=failure_category,
        failure_recoverable=failure_recoverable,
        failure_context=failure_context,
        before_snapshot=before_snapshot_rel,
        after_snapshot=after_snapshot_rel,
        log_rel=log_rel,
        is_exploit_stage=is_exploit_stage,
        exp_verify_ok=exp_verify_ok,
        exp_verify_report=exp_verify_report,
        exp_autofix_attempts=exp_autofix_attempts,
        exp_autofix_last_error=exp_autofix_last_error,
        stage_cache_hit=stage_cache_hit,
        stage_cache_ref=stage_cache_ref,
        stage_cache_saved=stage_cache_saved,
        bundled=bool(bundled),
    )
    tx_meta_rel = write_tx_meta_fn(session_id, loop_idx, stage, tx_meta)

    receipt_rel = write_stage_receipt_fn(
        root_dir=root_dir,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        spec=stage_spec,
        stage_result={
            "ok": ok,
            "rc": rc,
            "error": err,
            "tx_meta": tx_meta_rel,
            "attempt_count": len(attempt_records),
            "stage_spec_errors": stage_spec_errors,
            "log": log_rel,
        },
    )
    receipt_state = load_json_fn(state_path)
    register_stage_receipt_fn(receipt_state, stage, receipt_rel)
    save_json_fn(state_path, receipt_state)

    failure_report_rel = ""
    if not ok:
        failure_report_rel = write_failure_report_fn(
            session_id,
            loop_idx,
            stage,
            err or "stage failed",
            tx_meta_rel,
            log_rel,
            failure_context,
        )

    stage_elapsed_sec = max(0.0, float(monotonic_now_fn() - stage_started_monotonic))
    metrics.record_stage_wall(stage, stage_elapsed_sec)
    update_stage_timing_state_fn(
        state_path=state_path,
        stage=stage,
        loop_idx=loop_idx,
        started_utc=stage_started_utc,
        ended_utc=stage_ended_utc,
        elapsed_sec=stage_elapsed_sec,
        attempts=len(attempt_records),
        ok=ok,
    )
    write_realtime_kpi_snapshot_fn(
        enabled=kpi_enabled,
        metrics=metrics,
        per_session_abs=per_session_abs,
        global_kpi_abs=global_kpi_abs,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        started_utc=stage_started_utc,
        ended_utc=stage_ended_utc,
        elapsed_sec=stage_elapsed_sec,
        ok=ok,
        rc=rc,
        failure_category=(failure_category if not ok else ""),
        tx_meta_rel=tx_meta_rel,
        log_rel=log_rel,
    )

    stage_result = build_stage_result_record_fn(
        loop_idx=loop_idx,
        stage=stage,
        ok=ok,
        rc=rc,
        log_rel=log_rel,
        tx_meta_rel=tx_meta_rel,
        failure_report_rel=failure_report_rel,
        decision_report_rel=decision_report_rel,
        mutation_manifest_rel=mutation_manifest_rel,
        attempt_records=attempt_records,
        stage_spec_errors=stage_spec_errors,
        failure_category=failure_category,
        failure_context=failure_context,
        receipt_rel=receipt_rel,
        is_exploit_stage=is_exploit_stage,
        exp_verify_ok=exp_verify_ok,
        exp_verify_report=exp_verify_report,
        exp_autofix_attempts=exp_autofix_attempts,
        exp_autofix_last_error=exp_autofix_last_error,
        stage_cache_hit=stage_cache_hit,
        stage_cache_ref=stage_cache_ref,
        stage_cache_saved=stage_cache_saved,
        bundled=bool(bundled),
        started_utc=stage_started_utc,
        ended_utc=stage_ended_utc,
        stage_elapsed_sec=stage_elapsed_sec,
    )
    return StageFinalizeOutcome(stage_result=stage_result)
