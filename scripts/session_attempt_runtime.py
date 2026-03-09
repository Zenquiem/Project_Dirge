#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class AttemptRetryActionResult:
    should_continue: bool
    next_attempt_no: int
    mcp_forced_retry_used: bool


@dataclass(frozen=True)
class AttemptFinalizeOutcome:
    failure_category: str
    failure_recoverable: bool
    next_attempt_no: int
    mcp_forced_retry_used: bool
    should_continue: bool
    should_break: bool


def apply_attempt_retry_decision(
    *,
    retry_decision: Any,
    stage: str,
    failure_category: str,
    attempt_no: int,
    state_path: str,
    session_id: str,
    loop_idx: int,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    log_abs: str,
    mcp_forced_retry_used: bool,
    metrics: Any,
    run_mcp_self_heal_fn: Callable[..., str],
    append_file_fn: Callable[[str, str], None],
    sleep_fn: Callable[[float], None],
) -> AttemptRetryActionResult:
    if retry_decision.action == "force_mcp_retry":
        metrics.stage_retries += 1
        heal_rel = run_mcp_self_heal_fn(
            state_path=state_path,
            session_id=session_id,
            loop_idx=loop_idx,
            stage=f"{stage}_retry",
            reason=f"{stage} {failure_category} forced reconnect retry",
            health_cfg=health_cfg,
            codex_bin=codex_bin,
            notes=None,
        )
        retry_wait = float(retry_decision.retry_wait)
        append_file_fn(
            log_abs,
            "[run_session] forced reconnect retry: "
            f"{retry_decision.reason} self_heal={heal_rel or 'none'} wait={retry_wait:.2f}s\n",
        )
        if retry_wait > 0:
            sleep_fn(retry_wait)
        return AttemptRetryActionResult(
            should_continue=True,
            next_attempt_no=attempt_no + 1,
            mcp_forced_retry_used=True,
        )

    if retry_decision.action == "retry":
        metrics.stage_retries += 1
        retry_wait = float(retry_decision.retry_wait)
        append_file_fn(
            log_abs,
            f"[run_session] retry {retry_decision.reason} attempt={attempt_no} wait={retry_wait:.2f}s\n",
        )
        if retry_wait > 0:
            sleep_fn(retry_wait)
        return AttemptRetryActionResult(
            should_continue=True,
            next_attempt_no=attempt_no + 1,
            mcp_forced_retry_used=bool(mcp_forced_retry_used),
        )

    return AttemptRetryActionResult(
        should_continue=False,
        next_attempt_no=attempt_no,
        mcp_forced_retry_used=bool(mcp_forced_retry_used),
    )


def finalize_attempt(
    *,
    ok: bool,
    rc: int,
    err: str,
    contract_errors: List[str],
    validate_failed: bool,
    verifier_failed: bool,
    fuse_triggered: bool,
    stage: str,
    attempt_no: int,
    attempt_records: List[Dict[str, Any]],
    mcp_forced_retry_used: bool,
    codex_available: bool,
    recovery_cfg: Dict[str, Any],
    state_path: str,
    session_id: str,
    loop_idx: int,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    log_abs: str,
    metrics: Any,
    classify_failure_fn: Callable[..., Any],
    utc_now_fn: Callable[[], str],
    evaluate_attempt_retry_policy_fn: Callable[..., Any],
    should_retry_fn: Callable[..., bool],
    next_backoff_seconds_fn: Callable[..., float],
    run_mcp_self_heal_fn: Callable[..., str],
    append_file_fn: Callable[[str, str], None],
    sleep_fn: Callable[[float], None],
) -> AttemptFinalizeOutcome:
    info = classify_failure_fn(
        rc,
        err,
        contract_errors=contract_errors,
        validate_failed=validate_failed,
        verifier_failed=verifier_failed,
    )
    failure_category = str(info.category or "")
    failure_recoverable = bool(info.recoverable)
    attempt_records.append(
        {
            "attempt": attempt_no,
            "ok": ok,
            "rc": rc,
            "error": err,
            "failure_category": failure_category if not ok else "",
            "recoverable": bool(failure_recoverable and (not ok)),
            "ended_utc": utc_now_fn(),
        }
    )

    if ok:
        return AttemptFinalizeOutcome(
            failure_category=failure_category,
            failure_recoverable=failure_recoverable,
            next_attempt_no=attempt_no,
            mcp_forced_retry_used=bool(mcp_forced_retry_used),
            should_continue=False,
            should_break=True,
        )

    if failure_recoverable:
        metrics.recoverable_failures += 1

    if fuse_triggered:
        return AttemptFinalizeOutcome(
            failure_category=failure_category,
            failure_recoverable=failure_recoverable,
            next_attempt_no=attempt_no,
            mcp_forced_retry_used=bool(mcp_forced_retry_used),
            should_continue=False,
            should_break=True,
        )

    retry_decision = evaluate_attempt_retry_policy_fn(
        stage=stage,
        mcp_forced_retry_used=mcp_forced_retry_used,
        codex_available=codex_available,
        failure_category=failure_category,
        err=err,
        attempt_no=attempt_no,
        info=info,
        recovery_cfg=recovery_cfg,
        should_retry_fn=should_retry_fn,
        next_backoff_seconds_fn=next_backoff_seconds_fn,
    )
    retry_action = apply_attempt_retry_decision(
        retry_decision=retry_decision,
        stage=stage,
        failure_category=failure_category,
        attempt_no=attempt_no,
        state_path=state_path,
        session_id=session_id,
        loop_idx=loop_idx,
        health_cfg=health_cfg,
        codex_bin=codex_bin,
        log_abs=log_abs,
        mcp_forced_retry_used=mcp_forced_retry_used,
        metrics=metrics,
        run_mcp_self_heal_fn=run_mcp_self_heal_fn,
        append_file_fn=append_file_fn,
        sleep_fn=sleep_fn,
    )
    return AttemptFinalizeOutcome(
        failure_category=failure_category,
        failure_recoverable=failure_recoverable,
        next_attempt_no=retry_action.next_attempt_no,
        mcp_forced_retry_used=bool(retry_action.mcp_forced_retry_used),
        should_continue=bool(retry_action.should_continue),
        should_break=bool(not retry_action.should_continue),
    )
