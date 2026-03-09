#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FinalExitDecision:
    exit_code: int
    acceptance_failed: bool


def derive_final_session_status(*, fuse_triggered: bool, stop_requested: bool, has_fail: bool) -> str:
    if fuse_triggered:
        return "fused"
    if stop_requested:
        return "stopped"
    return "finished_with_errors" if has_fail else "finished"


def derive_final_exit_decision(
    *,
    fuse_triggered: bool,
    stop_requested: bool,
    has_fail: bool,
    acceptance_enabled: bool,
    acceptance_passed: bool,
) -> FinalExitDecision:
    acceptance_failed = bool(acceptance_enabled and (not acceptance_passed))
    if fuse_triggered:
        return FinalExitDecision(exit_code=68, acceptance_failed=acceptance_failed)
    if stop_requested:
        return FinalExitDecision(exit_code=130, acceptance_failed=acceptance_failed)
    if has_fail or acceptance_failed:
        return FinalExitDecision(exit_code=1, acceptance_failed=acceptance_failed)
    return FinalExitDecision(exit_code=0, acceptance_failed=False)


def derive_final_rewrite_reason(
    *,
    exploit_rewrite_stop_reason: str,
    fuse_reason: str,
    session_last_error: str,
    terminal_stage: str,
) -> str:
    return (
        str(exploit_rewrite_stop_reason or "").strip()
        or str(fuse_reason or "").strip()
        or str(session_last_error or "").strip()
        or f"{terminal_stage} not solved after rewrite budget"
    )


def build_final_output_doc(
    *,
    session_id: str,
    state_rel: str,
    report_rel: str,
    metrics_rel: str,
    fast_mode: bool,
    fuse_triggered: bool,
    fuse_reason: str,
    acceptance_report: str,
    acceptance_passed: bool,
    timeline_report: str,
    timing_report: str,
    exploit_rewrite_report: str,
    exit_code: int,
    stage_results: list[dict],
    notes: list[str],
) -> dict:
    return {
        "session_id": session_id,
        "state": state_rel,
        "report": report_rel,
        "metrics": metrics_rel,
        "fast_mode": fast_mode,
        "fuse_triggered": fuse_triggered,
        "fuse_reason": fuse_reason,
        "acceptance_report": acceptance_report,
        "acceptance_passed": acceptance_passed,
        "timeline_report": timeline_report,
        "timing_report": timing_report,
        "exploit_rewrite_report": exploit_rewrite_report,
        "exit_code": int(exit_code),
        "stage_results": stage_results,
        "notes": notes,
    }
