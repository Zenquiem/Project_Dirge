#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Tuple


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_summary_report(
    path: str,
    session_id: str,
    stage_results: List[Dict[str, Any]],
    state: Dict[str, Any],
    notes: List[str],
    utc_now_fn: Callable[[], str] | None = None,
) -> None:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    lines = []
    lines.append(f"# Session Summary: {session_id}")
    lines.append("")
    lines.append(f"- generated_utc: {now}")
    lines.append(f"- stage: {state.get('progress', {}).get('stage', '')}")
    lines.append(f"- no_progress_loops: {state.get('progress', {}).get('decision', {}).get('no_progress_loops', 0)}")
    lines.append(f"- objective_score: {state.get('progress', {}).get('objectives', {}).get('score', 0)}")
    lines.append(f"- objective_target_achieved: {state.get('progress', {}).get('objectives', {}).get('target_achieved', False)}")
    lines.append(
        f"- competition_target_achieved: {state.get('progress', {}).get('objectives', {}).get('competition_target_achieved', False)}"
    )
    lines.append(f"- binary: {state.get('challenge', {}).get('binary_path', '')}")
    lines.append(f"- exp_path: {state.get('session', {}).get('exp', {}).get('path', '')}")
    lines.append(f"- exp_status: {state.get('session', {}).get('exp', {}).get('status', '')}")
    lines.append(f"- exp_local_verify_passed: {state.get('session', {}).get('exp', {}).get('local_verify_passed', False)}")
    lines.append(f"- allow_remote_exp: {state.get('project', {}).get('features', {}).get('allow_remote_exp', False)}")
    lines.append("")
    lines.append("## Stage Results")
    for item in stage_results:
        lines.append(
            f"- loop={item.get('loop')} stage={item.get('stage')} ok={item.get('ok')} "
            f"rc={item.get('rc')} log={item.get('log')} tx={item.get('tx_meta','')}"
        )
    if notes:
        lines.append("")
        lines.append("## Notes")
        for n in notes:
            lines.append(f"- {n}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def _parse_utc_ts(raw: str) -> datetime | None:
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _derive_manual_timing_rows(
    stage_results: List[Dict[str, Any]],
    state: Dict[str, Any],
    exploit_stage_level_fn: Callable[[str], int],
) -> List[Dict[str, Any]]:
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    local_verified_utc = str(exp.get("local_verified_utc", "")).strip()
    remote_verified_utc = str(remote.get("remote_verified_utc", "") or remote.get("last_remote_ok_utc", "")).strip()
    last_terminal_end = ""
    last_terminal_stage = ""
    for item in stage_results:
        if not isinstance(item, dict):
            continue
        stage = str(item.get("stage", "")).strip()
        if exploit_stage_level_fn(stage) < 0:
            continue
        ended_utc = str(item.get("ended_utc", "")).strip()
        if ended_utc:
            last_terminal_end = ended_utc
            last_terminal_stage = stage
    out: List[Dict[str, Any]] = []

    def _append(stage: str, started_utc: str, ended_utc: str, source_stage: str) -> None:
        dt0 = _parse_utc_ts(started_utc)
        dt1 = _parse_utc_ts(ended_utc)
        if dt0 is None or dt1 is None:
            return
        ms = int(max(0.0, (dt1 - dt0).total_seconds()) * 1000.0)
        if ms <= 0:
            return
        out.append(
            {
                "loop": 0,
                "stage": stage,
                "ok": True,
                "rc": 0,
                "started_utc": started_utc,
                "ended_utc": ended_utc,
                "duration_ms": ms,
                "elapsed_sec": round(float(ms) / 1000.0, 3),
                "attempts": 1,
                "failure_category": "",
                "log": "",
                "tx_meta": "",
                "derived": True,
                "source_stage": source_stage,
            }
        )

    if last_terminal_end and local_verified_utc:
        _append("manual_local_exploit", last_terminal_end, local_verified_utc, last_terminal_stage or "exploit")
    if local_verified_utc and remote_verified_utc:
        _append("manual_remote_adapt", local_verified_utc, remote_verified_utc, "remote_verify")
    return out


def write_timeline_report(
    root_dir: str,
    session_id: str,
    stage_results: List[Dict[str, Any]],
    metrics: Any,
    state: Dict[str, Any] | None = None,
    exploit_stage_level_fn: Callable[[str], int] | None = None,
    utc_now_fn: Callable[[], str] | None = None,
) -> str:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    out_rel = f"artifacts/reports/timeline_{session_id}.json"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    events: List[Dict[str, Any]] = []
    for item in stage_results:
        tx_rel = str(item.get("tx_meta", "")).strip()
        started_utc = ""
        ended_utc = ""
        if tx_rel:
            tx_abs = os.path.join(root_dir, tx_rel)
            if os.path.exists(tx_abs):
                try:
                    with open(tx_abs, "r", encoding="utf-8") as f:
                        tx = json.load(f)
                    started_utc = str(tx.get("started_utc", "")).strip()
                    ended_utc = str(tx.get("ended_utc", "")).strip()
                except Exception:
                    started_utc = ""
                    ended_utc = ""
        events.append(
            {
                "loop": int(item.get("loop", 0) or 0),
                "stage": str(item.get("stage", "")).strip(),
                "ok": bool(item.get("ok", False)),
                "rc": int(item.get("rc", 0) or 0),
                "started_utc": started_utc,
                "ended_utc": ended_utc,
                "duration_ms": int(item.get("duration_ms", int(float(item.get("elapsed_sec", 0.0) or 0.0) * 1000.0)) or 0),
                "elapsed_sec": float(item.get("elapsed_sec", 0.0) or 0.0),
                "attempts": int(item.get("attempts", 0) or 0),
                "failure_category": str(item.get("failure_category", "")).strip(),
                "log": str(item.get("log", "")).strip(),
                "tx_meta": tx_rel,
            }
        )
    if isinstance(state, dict) and callable(exploit_stage_level_fn):
        events.extend(_derive_manual_timing_rows(stage_results, state, exploit_stage_level_fn))

    doc = {
        "generated_utc": now,
        "session_id": session_id,
        "wall_time_sec": float(metrics.wall_time_sec),
        "stage_wall_total_sec": float(metrics.stage_wall_total_sec),
        "stage_wall_sec": dict(metrics.stage_wall_sec),
        "events": events,
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return out_rel


def write_timing_report(
    root_dir: str,
    session_id: str,
    stage_results: List[Dict[str, Any]],
    metrics: Any,
    state: Dict[str, Any] | None = None,
    exploit_stage_level_fn: Callable[[str], int] | None = None,
    utc_now_fn: Callable[[], str] | None = None,
) -> str:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    out_rel = f"artifacts/reports/timing_{session_id}.json"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    rows: List[Dict[str, Any]] = []
    stage_totals: Dict[str, int] = {}
    total_ms = 0
    all_items = list(stage_results)
    if isinstance(state, dict) and callable(exploit_stage_level_fn):
        all_items.extend(_derive_manual_timing_rows(stage_results, state, exploit_stage_level_fn))
    for item in all_items:
        stage = str(item.get("stage", "")).strip()
        ms = int(item.get("duration_ms", int(float(item.get("elapsed_sec", 0.0) or 0.0) * 1000.0)) or 0)
        ms = max(0, ms)
        total_ms += ms
        stage_totals[stage] = stage_totals.get(stage, 0) + ms
        rows.append(
            {
                "loop": int(item.get("loop", 0) or 0),
                "stage": stage,
                "ok": bool(item.get("ok", False)),
                "rc": int(item.get("rc", 0) or 0),
                "started_utc": str(item.get("started_utc", "")).strip(),
                "ended_utc": str(item.get("ended_utc", "")).strip(),
                "duration_ms": ms,
                "attempts": int(item.get("attempts", 0) or 0),
                "failure_category": str(item.get("failure_category", "")).strip(),
                "tx_meta": str(item.get("tx_meta", "")).strip(),
                "derived": bool(item.get("derived", False)),
                "source_stage": str(item.get("source_stage", "")).strip(),
            }
        )

    by_stage: List[Dict[str, Any]] = []
    for stage, ms in sorted(stage_totals.items(), key=lambda x: x[1], reverse=True):
        pct = (float(ms) / float(total_ms) * 100.0) if total_ms > 0 else 0.0
        by_stage.append({"stage": stage, "duration_ms": int(ms), "ratio_pct": round(pct, 2)})

    doc = {
        "generated_utc": now,
        "session_id": session_id,
        "total_duration_ms": int(total_ms),
        "total_duration_sec": round(float(total_ms) / 1000.0, 3),
        "wall_time_sec": float(metrics.wall_time_sec),
        "stage_wall_total_sec": float(metrics.stage_wall_total_sec),
        "by_stage": by_stage,
        "timeout_circuit": {
            "activations": int(metrics.timeout_circuit_activations),
            "skips": int(metrics.timeout_circuit_skips),
        },
        "events": rows,
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return out_rel


def write_exploit_rewrite_report(
    root_dir: str,
    session_id: str,
    terminal_stage: str,
    reason: str,
    solved: bool,
    loops_executed: int,
    base_max_loops: int,
    extra_loops_budget: int,
    rewrite_elapsed_sec: float,
    same_error_streak: int,
    non_actionable_verify_streak: int,
    last_error: str,
    last_verify_report: str,
    exp_path: str,
    stage_results: List[Dict[str, Any]],
    metrics: Any,
    shorten_text_fn: Callable[[str, int], str],
    utc_now_fn: Callable[[], str] | None = None,
) -> str:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    out_rel = f"artifacts/reports/exploit_rewrite_{session_id}.json"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    fail_counts: Dict[str, int] = {}
    stage_fail_counts: Dict[str, int] = {}
    ida_timeout_count = 0
    terminal_results: List[Dict[str, Any]] = []
    for rec in stage_results:
        if not isinstance(rec, dict):
            continue
        st = str(rec.get("stage", "")).strip()
        ok = bool(rec.get("ok", False))
        cat = str(rec.get("failure_category", "")).strip()
        if st == terminal_stage:
            terminal_results.append(
                {
                    "loop": int(rec.get("loop", 0) or 0),
                    "ok": ok,
                    "rc": int(rec.get("rc", 0) or 0),
                    "failure_category": cat,
                    "exp_verify_ok": rec.get("exp_verify_ok", None),
                    "exp_verify_report": str(rec.get("exp_verify_report", "")).strip(),
                    "exp_autofix_attempts": int(rec.get("exp_autofix_attempts", 0) or 0),
                    "exp_autofix_last_error": shorten_text_fn(str(rec.get("exp_autofix_last_error", "")).strip(), 400),
                    "log": str(rec.get("log", "")).strip(),
                }
            )
        if ok:
            continue
        stage_fail_counts[st] = int(stage_fail_counts.get(st, 0) or 0) + 1
        key = cat or "unknown"
        fail_counts[key] = int(fail_counts.get(key, 0) or 0) + 1
        if st == "ida_slice" and key in {"timeout", "mcp_transient"}:
            ida_timeout_count += 1

    doc = {
        "generated_utc": now,
        "session_id": session_id,
        "terminal_stage": terminal_stage,
        "solved": bool(solved),
        "reason": str(reason or "").strip(),
        "loops_executed": int(loops_executed),
        "base_max_loops": int(base_max_loops),
        "extra_loops_budget": int(extra_loops_budget),
        "rewrite_elapsed_sec": round(max(0.0, float(rewrite_elapsed_sec or 0.0)), 3),
        "same_error_streak": int(max(0, int(same_error_streak or 0))),
        "non_actionable_verify_streak": int(max(0, int(non_actionable_verify_streak or 0))),
        "last_error": shorten_text_fn(str(last_error or "").strip(), 600),
        "last_verify_report": str(last_verify_report or "").strip(),
        "exp_path": str(exp_path or "").strip(),
        "failure_categories": fail_counts,
        "stage_failures": stage_fail_counts,
        "ida_timeout_or_mcp_failures": int(ida_timeout_count),
        "terminal_results": terminal_results[-8:],
        "metrics": {
            "wall_time_sec": round(float(metrics.wall_time_sec or 0.0), 3),
            "codex_calls": int(metrics.codex_calls),
            "prompt_chars_total": int(metrics.prompt_chars_total),
            "autofix_rounds_total": int(metrics.autofix_rounds_total),
            "exploit_attempts": int(metrics.exploit_attempts),
            "exploit_success": int(metrics.exploit_success),
            "timeout_circuit_activations": int(metrics.timeout_circuit_activations),
            "timeout_circuit_skips": int(metrics.timeout_circuit_skips),
        },
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return out_rel


def write_cost_fuse_report(
    root_dir: str,
    session_id: str,
    max_codex_calls: int,
    max_prompt_chars: int,
    max_wall_time_sec: float,
    max_autofix_rounds: int,
    metrics: Any,
    triggered: bool,
    reason: str,
    utc_now_fn: Callable[[], str] | None = None,
) -> str:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    out_rel = f"artifacts/reports/cost_fuse_{session_id}.json"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_utc": now,
                "session_id": session_id,
                "triggered": bool(triggered),
                "reason": reason,
                "limits": {
                    "max_codex_calls": max_codex_calls,
                    "max_prompt_chars": max_prompt_chars,
                    "max_wall_time_sec": max_wall_time_sec,
                    "max_autofix_rounds": max_autofix_rounds,
                },
                "usage": {
                    "codex_calls": int(metrics.codex_calls),
                    "prompt_chars_total": int(metrics.prompt_chars_total),
                    "wall_time_sec": float(metrics.wall_time_sec),
                    "autofix_rounds_total": int(metrics.autofix_rounds_total),
                    "timeout_circuit_activations": int(metrics.timeout_circuit_activations),
                    "timeout_circuit_skips": int(metrics.timeout_circuit_skips),
                },
            },
            f,
            ensure_ascii=False,
            indent=2,
        )
    return out_rel


def write_acceptance_report(
    root_dir: str,
    session_id: str,
    metrics: Any,
    final_state: Dict[str, Any],
    acceptance_cfg: Dict[str, Any],
    terminal_stage: str,
    exploit_stage_level_fn: Callable[[str], int],
    utc_now_fn: Callable[[], str] | None = None,
) -> Tuple[str, bool]:
    now = utc_now_fn() if callable(utc_now_fn) else _utc_now()
    enabled = bool(acceptance_cfg.get("enabled", False))
    out_rel = f"artifacts/reports/acceptance_{session_id}.json"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    checks: Dict[str, Dict[str, Any]] = {}
    reasons: List[str] = []
    passed = True

    if enabled:
        max_wall = float(acceptance_cfg.get("max_wall_time_sec", 0) or 0.0)
        max_calls = int(acceptance_cfg.get("max_codex_calls", 0) or 0)
        max_prompt = int(acceptance_cfg.get("max_prompt_chars_total", 0) or 0)
        req_terminal = str(acceptance_cfg.get("required_terminal_stage", terminal_stage)).strip() or terminal_stage
        state_enable_exploit = bool(final_state.get("project", {}).get("features", {}).get("enable_exploit", True))

        if max_wall > 0:
            ok = float(metrics.wall_time_sec) <= max_wall
            checks["wall_time_sec"] = {"ok": ok, "actual": float(metrics.wall_time_sec), "limit": max_wall}
            if not ok:
                passed = False
                reasons.append(f"wall_time_sec>{max_wall}")

        if max_calls > 0:
            ok = int(metrics.codex_calls) <= max_calls
            checks["codex_calls"] = {"ok": ok, "actual": int(metrics.codex_calls), "limit": max_calls}
            if not ok:
                passed = False
                reasons.append(f"codex_calls>{max_calls}")

        if max_prompt > 0:
            ok = int(metrics.prompt_chars_total) <= max_prompt
            checks["prompt_chars_total"] = {
                "ok": ok,
                "actual": int(metrics.prompt_chars_total),
                "limit": max_prompt,
            }
            if not ok:
                passed = False
                reasons.append(f"prompt_chars_total>{max_prompt}")

        if req_terminal and (state_enable_exploit or exploit_stage_level_fn(req_terminal) < 0):
            final_stage = str(final_state.get("progress", {}).get("stage", "")).strip()
            ok = final_stage == req_terminal
            checks["terminal_stage"] = {"ok": ok, "actual": final_stage, "required": req_terminal}
            if not ok:
                passed = False
                reasons.append(f"terminal_stage!={req_terminal}")
    else:
        checks["enabled"] = {"ok": True, "actual": False, "required": False}

    doc = {
        "generated_utc": now,
        "session_id": session_id,
        "enabled": enabled,
        "passed": passed,
        "reasons": reasons,
        "checks": checks,
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return out_rel, passed
