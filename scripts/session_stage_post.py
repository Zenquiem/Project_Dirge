#!/usr/bin/env python3
from __future__ import annotations

import glob
import json
import os
from typing import Any, Callable, Dict, List


def update_stage_timing_state(
    *,
    state_path: str,
    stage: str,
    loop_idx: int,
    started_utc: str,
    ended_utc: str,
    elapsed_sec: float,
    attempts: int,
    ok: bool,
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    utc_now_fn: Callable[[], str],
) -> None:
    state = load_json_fn(state_path)
    progress = state.setdefault("progress", {})
    timing = progress.setdefault("timing", {})
    stages = timing.setdefault("stages", {})
    duration_ms = int(max(0.0, float(elapsed_sec or 0.0)) * 1000.0)
    rec = {
        "loop": int(loop_idx),
        "stage": str(stage).strip(),
        "started_utc": str(started_utc or "").strip(),
        "ended_utc": str(ended_utc or "").strip(),
        "duration_ms": duration_ms,
        "attempts": int(attempts or 0),
        "ok": bool(ok),
    }
    st = stages.setdefault(stage, {})
    st.update(rec)
    hist = st.get("history", []) if isinstance(st.get("history", []), list) else []
    hist.append(rec)
    st["history"] = hist[-12:]
    stage_durations = progress.setdefault("stage_durations", {})
    sd = stage_durations.setdefault(stage, {})
    sd["last_duration_ms"] = duration_ms
    sd["last_duration_sec"] = round(duration_ms / 1000.0, 3)
    sd["last_loop"] = int(loop_idx)
    sd["last_ok"] = bool(ok)
    totals = progress.setdefault("stage_duration_totals_ms", {})
    prev_total = totals.get(stage, 0)
    try:
        prev_total_i = int(prev_total or 0)
    except Exception:
        prev_total_i = 0
    totals[stage] = int(max(0, prev_total_i + duration_ms))
    timing["last_stage"] = str(stage).strip()
    timing["last_updated_utc"] = utc_now_fn()
    save_json_fn(state_path, state)


def refresh_global_kpi(
    *,
    root_dir: str,
    global_path: str,
    current_metrics: Any,
    metrics_from_dict_fn: Callable[[Dict[str, Any]], Any],
    write_global_kpi_fn: Callable[[str, List[Any]], None],
) -> None:
    all_metrics: List[Any] = []
    for p in glob.glob(os.path.join(root_dir, "sessions", "*", "metrics.json")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                all_metrics.append(metrics_from_dict_fn(json.load(f)))
        except Exception:
            continue
    if current_metrics.session_id not in {m.session_id for m in all_metrics}:
        all_metrics.append(current_metrics)
    write_global_kpi_fn(global_path, all_metrics)


def write_realtime_kpi_snapshot(
    *,
    enabled: bool,
    metrics: Any,
    per_session_abs: str,
    global_kpi_abs: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    started_utc: str,
    ended_utc: str,
    elapsed_sec: float,
    ok: bool,
    rc: int,
    failure_category: str,
    tx_meta_rel: str,
    log_rel: str,
    refresh_global_kpi_fn: Callable[[str, Any], None],
    load_json_fn: Callable[[str], Dict[str, Any]],
    repo_rel_fn: Callable[[str], str],
    utc_now_fn: Callable[[], str],
) -> None:
    if not enabled:
        return
    try:
        metrics.save(per_session_abs)
        refresh_global_kpi_fn(global_kpi_abs, metrics)
    except Exception:
        return
    try:
        doc = load_json_fn(global_kpi_abs) if os.path.exists(global_kpi_abs) else {}
    except Exception:
        doc = {}
    if not isinstance(doc, dict):
        doc = {}
    stage_event = {
        "updated_utc": utc_now_fn(),
        "session_id": str(session_id).strip(),
        "loop": int(loop_idx),
        "stage": str(stage).strip(),
        "ok": bool(ok),
        "rc": int(rc),
        "failure_category": str(failure_category or "").strip(),
        "started_utc": str(started_utc or "").strip(),
        "ended_utc": str(ended_utc or "").strip(),
        "duration_ms": int(max(0.0, float(elapsed_sec or 0.0)) * 1000.0),
        "elapsed_sec": round(max(0.0, float(elapsed_sec or 0.0)), 3),
        "tx_meta": str(tx_meta_rel or "").strip(),
        "log": str(log_rel or "").strip(),
    }
    doc["updated_utc"] = stage_event["updated_utc"]
    doc["current_session_id"] = str(session_id).strip()
    doc["current_session_metrics"] = repo_rel_fn(per_session_abs)
    doc["latest_stage_event"] = stage_event
    try:
        with open(global_kpi_abs, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
    except Exception:
        return


def tx_prefix(root_dir: str, session_id: str, loop_idx: int, stage: str) -> str:
    return os.path.join(root_dir, "sessions", session_id, "transactions", f"{loop_idx:02d}_{stage}")


def write_tx_snapshot(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    kind: str,
    state: Dict[str, Any],
    repo_rel_fn: Callable[[str], str],
) -> str:
    path = f"{tx_prefix(root_dir, session_id, loop_idx, stage)}.{kind}.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    return repo_rel_fn(path)


def write_tx_meta(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    data: Dict[str, Any],
    repo_rel_fn: Callable[[str], str],
) -> str:
    path = f"{tx_prefix(root_dir, session_id, loop_idx, stage)}.meta.json"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return repo_rel_fn(path)


def next_loop_index(*, root_dir: str, session_id: str) -> int:
    tx_dir = os.path.join(root_dir, "sessions", session_id, "transactions")
    if not os.path.isdir(tx_dir):
        return 1
    max_loop = 0
    for name in os.listdir(tx_dir):
        if not name.endswith(".meta.json"):
            continue
        head = name.split("_", 1)[0]
        if head.isdigit():
            max_loop = max(max_loop, int(head))
    return max_loop + 1


def _extract_last_prompt_hint(log_path: str, tail_text_file_fn: Callable[[str, int], str], shorten_text_fn: Callable[[str, int], str]) -> str:
    txt = tail_text_file_fn(log_path, max_bytes=28000)
    if not txt:
        return ""
    lines = [x.strip() for x in txt.splitlines() if x.strip()]
    if not lines:
        return ""
    hints = ("choice", "menu", "option", "prompt", "choose")
    for line in reversed(lines[-120:]):
        low = line.lower()
        if any(h in low for h in hints):
            return shorten_text_fn(line, 220)
    return shorten_text_fn(lines[-1], 220)


def build_failure_context(
    *,
    root_dir: str,
    stage: str,
    rc: int,
    err: str,
    failure_category: str,
    attempt_records: List[Dict[str, Any]],
    log_rel: str,
    exp_verify_report: str,
    tail_text_file_fn: Callable[[str, int], str],
    detect_stage_log_signature_fn: Callable[[str], str],
    read_verify_report_detail_fn: Callable[[str, int], Dict[str, Any]],
    shorten_text_fn: Callable[[str, int], str],
    utc_now_fn: Callable[[], str],
) -> Dict[str, Any]:
    log_abs = os.path.join(root_dir, log_rel) if log_rel else ""
    log_tail = tail_text_file_fn(log_abs, max_bytes=18000) if (log_abs and os.path.exists(log_abs)) else ""
    log_signature = detect_stage_log_signature_fn(log_abs) if (log_abs and os.path.exists(log_abs)) else ""
    verify_detail: Dict[str, Any] = {}
    if exp_verify_report:
        verify_detail = read_verify_report_detail_fn(exp_verify_report, max_error_chars=220)
    ctx: Dict[str, Any] = {
        "generated_utc": utc_now_fn(),
        "stage": str(stage).strip(),
        "rc": int(rc or 0),
        "error": shorten_text_fn(str(err or "").strip(), 400),
        "failure_category": str(failure_category or "").strip(),
        "attempt_count": len(attempt_records),
        "retry_index": int(attempt_records[-1].get("attempt", 0) or 0) if attempt_records else 0,
        "log": str(log_rel or "").strip(),
        "log_signature": str(log_signature or "").strip(),
        "last_prompt_hint": _extract_last_prompt_hint(log_abs, tail_text_file_fn, shorten_text_fn) if log_abs else "",
        "log_tail_excerpt": shorten_text_fn(log_tail, 700),
        "verify_report": str(exp_verify_report or "").strip(),
    }
    if verify_detail:
        ctx["verify"] = {
            "run_rc": verify_detail.get("run_rc", None),
            "run_timeout": verify_detail.get("run_timeout", None),
            "last_error": shorten_text_fn(str(verify_detail.get("last_error", "")).strip(), 260),
            "run_steps_summary": shorten_text_fn(str(verify_detail.get("run_steps_summary", "")).strip(), 260),
            "runtime_findings": (
                verify_detail.get("runtime_findings", [])
                if isinstance(verify_detail.get("runtime_findings", []), list)
                else []
            )[:4],
            "stage_evidence": verify_detail.get("stage_evidence", {}),
        }
    return ctx


def write_failure_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    reason: str,
    tx_meta_rel: str,
    log_rel: str,
    context: Dict[str, Any] | None,
    shorten_text_fn: Callable[[str, int], str],
    utc_now_fn: Callable[[], str],
) -> str:
    out_rel = f"artifacts/reports/failure_{session_id}_{loop_idx:02d}_{stage}.md"
    out_abs = os.path.join(root_dir, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    context_rel = ""
    ctx_obj = context if isinstance(context, dict) else {}
    if ctx_obj:
        context_rel = f"artifacts/reports/failure_ctx_{session_id}_{loop_idx:02d}_{stage}.json"
        context_abs = os.path.join(root_dir, context_rel)
        os.makedirs(os.path.dirname(context_abs), exist_ok=True)
        with open(context_abs, "w", encoding="utf-8") as f:
            json.dump(ctx_obj, f, ensure_ascii=False, indent=2)
    lines = [
        f"# Stage Failure: {session_id} / {stage}",
        "",
        f"- generated_utc: {utc_now_fn()}",
        f"- loop: {loop_idx}",
        f"- stage: {stage}",
        f"- reason: {reason}",
        f"- tx_meta: {tx_meta_rel}",
        f"- stage_log: {log_rel}",
    ]
    if context_rel:
        lines.append(f"- context_json: {context_rel}")
        if str(ctx_obj.get("failure_category", "")).strip():
            lines.append(f"- failure_category: {ctx_obj.get('failure_category')}")
        if str(ctx_obj.get("last_prompt_hint", "")).strip():
            lines.append(f"- last_prompt_hint: {ctx_obj.get('last_prompt_hint')}")
        verify_obj = ctx_obj.get("verify", {}) if isinstance(ctx_obj.get("verify", {}), dict) else {}
        if verify_obj:
            lines.append(
                "- verify: "
                + f"run_rc={verify_obj.get('run_rc')}, timeout={verify_obj.get('run_timeout')}, "
                + f"last_error={shorten_text_fn(str(verify_obj.get('last_error', '')).strip(), 140)}"
            )
    with open(out_abs, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return out_rel
