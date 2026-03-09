from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_strategy_route_switch_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    current_hint: str,
    current_strategy: str,
    next_hint: str,
    cycle: List[str],
    no_progress_loops: int,
    terminal_unsolved_streak: int,
    reason: str,
    recommend_hint: bool,
) -> str:
    rel = f"artifacts/reports/strategy_route_switch_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "current_hint": str(current_hint or ""),
        "current_strategy": str(current_strategy or ""),
        "next_hint": str(next_hint or ""),
        "cycle": [str(x).strip() for x in cycle if str(x).strip()],
        "no_progress_loops": int(no_progress_loops),
        "terminal_unsolved_streak": int(terminal_unsolved_streak),
        "reason": str(reason or "").strip(),
        "recommend_external_hint": bool(recommend_hint),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel


def write_hint_request_gate_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    no_progress_loops: int,
    no_new_evidence_sec: float,
    reasons: List[str],
) -> str:
    rel = f"artifacts/reports/hint_gate_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "no_progress_loops": int(no_progress_loops),
        "no_new_evidence_sec": round(max(0.0, float(no_new_evidence_sec or 0.0)), 3),
        "reasons": [str(x).strip() for x in reasons if str(x).strip()],
        "recommend_external_hint": True,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel


def write_timeout_no_evidence_gate_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    consecutive_timeout_loops: int,
    timeout_streak: int,
    rc124_failures_in_loop: int,
    no_progress_loops: int,
    no_new_evidence_sec: float,
    blind_mode: bool,
    reason: str,
) -> str:
    rel = f"artifacts/reports/timeout_no_evidence_gate_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "blind_mode": bool(blind_mode),
        "threshold_consecutive_timeout_loops": int(consecutive_timeout_loops),
        "timeout_streak": int(timeout_streak),
        "rc124_failures_in_loop": int(rc124_failures_in_loop),
        "no_progress_loops": int(no_progress_loops),
        "no_new_evidence_sec": round(max(0.0, float(no_new_evidence_sec or 0.0)), 3),
        "reason": str(reason or "").strip(),
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel
