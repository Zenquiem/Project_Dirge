from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def exploit_stage_level(stage: str) -> int:
    normalized = str(stage).strip().lower()
    if not normalized.startswith("exploit_l"):
        return -1
    tail = normalized[len("exploit_l") :]
    return int(tail) if tail.isdigit() else -1


def terminal_exploit_stage(stages: List[str]) -> str:
    best = ""
    best_level = -1
    for stage in stages:
        level = exploit_stage_level(stage)
        if level > best_level:
            best_level = level
            best = stage
    return best if best_level >= 0 else ""


def ensure_terminal_stage_last(stages: List[str], terminal_stage: str) -> List[str]:
    if not terminal_stage:
        return stages
    ordered = [stage for stage in stages if stage != terminal_stage]
    ordered.append(terminal_stage)
    deduped: List[str] = []
    seen = set()
    for stage in ordered:
        if stage in seen:
            continue
        seen.add(stage)
        deduped.append(stage)
    return deduped


def stage_counter_key(stage: str) -> str:
    if exploit_stage_level(stage) >= 0:
        return "exploit_runs"
    return {
        "recon": "recon_runs",
        "ida_slice": "ida_calls",
        "gdb_evidence": "gdb_runs",
    }.get(stage, "")


def ensure_counter_progress(before: Dict[str, Any], after: Dict[str, Any], stage: str) -> Dict[str, Any]:
    progress = after.setdefault("progress", {})
    before_progress = before.get("progress", {}) if isinstance(before.get("progress", {}), dict) else {}

    counters = progress.setdefault("counters", {})
    before_counters = before_progress.get("counters", {}) if isinstance(before_progress.get("counters", {}), dict) else {}

    run_seq = int(progress.get("run_seq", 0) or 0)
    before_run_seq = int(before_progress.get("run_seq", 0) or 0)
    if run_seq <= before_run_seq:
        progress["run_seq"] = before_run_seq + 1

    total_runs = int(counters.get("total_runs", 0) or 0)
    before_total = int(before_counters.get("total_runs", 0) or 0)
    if total_runs <= before_total:
        counters["total_runs"] = before_total + 1

    counter_key = stage_counter_key(stage)
    if counter_key:
        current_stage_count = int(counters.get(counter_key, 0) or 0)
        previous_stage_count = int(before_counters.get(counter_key, 0) or 0)
        if current_stage_count <= previous_stage_count:
            counters[counter_key] = previous_stage_count + 1

    progress["stage"] = stage
    progress["last_updated_utc"] = utc_now()
    return after
