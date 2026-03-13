#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else []


def _safe_dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        low = v.strip().lower()
        if low in {"1", "true", "yes", "y"}:
            return True
        if low in {"0", "false", "no", "n"}:
            return False
    return default


@dataclass
class CapabilityInference:
    before: Dict[str, Any]
    after: Dict[str, Any]
    changed: bool
    reasons: List[str]


def _collect_hypo_types(state: Dict[str, Any]) -> List[str]:
    static = _safe_dict(state.get("static_analysis"))
    hypos = _safe_list(static.get("hypotheses"))
    out: List[str] = []
    for h in hypos:
        if not isinstance(h, dict):
            continue
        t = str(h.get("type", "")).strip().lower()
        if t:
            out.append(t)
    return out


def _extract_top_cluster_count(state: Dict[str, Any]) -> int:
    dynamic = _safe_dict(state.get("dynamic_evidence"))
    clusters = _safe_list(dynamic.get("clusters"))
    if not clusters:
        return 0
    top = clusters[0] if isinstance(clusters[0], dict) else {}
    try:
        return int(top.get("count", 0) or 0)
    except Exception:
        return 0


def _find_system_observed(state: Dict[str, Any]) -> bool:
    dynamic = _safe_dict(state.get("dynamic_evidence"))
    evid = _safe_list(dynamic.get("evidence"))
    for ev in evid:
        if not isinstance(ev, dict):
            continue
        g = _safe_dict(ev.get("gdb"))
        if _as_bool(g.get("system_call_observed"), default=False):
            return True
        bt = g.get("bt", g.get("backtrace", ""))
        if isinstance(bt, str) and "system" in bt:
            return True
    return False


def _find_control_rip(state: Dict[str, Any]) -> Tuple[bool, int]:
    dynamic = _safe_dict(state.get("dynamic_evidence"))
    evid = _safe_list(dynamic.get("evidence"))
    if evid:
        for ev in reversed(evid):
            if not isinstance(ev, dict):
                continue
            g = _safe_dict(ev.get("gdb"))
            if _as_bool(g.get("control_rip"), default=False):
                try:
                    return True, int(g.get("offset_to_rip", 0) or 0)
                except Exception:
                    return True, 0
            try:
                off = int(g.get("offset_to_rip", 0) or 0)
            except Exception:
                off = 0
            if off > 0:
                return True, off
        return False, 0

    caps = _safe_dict(state.get("capabilities"))
    if _as_bool(caps.get("control_rip"), default=False):
        off = caps.get("offset_to_rip")
        try:
            return True, int(off)
        except Exception:
            return True, 0
    return False, 0


def _find_offset_candidates(state: Dict[str, Any]) -> Tuple[int, int]:
    dynamic = _safe_dict(state.get("dynamic_evidence"))
    evid = _safe_list(dynamic.get("evidence"))
    if evid:
        for ev in reversed(evid):
            if not isinstance(ev, dict):
                continue
            g = _safe_dict(ev.get("gdb"))
            try:
                fault = int(g.get("fault_offset_candidate", 0) or 0)
            except Exception:
                fault = 0
            try:
                static = int(g.get("static_offset_candidate", 0) or 0)
            except Exception:
                static = 0
            if fault > 0 or static > 0:
                return fault, static
        return 0, 0

    caps = _safe_dict(state.get("capabilities"))
    try:
        fault = int(caps.get("fault_offset_candidate", 0) or 0)
    except Exception:
        fault = 0
    try:
        static = int(caps.get("static_offset_candidate", 0) or 0)
    except Exception:
        static = 0
    if fault > 0 or static > 0:
        return fault, static

    static_analysis = _safe_dict(state.get("static_analysis"))
    try:
        static_guess = int(static_analysis.get("stack_smash_offset_guess", 0) or 0)
    except Exception:
        static_guess = 0
    return 0, static_guess


def infer_capabilities(state: Dict[str, Any], infer_cfg: Dict[str, Any]) -> CapabilityInference:
    caps = _safe_dict(state.get("capabilities"))
    before = dict(caps)
    after = dict(caps)
    reasons: List[str] = []

    dynamic = _safe_dict(state.get("dynamic_evidence"))
    evid = _safe_list(dynamic.get("evidence"))
    has_crash = len(evid) > 0
    if after.get("has_crash") != has_crash:
        reasons.append(f"has_crash <- {has_crash} (evidence={len(evid)})")
    after["has_crash"] = has_crash

    stability_threshold = int(infer_cfg.get("crash_stability_threshold", 2) or 2)
    top_cluster_count = _extract_top_cluster_count(state)
    crash_stable = top_cluster_count >= stability_threshold
    if after.get("crash_stable") != crash_stable:
        reasons.append(f"crash_stable <- {crash_stable} (top_cluster_count={top_cluster_count})")
    after["crash_stable"] = crash_stable

    hypo_types = _collect_hypo_types(state)
    stackish = any(t in {"stack_overflow", "ret2win", "ret2libc", "ret2shellcode"} for t in hypo_types)
    sigsegv_seen = False
    for ev in evid:
        if not isinstance(ev, dict):
            continue
        g = _safe_dict(ev.get("gdb"))
        sig = str(g.get("signal", "")).upper()
        if sig == "SIGSEGV":
            sigsegv_seen = True
            break
    stack_smash = stackish or sigsegv_seen
    if after.get("stack_smash_suspected") != stack_smash:
        reasons.append(f"stack_smash_suspected <- {stack_smash}")
    after["stack_smash_suspected"] = stack_smash

    control_rip, off = _find_control_rip(state)
    if after.get("control_rip") != control_rip:
        reasons.append(f"control_rip <- {control_rip}")
    after["control_rip"] = control_rip
    if control_rip and off > 0:
        prev_off = after.get("offset_to_rip")
        if prev_off != off:
            reasons.append(f"offset_to_rip <- {off}")
        after["offset_to_rip"] = off
    elif "offset_to_rip" in after:
        reasons.append("offset_to_rip cleared")
        after.pop("offset_to_rip", None)

    fault_offset_candidate, static_offset_candidate = _find_offset_candidates(state)
    if fault_offset_candidate > 0:
        if after.get("fault_offset_candidate") != fault_offset_candidate:
            reasons.append(f"fault_offset_candidate <- {fault_offset_candidate}")
        after["fault_offset_candidate"] = fault_offset_candidate
    elif "fault_offset_candidate" in after:
        reasons.append("fault_offset_candidate cleared")
        after.pop("fault_offset_candidate", None)

    if static_offset_candidate > 0:
        if after.get("static_offset_candidate") != static_offset_candidate:
            reasons.append(f"static_offset_candidate <- {static_offset_candidate}")
        after["static_offset_candidate"] = static_offset_candidate
    elif "static_offset_candidate" in after:
        reasons.append("static_offset_candidate cleared")
        after.pop("static_offset_candidate", None)

    rip_control = "unknown"
    if control_rip:
        rip_control = "yes"
    elif has_crash:
        rip_control = "no"
    if str(after.get("rip_control", "unknown")) != rip_control:
        reasons.append(f"rip_control <- {rip_control}")
    after["rip_control"] = rip_control

    has_leak = "unknown"
    if any(t in {"fmt", "ret2libc"} for t in hypo_types):
        has_leak = "possible"
    for ev in evid:
        if not isinstance(ev, dict):
            continue
        g = _safe_dict(ev.get("gdb"))
        if _as_bool(g.get("leak_observed"), default=False):
            has_leak = "yes"
            break
    if str(after.get("has_leak", "unknown")) != has_leak:
        reasons.append(f"has_leak <- {has_leak}")
    after["has_leak"] = has_leak

    write_prim = "unknown"
    if any(t in {"uaf", "heap_related"} for t in hypo_types):
        write_prim = "possible"
    if str(after.get("write_primitive", "unknown")) != write_prim:
        reasons.append(f"write_primitive <- {write_prim}")
    after["write_primitive"] = write_prim

    exp = _safe_dict(_safe_dict(state.get("session")).get("exp"))
    local_verify_passed = _as_bool(exp.get("local_verify_passed"), default=False)
    exp_strategy = str(exp.get("strategy", "")).strip().lower()

    ret2win_verified = _as_bool(after.get("ret2win_path_verified"), default=False)
    if not ret2win_verified:
        for h in _safe_list(_safe_dict(state.get("hypotheses")).get("active")):
            if not isinstance(h, dict):
                continue
            if str(h.get("type", "")).strip().lower() == "ret2win" and _as_bool(h.get("verified"), default=False):
                ret2win_verified = True
                break
    if not ret2win_verified and local_verify_passed and exp_strategy == "ret2win":
        ret2win_verified = True
    if _as_bool(after.get("ret2win_path_verified"), default=False) != ret2win_verified:
        reasons.append(f"ret2win_path_verified <- {ret2win_verified}")
    after["ret2win_path_verified"] = ret2win_verified

    system_observed = _as_bool(after.get("system_call_observed"), default=False) or _find_system_observed(state)
    if _as_bool(after.get("system_call_observed"), default=False) != system_observed:
        reasons.append(f"system_call_observed <- {system_observed}")
    after["system_call_observed"] = system_observed

    exploit_success = _as_bool(after.get("exploit_success"), default=False)
    if local_verify_passed:
        exploit_success = True
    if _as_bool(after.get("exploit_success"), default=False) != exploit_success:
        reasons.append(f"exploit_success <- {exploit_success}")
    after["exploit_success"] = exploit_success

    changed = before != after
    state["capabilities"] = after
    return CapabilityInference(before=before, after=after, changed=changed, reasons=reasons)


def write_capability_report(
    *,
    root_dir: str,
    session_id: str,
    loop_idx: int,
    inf: CapabilityInference,
) -> str:
    rel = f"artifacts/reports/capabilities_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(root_dir, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": loop_idx,
        "changed": inf.changed,
        "reasons": inf.reasons,
        "before": inf.before,
        "after": inf.after,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel
