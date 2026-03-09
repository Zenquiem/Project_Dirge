#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
DEFAULT_SCHEMA = os.path.join(ROOT_DIR, "state", "schema.json")
DEFAULT_POLICY = os.path.join(ROOT_DIR, "policy", "agent.yaml")
DEFAULT_BUDGET = os.path.join(ROOT_DIR, "policy", "budget.yaml")
DEFAULT_STAGE_CONTRACTS = os.path.join(ROOT_DIR, "policy", "stage_contracts.yaml")
DEFAULT_STAGE_RUNNER = os.path.join(ROOT_DIR, "policy", "stage_runner.yaml")
CACHE_SCHEMA_VERSION = 2
EXPLOIT_REWRITE_UNTIL_SUCCESS_LOOP_CAP = 1_000_000

sys.path.insert(0, ROOT_DIR)

from core.capability_engine import infer_capabilities, write_capability_report  # noqa: E402
from core.crash_cluster import cluster_evidence  # noqa: E402
from core.decision_engine import choose_stage_plan  # noqa: E402
from core.exploit_strategy import choose_exploit_strategy  # noqa: E402
from core.hypothesis_engine import HypothesisEngine  # noqa: E402
from core.input_mutator import generate_mutations, write_mutations  # noqa: E402
from core.mcp_adapters import CodexCLIAdapter, GDBAdapter, IDAAdapter, StageRequest  # noqa: E402
from core.metrics import SessionMetrics, write_global_kpi  # noqa: E402
from core.objective_engine import evaluate_objectives, write_objective_report  # noqa: E402
from core.plugins import generate_exp_stub  # noqa: E402
from core.recovery_engine import classify_failure, next_backoff_seconds, should_retry  # noqa: E402
from core.session_control import acquire_run_lock, clear_stop_request, read_stop_request, release_run_lock  # noqa: E402
from core.stage_runner import get_stage_spec, register_stage_receipt, stage_prompt_contract, write_stage_receipt  # noqa: E402
from core.stage_contracts import validate_stage_contract  # noqa: E402
from session_reports import (  # noqa: E402
    write_acceptance_report as _write_acceptance_report_impl,
    write_cost_fuse_report as _write_cost_fuse_report_impl,
    write_exploit_rewrite_report as _write_exploit_rewrite_report_impl,
    write_summary_report as _write_summary_report_impl,
    write_timeline_report as _write_timeline_report_impl,
    write_timing_report as _write_timing_report_impl,
)
from session_finish_policy import (  # noqa: E402
    build_final_output_doc as _build_final_output_doc_impl,
    derive_final_exit_decision as _derive_final_exit_decision_impl,
    derive_final_rewrite_reason as _derive_final_rewrite_reason_impl,
    derive_final_session_status as _derive_final_session_status_impl,
)
from session_attempt_policy import (  # noqa: E402
    evaluate_attempt_retry_policy as _evaluate_attempt_retry_policy_impl,
    should_use_cache_fallback as _should_use_cache_fallback_impl,
)
from session_attempt_runtime import finalize_attempt as _finalize_attempt_impl  # noqa: E402
from session_state_sync import (  # noqa: E402
    sync_meta_from_state as _sync_meta_from_state_impl,
    sync_state_meta_cli as _sync_state_meta_cli_impl,
)
from session_stage_records import (  # noqa: E402
    build_stage_result_record as _build_stage_result_record_impl,
    build_stage_tx_meta_doc as _build_stage_tx_meta_doc_impl,
)
from session_stage_post import (  # noqa: E402
    build_failure_context as _build_failure_context_impl,
    next_loop_index as _next_loop_index_impl,
    refresh_global_kpi as _refresh_global_kpi_impl,
    tx_prefix as _tx_prefix_impl,
    update_stage_timing_state as _update_stage_timing_state_impl,
    write_failure_report as _write_failure_report_impl,
    write_realtime_kpi_snapshot as _write_realtime_kpi_snapshot_impl,
    write_tx_meta as _write_tx_meta_impl,
    write_tx_snapshot as _write_tx_snapshot_impl,
)
from session_stage_finalize import finalize_stage_post_run as _finalize_stage_post_run_impl  # noqa: E402
from session_stage_flow import apply_post_stage_flow as _apply_post_stage_flow_impl  # noqa: E402
from session_loop_finalize import (  # noqa: E402
    apply_loop_decision_state as _apply_loop_decision_state_impl,
    evaluate_loop_stop as _evaluate_loop_stop_impl,
)
from session_run_finalize import finalize_run_outputs as _finalize_run_outputs_impl  # noqa: E402
from session_stage_outcome import (  # noqa: E402
    apply_stage_result_state as _apply_stage_result_state_impl,
    apply_stage_spec_check as _apply_stage_spec_check_impl,
)
from session_mcp_recovery import run_mcp_self_heal as _run_mcp_self_heal_impl  # noqa: E402
from session_mcp_gate import run_stage_mcp_gate as _run_stage_mcp_gate_impl  # noqa: E402
from session_exploit_runtime import (  # noqa: E402
    run_exploit_autofix as _run_exploit_autofix_impl,
    sync_exp_verify_artifacts as _sync_exp_verify_artifacts_impl,
)
from session_codex_stage import run_stage_codex as _run_stage_codex_impl  # noqa: E402
from session_stage_validation import run_stage_post_validation as _run_stage_post_validation_impl  # noqa: E402
from session_exploit_prepare import (  # noqa: E402
    run_exploit_plugin_stage as _run_exploit_plugin_stage_impl,
    run_terminal_exploit_precheck as _run_terminal_exploit_precheck_impl,
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def exploit_stage_level(stage: str) -> int:
    s = str(stage).strip().lower()
    if not s.startswith("exploit_l"):
        return -1
    tail = s[len("exploit_l") :]
    return int(tail) if tail.isdigit() else -1


def terminal_exploit_stage(stages: List[str]) -> str:
    best = ""
    best_lv = -1
    for st in stages:
        lv = exploit_stage_level(st)
        if lv > best_lv:
            best_lv = lv
            best = st
    return best if best_lv >= 0 else ""


def ensure_terminal_stage_last(stages: List[str], terminal_stage: str) -> List[str]:
    if not terminal_stage:
        return stages
    out = [x for x in stages if x != terminal_stage]
    out.append(terminal_stage)
    dedup: List[str] = []
    seen = set()
    for x in out:
        if x in seen:
            continue
        seen.add(x)
        dedup.append(x)
    return dedup


def detect_bundle_plan(
    stages: List[str],
    *,
    enabled: bool,
    include_exploit_stages: bool,
    require_consecutive: bool = True,
) -> Tuple[bool, str, List[str]]:
    if not enabled:
        return False, "", []
    core = ["recon", "ida_slice", "gdb_evidence"]
    present = [s for s in core if s in stages]
    if len(present) < 3:
        return False, "", []
    ordered = [s for s in stages if s in core]
    if include_exploit_stages:
        ordered.extend([s for s in stages if exploit_stage_level(s) >= 0])
    ordered = list(dict.fromkeys(ordered))
    if require_consecutive:
        idx = [stages.index(s) for s in core]
        if not (idx[0] < idx[1] < idx[2]):
            return False, "", []
    trigger = ordered[0] if ordered else ""
    return bool(trigger), trigger, ordered


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def try_load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def repo_rel(path: str) -> str:
    return os.path.relpath(os.path.abspath(path), ROOT_DIR)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def challenge_binary_sha256(state: Dict[str, Any]) -> str:
    binary = str(state.get("challenge", {}).get("binary_path", "")).strip()
    if not binary:
        return ""
    ap = binary if os.path.isabs(binary) else os.path.abspath(os.path.join(ROOT_DIR, binary))
    if (not os.path.exists(ap)) or (not os.path.isfile(ap)):
        return ""
    try:
        return file_sha256(ap)
    except Exception:
        return ""


def _elf_bits(path: str) -> int:
    try:
        with open(path, "rb") as f:
            hdr = f.read(5)
        if len(hdr) < 5 or hdr[:4] != b"\x7fELF":
            return 0
        klass = int(hdr[4])
        if klass == 1:
            return 32
        if klass == 2:
            return 64
    except Exception:
        return 0
    return 0


def _elf_arch(path: str) -> str:
    try:
        with open(path, "rb") as f:
            hdr = f.read(0x20)
        if len(hdr) < 0x14 or hdr[:4] != b"\x7fELF":
            return ""
        endian = hdr[5] if len(hdr) > 5 else 1
        if endian == 2:
            em = int.from_bytes(hdr[18:20], "big", signed=False)
        else:
            em = int.from_bytes(hdr[18:20], "little", signed=False)
        if em == 3:
            return "i386"
        if em == 62:
            return "amd64"
        if em == 40:
            return "arm"
        if em == 183:
            return "aarch64"
    except Exception:
        return ""
    return ""


def _abi_info(path: str) -> Dict[str, Any]:
    raw = str(path or "").strip()
    ap = os.path.abspath(raw) if raw else ""
    exists = bool(ap and os.path.isfile(ap))
    bits = _elf_bits(ap) if exists else 0
    arch = _elf_arch(ap) if exists else ""
    if (not arch) and bits == 64:
        arch = "amd64"
    elif (not arch) and bits == 32:
        arch = "i386"
    return {
        "path": ap,
        "exists": exists,
        "bits": int(bits or 0),
        "arch": str(arch or "").strip(),
        "name": os.path.basename(ap) if ap else "",
    }


def _looks_like_loader_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low in {"ld.so", "ld-linux.so.2", "ld-linux-x86-64.so.2"}:
        return True
    if low.startswith("ld-linux") and ".so" in low:
        return True
    if low.startswith("ld-") and ".so" in low:
        return True
    return False


def _looks_like_libc_name(name: str) -> bool:
    low = str(name or "").strip().lower()
    if not low:
        return False
    if low == "libc.so.6":
        return True
    if low.startswith("libc") and ".so" in low:
        return True
    return False


def _score_loader_name(name: str) -> int:
    low = str(name or "").strip().lower()
    score = 0
    if low in {"ld-linux-x86-64.so.2", "ld-linux.so.2"}:
        score += 180
    elif low.startswith("ld-linux") and ".so" in low:
        score += 160
    elif low.startswith("ld-") and ".so" in low:
        score += 130
    elif low == "ld.so":
        score += 90
    if "2.27" in low:
        score += 24
    if "x86-64" in low or "x86_64" in low:
        score += 8
    return score


def _score_libc_name(name: str) -> int:
    low = str(name or "").strip().lower()
    score = 0
    if low == "libc.so.6":
        score += 180
    elif low.startswith("libc-") and ".so" in low:
        score += 150
    elif low.startswith("libc") and ".so" in low:
        score += 120
    if "2.27" in low:
        score += 24
    return score


def _candidate_runtime_dirs(state: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    seen = set()

    def _add_dir(raw_path: str) -> None:
        p = str(raw_path or "").strip()
        if not p:
            return
        if not os.path.isabs(p):
            p = os.path.abspath(os.path.join(ROOT_DIR, p))
        else:
            p = os.path.abspath(p)
        if os.path.isfile(p):
            p = os.path.dirname(p)
        if (not p) or (not os.path.isdir(p)):
            return
        if p in seen:
            return
        seen.add(p)
        out.append(p)

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    _add_dir(str(challenge.get("binary_path", "")).strip())
    _add_dir(str(challenge.get("workdir", "")).strip())
    _add_dir(str(challenge.get("source_dir", "")).strip())
    _add_dir(str(challenge.get("work_dir", "")).strip())
    return out


def _is_elf_file(path: str) -> bool:
    p = str(path or "").strip()
    if (not p) or (not os.path.isfile(p)):
        return False
    try:
        with open(p, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def _binary_candidate_score(path: str, rel: str, depth: int, st_mode: int) -> int:
    name = os.path.basename(str(path or "")).strip().lower()
    score = 0
    if _looks_like_loader_name(name):
        score += 400
    if _looks_like_libc_name(name):
        score += 360
    if name.endswith(".so") or (".so." in name):
        score += 180
    if name.startswith("lib") and (".so" in name):
        score += 120
    if not (int(st_mode or 0) & 0o100):
        score += 40
    if name in {"chall", "challenge", "pwn", "main", "bin", "timu", "vuln", "a.out"}:
        score -= 20
    score += max(0, int(depth)) * 8
    score += min(len(str(rel or "")), 220)
    return int(score)


def _binary_path_suspicious(path: str) -> bool:
    p = str(path or "").strip()
    if not p:
        return True
    name = os.path.basename(p).strip().lower()
    if _looks_like_loader_name(name) or _looks_like_libc_name(name):
        return True
    if name.endswith(".so") or (".so." in name):
        return True
    return False


def _to_repo_rel_or_abs(path: str) -> str:
    ap = os.path.abspath(str(path or "").strip())
    if not ap:
        return ""
    try:
        if os.path.commonpath([ROOT_DIR, ap]) == ROOT_DIR:
            return repo_rel(ap)
    except Exception:
        pass
    return ap


def _scan_best_binary_candidate(
    state: Dict[str, Any],
    *,
    max_depth: int = 4,
    max_files: int = 12000,
) -> Dict[str, Any]:
    roots = _candidate_runtime_dirs(state)
    if not roots:
        return {}
    best: Dict[str, Any] = {}
    best_score: int | None = None
    scanned = 0

    for base in roots:
        if scanned >= max_files:
            break
        if not os.path.isdir(base):
            continue
        base_abs = os.path.abspath(base)
        for cur, dirs, files in os.walk(base_abs):
            rel_dir = os.path.relpath(cur, base_abs)
            depth = 0 if rel_dir in {".", ""} else rel_dir.count(os.sep) + 1
            if depth > max_depth:
                dirs[:] = []
                continue
            for fn in files:
                scanned += 1
                if scanned > max_files:
                    break
                p = os.path.join(cur, fn)
                if not _is_elf_file(p):
                    continue
                try:
                    st = os.stat(p)
                except Exception:
                    continue
                if not os.path.isfile(p):
                    continue
                rel = os.path.relpath(p, base_abs)
                score = _binary_candidate_score(p, rel, depth, int(st.st_mode))
                if best_score is None or int(score) < int(best_score):
                    best_score = int(score)
                    best = {
                        "path_abs": os.path.abspath(p),
                        "path_rel": _to_repo_rel_or_abs(p),
                        "base_dir": base_abs,
                        "depth": int(depth),
                        "score": int(score),
                        "name": os.path.basename(p),
                    }
            if scanned > max_files:
                break
    return best


def guard_binary_path_consistency(state_path: str, session_id: str) -> Tuple[bool, str, str]:
    state = load_json(state_path)
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    raw_bin = str(challenge.get("binary_path", "")).strip()
    bin_abs = raw_bin if os.path.isabs(raw_bin) else os.path.abspath(os.path.join(ROOT_DIR, raw_bin))
    bin_exists = bool(bin_abs and os.path.isfile(bin_abs))
    bin_elf = _is_elf_file(bin_abs) if bin_exists else False
    suspicious = _binary_path_suspicious(bin_abs if bin_exists else raw_bin)
    candidate = _scan_best_binary_candidate(state)
    candidate_abs = str(candidate.get("path_abs", "")).strip()
    candidate_score = int(candidate.get("score", 10**9) or 10**9) if candidate else 10**9
    current_score = 10**9
    if bin_exists:
        try:
            st = os.stat(bin_abs)
            current_score = _binary_candidate_score(
                bin_abs,
                os.path.relpath(bin_abs, os.path.dirname(bin_abs)),
                0,
                int(st.st_mode),
            )
        except Exception:
            current_score = 10**9

    reason = ""
    corrected = False
    corrected_to = ""

    should_correct = False
    if (not bin_exists) or (not bin_elf):
        should_correct = True
        reason = "binary missing or non-ELF"
    elif suspicious:
        should_correct = True
        reason = "binary path points to runtime .so (loader/libc)"
    elif candidate_abs and os.path.abspath(candidate_abs) != os.path.abspath(bin_abs):
        if int(candidate_score) + 220 < int(current_score):
            should_correct = True
            reason = "binary heuristic prefers another ELF candidate"

    if should_correct and candidate_abs and os.path.isfile(candidate_abs):
        corrected_to = _to_repo_rel_or_abs(candidate_abs)
        if corrected_to and corrected_to != raw_bin:
            challenge["binary_path"] = corrected_to
            state["challenge"] = challenge
            imp = challenge.setdefault("import_meta", {})
            if not str(imp.get("binary_path_original", "")).strip():
                imp["binary_path_original"] = raw_bin
            imp["binary_path_corrected_utc"] = utc_now()
            imp["binary_path_guard_reason"] = reason
            corrected = True

    report_rel = f"artifacts/reports/binary_path_guard_{session_id}.json"
    report_abs = os.path.join(ROOT_DIR, report_rel)
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)
    report_doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "raw_binary_path": raw_bin,
        "raw_binary_abs": bin_abs,
        "raw_exists": bool(bin_exists),
        "raw_is_elf": bool(bin_elf),
        "raw_suspicious": bool(suspicious),
        "current_score": int(current_score),
        "candidate": candidate if isinstance(candidate, dict) else {},
        "candidate_score": int(candidate_score),
        "corrected": bool(corrected),
        "corrected_to": corrected_to,
        "reason": reason,
    }
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report_doc, f, ensure_ascii=False, indent=2)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["binary_path_guard_report"] = report_rel
    save_json(state_path, state)
    if corrected:
        try:
            sync_meta_from_state(session_id, state)
        except Exception:
            pass
    summary = reason
    if corrected and corrected_to:
        summary = f"{reason}: {raw_bin} -> {corrected_to}"
    return corrected, report_rel, summary


def _readelf_symbol_offsets(libc_path: str, names: Set[str]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    if (not libc_path) or (not os.path.isfile(libc_path)) or (not names):
        return out
    cmd = ["readelf", "-Ws", libc_path]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=4.0)
    except Exception:
        return out
    if p.returncode != 0 or (not p.stdout.strip()):
        return out
    wanted = {str(x).strip() for x in names if str(x).strip()}
    if not wanted:
        return out
    line_re = re.compile(r"^\s*\d+:\s*([0-9A-Fa-f]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$")
    for line in p.stdout.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        try:
            addr = int(m.group(1), 16)
        except Exception:
            continue
        if addr <= 0:
            continue
        raw_name = str(m.group(2) or "").strip()
        if not raw_name:
            continue
        sym = raw_name.split("@", 1)[0].strip()
        if (not sym) or (sym not in wanted):
            continue
        if sym not in out:
            out[sym] = int(addr)
        if len(out) >= len(wanted):
            break
    return out


def _find_binsh_offset(libc_path: str) -> int:
    if (not libc_path) or (not os.path.isfile(libc_path)):
        return 0
    needle = b"/bin/sh\x00"
    try:
        with open(libc_path, "rb") as f:
            data = f.read()
    except Exception:
        return 0
    pos = data.find(needle)
    if pos < 0:
        return 0
    return int(pos)


def _extract_local_libc_offsets_env(libc_path: str) -> Dict[str, str]:
    env: Dict[str, str] = {}
    syms = _readelf_symbol_offsets(libc_path, {"puts", "read", "system"})
    if int(syms.get("puts", 0) or 0) > 0:
        env["PWN_LOCAL_PUTS_OFF"] = hex(int(syms["puts"]))
    if int(syms.get("read", 0) or 0) > 0:
        env["PWN_LOCAL_READ_OFF"] = hex(int(syms["read"]))
    if int(syms.get("system", 0) or 0) > 0:
        env["PWN_LOCAL_SYSTEM_OFF"] = hex(int(syms["system"]))
    binsh = _find_binsh_offset(libc_path)
    if binsh > 0:
        env["PWN_LOCAL_BINSH_OFF"] = hex(int(binsh))
    return env


def _runtime_bundle_hint(state: Dict[str, Any]) -> Dict[str, Any]:
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    payload = {
        "capabilities": state.get("capabilities", {}),
        "static_analysis": state.get("static_analysis", {}),
        "progress": state.get("progress", {}),
        "notes": state.get("notes", {}),
        "session_exp": exp,
    }
    try:
        blob = json.dumps(payload, ensure_ascii=False).lower()
    except Exception:
        blob = str(payload).lower()
    free_hook_hint = any(
        tok in blob
        for tok in (
            "__free_hook",
            "free_hook",
            "free hook",
            "official_wp_free_hook",
            "official wp",
            "hook=system",
            "hook -> system",
            "free_hook=system",
        )
    )
    old_glibc_hint = any(
        tok in blob
        for tok in (
            "glibc 2.23",
            "glibc_2_23",
            "xenial",
            "ubuntu16",
            "ubuntu 16",
            "ubuntu-16",
        )
    )
    prefer_old_glibc = bool(free_hook_hint or old_glibc_hint)
    preferred_terms: List[str] = []
    if prefer_old_glibc:
        preferred_terms.extend(["xenial", "2.23", "glibc_2.23", "ubuntu16", "ubuntu-16", "ubuntu 16"])
    notes: List[str] = []
    if free_hook_hint:
        notes.append("free_hook/official_wp runtime hints detected")
    if old_glibc_hint:
        notes.append("old glibc/Xenial 2.23 runtime hints detected")
    return {
        "prefer_old_glibc": bool(prefer_old_glibc),
        "prefer_free_hook": bool(free_hook_hint),
        "preferred_terms": preferred_terms,
        "preferred_profile": ("glibc_2_23" if prefer_old_glibc else ""),
        "notes": notes,
    }


def discover_runtime_loader_bundle(
    state: Dict[str, Any],
    *,
    max_walk_dirs: int = 240,
    max_walk_files: int = 8000,
) -> Dict[str, str]:
    roots = _candidate_runtime_dirs(state)
    if not roots:
        return {}
    runtime_hint = _runtime_bundle_hint(state)
    preferred_terms = [str(x).strip().lower() for x in runtime_hint.get("preferred_terms", []) if str(x).strip()]

    loader_cands: List[Tuple[int, int, str, str]] = []
    libc_cands: List[Tuple[int, int, str, str]] = []
    walked_dirs = 0
    walked_files = 0

    for base in roots:
        if walked_dirs >= max_walk_dirs or walked_files >= max_walk_files:
            break
        if not os.path.isdir(base):
            continue
        base = os.path.abspath(base)
        for root, dirnames, filenames in os.walk(base):
            rel = os.path.relpath(root, base)
            depth = 0 if rel in {".", ""} else rel.count(os.sep) + 1
            if depth > 2:
                dirnames[:] = []
                continue
            walked_dirs += 1
            if walked_dirs > max_walk_dirs:
                break
            for fn in filenames:
                walked_files += 1
                if walked_files > max_walk_files:
                    break
                low = str(fn or "").strip().lower()
                if not low:
                    continue
                ap = os.path.join(root, fn)
                if not os.path.isfile(ap):
                    continue
                path_low = str(ap).lower()
                if _looks_like_loader_name(low):
                    score = _score_loader_name(low)
                    if preferred_terms and any(term in path_low for term in preferred_terms):
                        score += 24
                    loader_cands.append((score, _elf_bits(ap), ap, root))
                if _looks_like_libc_name(low):
                    score = _score_libc_name(low)
                    if preferred_terms and any(term in path_low for term in preferred_terms):
                        score += 36
                    libc_cands.append((score, _elf_bits(ap), ap, root))
            if walked_files > max_walk_files:
                break

    if not loader_cands or not libc_cands:
        return {}

    best_pair: Tuple[int, str, str, str] | None = None
    for l_score, l_bits, l_path, l_dir in loader_cands:
        for c_score, c_bits, c_path, c_dir in libc_cands:
            if l_dir != c_dir:
                continue
            if l_bits > 0 and c_bits > 0 and l_bits != c_bits:
                continue
            pair_score = int(l_score + c_score + 40)
            if "glibc" in l_dir.lower():
                pair_score += 8
            pair_low = f"{l_path} {c_path} {c_dir}".lower()
            if preferred_terms and any(term in pair_low for term in preferred_terms):
                pair_score += 80
            if bool(runtime_hint.get("prefer_free_hook", False)) and any(term in pair_low for term in ("xenial", "2.23")):
                pair_score += 24
            candidate = (pair_score, l_path, c_path, c_dir)
            if (best_pair is None) or (pair_score > int(best_pair[0])):
                best_pair = candidate

    if best_pair is None:
        loader_cands.sort(key=lambda x: int(x[0]), reverse=True)
        libc_cands.sort(key=lambda x: int(x[0]), reverse=True)
        chosen_loader = loader_cands[0]
        l_score, l_bits, l_path, l_dir = chosen_loader
        compatible_libc = [x for x in libc_cands if ((not l_bits) or (not x[1]) or x[1] == l_bits)]
        if compatible_libc:
            c_score, _c_bits, c_path, c_dir = compatible_libc[0]
            pair_score = int(l_score + c_score + (20 if l_dir == c_dir else 0))
            best_pair = (pair_score, l_path, c_path, c_dir)

    if best_pair is None:
        return {}

    _pair_score, loader_path, libc_path, libc_dir = best_pair
    if (not os.path.isfile(loader_path)) or (not os.path.isfile(libc_path)):
        return {}
    env = {
        "PWN_LOADER": os.path.abspath(loader_path),
        "PWN_LIBC_PATH": os.path.abspath(libc_path),
        "PWN_LD_LIBRARY_PATH": os.path.abspath(libc_dir),
        "PWN_FORCE_LOADER": "1",
    }
    env.update(_extract_local_libc_offsets_env(os.path.abspath(libc_path)))
    preferred_profile = str(runtime_hint.get("preferred_profile", "")).strip()
    if preferred_profile:
        env.setdefault("PWN_LIBC_PROFILE", preferred_profile)
    return env


def collect_runtime_abi_guard(
    state: Dict[str, Any],
    selected_env: Dict[str, str],
    *,
    max_walk_dirs: int = 220,
    max_walk_files: int = 6000,
) -> Dict[str, Any]:
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    binary_path_raw = str(challenge.get("binary_path", "")).strip()
    if binary_path_raw and (not os.path.isabs(binary_path_raw)):
        binary_path_raw = os.path.abspath(os.path.join(ROOT_DIR, binary_path_raw))
    binary = _abi_info(binary_path_raw)
    loader = _abi_info(str(selected_env.get("PWN_LOADER", "")).strip())
    libc = _abi_info(str(selected_env.get("PWN_LIBC_PATH", "")).strip())

    mismatch_libcs: List[Dict[str, Any]] = []
    scanned_libcs = 0
    walked_dirs = 0
    walked_files = 0
    bin_bits = int(binary.get("bits", 0) or 0)
    bin_arch = str(binary.get("arch", "")).strip()

    for base in _candidate_runtime_dirs(state):
        if walked_dirs >= max_walk_dirs or walked_files >= max_walk_files:
            break
        if not os.path.isdir(base):
            continue
        base = os.path.abspath(base)
        for root, dirnames, filenames in os.walk(base):
            rel = os.path.relpath(root, base)
            depth = 0 if rel in {".", ""} else rel.count(os.sep) + 1
            if depth > 2:
                dirnames[:] = []
                continue
            walked_dirs += 1
            if walked_dirs > max_walk_dirs:
                break
            for fn in filenames:
                walked_files += 1
                if walked_files > max_walk_files:
                    break
                low = str(fn or "").strip().lower()
                if not low or (not _looks_like_libc_name(low)):
                    continue
                ap = os.path.join(root, fn)
                if not os.path.isfile(ap):
                    continue
                info = _abi_info(ap)
                if not bool(info.get("exists", False)):
                    continue
                scanned_libcs += 1
                c_bits = int(info.get("bits", 0) or 0)
                c_arch = str(info.get("arch", "")).strip()
                bits_mismatch = bool(bin_bits and c_bits and (bin_bits != c_bits))
                arch_mismatch = bool(bin_arch and c_arch and (bin_arch != c_arch))
                if bits_mismatch or arch_mismatch:
                    mismatch_libcs.append(
                        {
                            "path": info.get("path", ""),
                            "name": info.get("name", ""),
                            "bits": c_bits,
                            "arch": c_arch,
                            "bits_mismatch": bits_mismatch,
                            "arch_mismatch": arch_mismatch,
                        }
                    )
            if walked_files > max_walk_files:
                break

    sel_bits_mismatch = bool(bin_bits and int(libc.get("bits", 0) or 0) and (bin_bits != int(libc.get("bits", 0) or 0)))
    sel_arch_mismatch = bool(
        bin_arch
        and str(libc.get("arch", "")).strip()
        and (bin_arch != str(libc.get("arch", "")).strip())
    )
    selected_mismatch = bool(sel_bits_mismatch or sel_arch_mismatch)

    issues: List[str] = []
    if selected_mismatch:
        issues.append(
            "selected loader/libc mismatch with challenge binary ABI; disabled PWN_LOADER/PWN_LIBC_PATH auto injection"
        )
    if mismatch_libcs:
        issues.append(f"found {len(mismatch_libcs)} ABI-mismatched libc candidate(s) under challenge dirs")

    return {
        "binary": binary,
        "selected_loader": loader,
        "selected_libc": libc,
        "selected_mismatch": selected_mismatch,
        "selected_bits_mismatch": bool(sel_bits_mismatch),
        "selected_arch_mismatch": bool(sel_arch_mismatch),
        "scanned_libc_count": int(scanned_libcs),
        "mismatched_libcs": mismatch_libcs[:16],
        "issues": issues,
    }


def write_runtime_abi_guard_report(state_path: str, session_id: str, doc: Dict[str, Any]) -> str:
    out_rel = f"artifacts/reports/runtime_abi_guard_{session_id}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    payload = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "binary": doc.get("binary", {}),
        "selected_loader": doc.get("selected_loader", {}),
        "selected_libc": doc.get("selected_libc", {}),
        "selected_mismatch": bool(doc.get("selected_mismatch", False)),
        "selected_bits_mismatch": bool(doc.get("selected_bits_mismatch", False)),
        "selected_arch_mismatch": bool(doc.get("selected_arch_mismatch", False)),
        "scanned_libc_count": int(doc.get("scanned_libc_count", 0) or 0),
        "mismatched_libcs": doc.get("mismatched_libcs", []),
        "issues": doc.get("issues", []),
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["runtime_abi_guard_report"] = out_rel

    challenge = state.setdefault("challenge", {})
    runtime_guard = challenge.setdefault("runtime_guard", {}) if isinstance(challenge.get("runtime_guard", {}), dict) else {}
    runtime_guard["report"] = out_rel
    runtime_guard["selected_mismatch"] = bool(payload.get("selected_mismatch", False))
    runtime_guard["binary_bits"] = int(payload.get("binary", {}).get("bits", 0) or 0)
    runtime_guard["binary_arch"] = str(payload.get("binary", {}).get("arch", "")).strip()
    runtime_guard["selected_libc_bits"] = int(payload.get("selected_libc", {}).get("bits", 0) or 0)
    runtime_guard["selected_libc_arch"] = str(payload.get("selected_libc", {}).get("arch", "")).strip()
    runtime_guard["mismatched_libc_count"] = len(payload.get("mismatched_libcs", []) or [])
    runtime_guard["libc_quarantine"] = [
        str(x.get("path", "")).strip()
        for x in (payload.get("mismatched_libcs", []) if isinstance(payload.get("mismatched_libcs", []), list) else [])
        if isinstance(x, dict) and str(x.get("path", "")).strip()
    ][:16]
    challenge["runtime_guard"] = runtime_guard

    if runtime_guard.get("selected_mismatch", False):
        blockers = state.setdefault("summary", {}).setdefault("blockers", [])
        if isinstance(blockers, list):
            line = "runtime ABI guard: selected loader/libc mismatched challenge binary ABI"
            if line not in blockers:
                blockers.append(line)

    save_json(state_path, state)
    return out_rel


def write_runtime_env_profile(session_id: str, env_map: Dict[str, str]) -> str:
    safe_env: Dict[str, str] = {}
    for k, v in env_map.items():
        key = str(k).strip()
        val = str(v).strip()
        if (not key.startswith("PWN_")) or (not val):
            continue
        safe_env[key] = val
    if not safe_env:
        return ""

    out_rel = f"sessions/{session_id}/runtime/runtime_env.auto.sh"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)

    lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated runtime alignment profile for local verify/debug.",
    ]
    for key in sorted(safe_env.keys()):
        val = safe_env[key].replace("'", "'\''")
        lines.append(f"export {key}='{val}'")
    lines.append("")

    with open(out_abs, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    try:
        os.chmod(out_abs, 0o755)
    except Exception:
        pass
    return out_rel


def stage_cache_path(binary_sha256: str, stage: str) -> str:
    return os.path.join(ROOT_DIR, "artifacts", "cache", f"{binary_sha256}_{stage}.json")


def exploit_profile_cache_path(binary_sha256: str) -> str:
    return os.path.join(ROOT_DIR, "artifacts", "cache", f"{binary_sha256}_exploit_profile.json")


def _pick_read_len_from_state(state: Dict[str, Any]) -> int:
    io_profile = state.get("io_profile", {}) if isinstance(state.get("io_profile", {}), dict) else {}
    for k in ["read_len", "max_read_len", "recv_size", "input_size", "size_hint"]:
        v = io_profile.get(k, None)
        try:
            n = int(v)
        except Exception:
            continue
        if 16 <= n <= 0x4000:
            return n
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    items: List[Any] = []
    for k in ["suspects", "hypotheses", "entrypoints"]:
        arr = static.get(k, [])
        if isinstance(arr, list):
            items.extend(arr)
    for it in items:
        if not isinstance(it, dict):
            continue
        name = str(it.get("name", "") or it.get("symbol", "") or it.get("type", "")).lower()
        if "read" not in name:
            continue
        for key in ["size", "len", "read_size", "nbytes", "max_len"]:
            try:
                n = int(it.get(key, 0) or 0)
            except Exception:
                n = 0
            if 16 <= n <= 0x4000:
                return n
    return 0


def extract_exploit_profile_patch(state: Dict[str, Any]) -> Dict[str, Any]:
    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    read_len = _pick_read_len_from_state(state)
    patch = {
        "capabilities": {
            "control_rip": bool(caps.get("control_rip", False)),
            "offset_to_rip": int(caps.get("offset_to_rip", 0) or 0),
            "ret2win_path_verified": bool(caps.get("ret2win_path_verified", False)),
            "system_call_observed": bool(caps.get("system_call_observed", False)),
        },
        "session": {
            "exp": {
                "strategy": str(exp.get("strategy", "")).strip(),
            }
        },
        "io_profile": {},
    }
    if read_len > 0:
        patch["io_profile"]["read_len"] = read_len
    return patch


def exploit_profile_patch_is_useful(patch: Dict[str, Any]) -> bool:
    if not isinstance(patch, dict):
        return False
    caps = patch.get("capabilities", {}) if isinstance(patch.get("capabilities", {}), dict) else {}
    exp = (
        patch.get("session", {}).get("exp", {})
        if isinstance(patch.get("session", {}), dict) and isinstance(patch.get("session", {}).get("exp", {}), dict)
        else {}
    )
    strategy = str(exp.get("strategy", "")).strip().lower()
    control_rip = bool(caps.get("control_rip", False))
    off = int(caps.get("offset_to_rip", 0) or 0)
    ret2win_verified = bool(caps.get("ret2win_path_verified", False))
    system_observed = bool(caps.get("system_call_observed", False))

    # 弱画像（如 fuzz_probe + 无控制能力）不参与复用，避免污染新会话。
    if strategy in {"", "fuzz_probe"}:
        return False
    if control_rip or off > 0 or ret2win_verified or system_observed:
        return True
    return False


def save_exploit_profile_cache(state: Dict[str, Any], binary_sha256: str) -> str:
    if not binary_sha256:
        return ""
    patch = extract_exploit_profile_patch(state)
    if not exploit_profile_patch_is_useful(patch):
        return ""
    p = exploit_profile_cache_path(binary_sha256)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    doc = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "generated_utc": utc_now(),
        "kind": "exploit_profile",
        "binary_sha256": binary_sha256,
        "state_patch": patch,
    }
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return repo_rel(p)


def apply_exploit_profile_cache(state: Dict[str, Any], binary_sha256: str, overwrite: bool = False) -> Tuple[bool, str]:
    if not binary_sha256:
        return False, ""
    p = exploit_profile_cache_path(binary_sha256)
    if not os.path.exists(p):
        return False, ""
    try:
        with open(p, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return False, ""
    if int(doc.get("cache_schema_version", 0) or 0) != CACHE_SCHEMA_VERSION:
        return False, ""
    patch = doc.get("state_patch", {})
    if not isinstance(patch, dict):
        return False, ""
    if not exploit_profile_patch_is_useful(patch):
        return False, ""
    merged = _merge_dict(state, patch, overwrite=overwrite)
    state.clear()
    state.update(merged)
    return True, repo_rel(p)


def extract_stage_cache_patch(stage: str, state: Dict[str, Any]) -> Dict[str, Any]:
    if stage == "recon":
        return {
            "protections": state.get("protections", {}),
            "io_profile": state.get("io_profile", {}),
        }
    if stage == "ida_slice":
        static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
        return {
            "static_analysis": {
                "entrypoints": static.get("entrypoints", []),
                "suspects": static.get("suspects", []),
                "hypotheses": static.get("hypotheses", []),
            }
        }
    if stage == "gdb_evidence":
        dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
        return {
            "dynamic_evidence": {
                "inputs": dynamic.get("inputs", []),
                "evidence": dynamic.get("evidence", []),
                "clusters": dynamic.get("clusters", []),
            },
            "latest_bases": state.get("latest_bases", {}),
        }
    return {}


def cache_patch_is_valid(stage: str, state: Dict[str, Any]) -> bool:
    if stage == "recon":
        protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
        arch = str(protections.get("arch", "")).strip()
        pie = protections.get("pie", None)
        return bool(arch) and (pie is not None)
    if stage == "ida_slice":
        static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
        entrypoints = static.get("entrypoints", []) if isinstance(static.get("entrypoints", []), list) else []
        suspects = static.get("suspects", []) if isinstance(static.get("suspects", []), list) else []
        hypos = static.get("hypotheses", []) if isinstance(static.get("hypotheses", []), list) else []
        return bool(entrypoints) and (bool(suspects) or bool(hypos))
    if stage == "gdb_evidence":
        dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
        evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
        if not evid:
            return False
        last = evid[-1] if isinstance(evid[-1], dict) else {}
        if not isinstance(last, dict):
            return False
        g = last.get("gdb", {}) if isinstance(last.get("gdb", {}), dict) else {}
        pc_offset = str(g.get("pc_offset", "")).strip()
        signal = str(g.get("signal", "")).strip()
        if not pc_offset:
            return False
        if not signal:
            return False
        pie_base = str(state.get("latest_bases", {}).get("pie_base", "")).strip()
        mappings = last.get("mappings", {}) if isinstance(last.get("mappings", {}), dict) else {}
        evid_pie = str(mappings.get("pie_base", "")).strip()
        return bool(pie_base or evid_pie)
    return True


def _cyclic_bytes(length: int) -> bytes:
    n = max(1, int(length))
    set1 = b"abcdefghijklmnopqrstuvwxyz"
    set2 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    set3 = b"0123456789"
    out = bytearray()
    for a in set1:
        for b in set2:
            for c in set3:
                out.extend((a, b, c))
                if len(out) >= n:
                    return bytes(out[:n])
    while len(out) < n:
        out.extend(b"Aa0")
    return bytes(out[:n])


def _cyclic_find_offset(value_hex: str, max_len: int) -> int:
    s = str(value_hex or "").strip().lower()
    if not s:
        return -1
    if s.startswith("0x"):
        s = s[2:]
    if not re.fullmatch(r"[0-9a-f]+", s):
        return -1
    try:
        v = int(s, 16)
    except Exception:
        return -1
    if v <= 0:
        return -1
    pat = _cyclic_bytes(max(64, int(max_len) + 16))
    b8 = int(v).to_bytes(8, byteorder="little", signed=False)
    idx = pat.find(b8)
    if idx >= 0:
        return int(idx)
    b4 = b8[:4]
    idx = pat.find(b4)
    if idx >= 0:
        return int(idx)
    return -1


def _guess_offset_from_gdb_evidence(state: Dict[str, Any]) -> int:
    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
    if not evid:
        return 0
    last = evid[-1] if isinstance(evid[-1], dict) else {}
    if not isinstance(last, dict):
        return 0
    g = last.get("gdb", {}) if isinstance(last.get("gdb", {}), dict) else {}
    if not g:
        return 0

    try:
        off_existing = int(g.get("offset_to_rip", 0) or 0)
    except Exception:
        off_existing = 0
    if off_existing > 0:
        return int(off_existing)

    cyclic_len = 320
    inputs = dynamic.get("inputs", []) if isinstance(dynamic.get("inputs", []), list) else []
    for it in reversed(inputs[-8:]):
        if not isinstance(it, dict):
            continue
        try:
            n = int(it.get("size", 0) or 0)
        except Exception:
            n = 0
        if 32 <= n <= 8192:
            cyclic_len = n
            break

    cands: List[str] = []
    stack_top = str(g.get("stack_top_qword", "")).strip()
    if stack_top:
        cands.append(stack_top)
    stack_txt = str(g.get("stack", "")).strip()
    if stack_txt:
        m = re.search(r"0x[0-9a-fA-F]+:\s*0x([0-9a-fA-F]+)", stack_txt)
        if m:
            cands.append("0x" + m.group(1))
    rip = str(g.get("rip", "")).strip()
    if rip:
        cands.append(rip)

    seen = set()
    for cv in cands:
        x = str(cv).strip().lower()
        if not x or x in seen:
            continue
        seen.add(x)
        off = _cyclic_find_offset(x, cyclic_len)
        if 0 <= off <= 4096:
            return int(off)
    return 0


def _apply_gdb_offset_hint(state: Dict[str, Any]) -> int:
    off = _guess_offset_from_gdb_evidence(state)
    if off <= 0:
        return 0
    caps = state.setdefault("capabilities", {})
    caps["control_rip"] = True
    caps["rip_control"] = "yes"
    caps["offset_to_rip"] = int(off)
    latest_bases = state.setdefault("latest_bases", {})
    latest_bases["offset_to_rip"] = int(off)
    io_profile = state.setdefault("io_profile", {})
    if int(io_profile.get("offset_to_rip", 0) or 0) <= 0:
        io_profile["offset_to_rip"] = int(off)
    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
    if evid and isinstance(evid[-1], dict):
        g = evid[-1].setdefault("gdb", {})
        if isinstance(g, dict) and int(g.get("offset_to_rip", 0) or 0) <= 0:
            g["offset_to_rip"] = int(off)
            if not str(g.get("offset_source", "")).strip():
                g["offset_source"] = "stack_hint_recovery"
    return int(off)


def stage_state_reuse_reason(stage: str, state: Dict[str, Any], session_id: str = "") -> str:
    st = str(stage or "").strip()
    if st not in {"recon", "ida_slice"}:
        return ""
    if not cache_patch_is_valid(st, state):
        return ""
    latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    latest = latest if isinstance(latest, dict) else {}
    sid = str(session_id or "").strip()
    if st == "recon":
        rep = str(latest.get("recon_report", "")).strip()
        if rep and ((not sid) or (sid in rep)):
            return "state:recon_ready"
    if st == "ida_slice":
        js = str(latest.get("ida_slice_json", "")).strip()
        if js and ((not sid) or (sid in js)):
            return "state:ida_ready"
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    pyghidra = challenge.get("pyghidra", {}) if isinstance(challenge.get("pyghidra", {}), dict) else {}
    analysis_ready = bool(
        pyghidra.get("analysis_ready", False)
        or pyghidra.get("binary_analyzed", False)
        or challenge.get("analysis_ready", False)
    )
    if analysis_ready:
        return "state:analyzed_ready"
    return ""


def l0_l2_ready(state: Dict[str, Any], allow_without_ida: bool = False) -> bool:
    recon_ok = cache_patch_is_valid("recon", state)
    ida_ok = cache_patch_is_valid("ida_slice", state)
    gdb_ok = cache_patch_is_valid("gdb_evidence", state)
    if allow_without_ida:
        return bool(recon_ok and gdb_ok)
    return bool(recon_ok and ida_ok and gdb_ok)


def detect_blind_mode(state: Dict[str, Any]) -> bool:
    if not isinstance(state, dict):
        return False
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    binary_path = str(challenge.get("binary_path", "")).strip()
    import_meta = challenge.get("import_meta", {}) if isinstance(challenge.get("import_meta", {}), dict) else {}
    blind_meta = bool(import_meta.get("blind_mode", False))
    return bool((not binary_path) or blind_meta)


def _collect_runtime_hint_space(state: Dict[str, Any]) -> str:
    out: List[str] = []
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    for k in ("entrypoints", "suspects", "hypotheses"):
        arr = static.get(k, [])
        if not isinstance(arr, list):
            continue
        for it in arr:
            if isinstance(it, dict):
                for kk in ("name", "symbol", "type", "statement", "verify_with", "callee", "target", "detail"):
                    s = str(it.get(kk, "")).strip().lower()
                    if s:
                        out.append(s)
            elif isinstance(it, str):
                s = str(it).strip().lower()
                if s:
                    out.append(s)

    ev_root = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    ev_items = ev_root.get("evidence", []) if isinstance(ev_root.get("evidence", []), list) else []
    for ev in ev_items[-24:]:
        if not isinstance(ev, dict):
            continue
        for kk in ("type", "value", "summary", "note", "reason", "stderr", "stdout"):
            s = str(ev.get(kk, "")).strip().lower()
            if s:
                out.append(s)

    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    for kk in ("strategy", "strategy_hint", "last_error", "last_verify_error"):
        s = str(exp.get(kk, "")).strip().lower()
        if s:
            out.append(s)

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    bin_path = str(challenge.get("binary_path", "")).strip().lower()
    if bin_path:
        out.append(bin_path)
    return " ".join(out)


def detect_lua_runtime_exec_hint(state: Dict[str, Any]) -> bool:
    if not isinstance(state, dict):
        return False
    hint_space = _collect_runtime_hint_space(state)
    if not hint_space:
        return False
    lua_tokens = (
        "lua",
        "load(",
        "loadstring",
        "dofile(",
        "writeraw",
        "bytecode",
        ".luac",
        "return ..",
        "return \"..",
        "pcall(",
        "os.execute",
        "io.popen",
    )
    hits = sum(1 for t in lua_tokens if t in hint_space)
    return bool(hits >= 2)


def detect_repl_cmd_exec_hint(state: Dict[str, Any]) -> bool:
    if not isinstance(state, dict):
        return False
    if detect_lua_runtime_exec_hint(state):
        return True
    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    exp_strategy = str(exp.get("strategy", "")).strip().lower()
    if exp_strategy == "js_shell_cmd_exec":
        return True

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    bin_path = str(challenge.get("binary_path", "")).strip().lower()
    score = 0
    if bin_path.endswith((".js", ".mjs", ".cjs")):
        score += 2
    if "node" in bin_path:
        score += 1

    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    items: List[str] = []
    for k in ("entrypoints", "suspects", "hypotheses"):
        arr = static.get(k, [])
        if not isinstance(arr, list):
            continue
        for it in arr:
            if isinstance(it, dict):
                for kk in ("name", "symbol", "type", "statement", "verify_with", "callee", "target"):
                    s = str(it.get(kk, "")).strip().lower()
                    if s:
                        items.append(s)
            elif isinstance(it, str):
                s = str(it).strip().lower()
                if s:
                    items.append(s)
    hint_space = " ".join(items)
    tokens = (
        "javascript",
        "js shell",
        "node",
        "repl",
        "child_process",
        "execsync",
        "require(",
        "vm2",
        "cmd injection",
        "command exec",
        "command execution",
    )
    score += sum(1 for t in tokens if t in hint_space)
    if score >= 2:
        return True

    try:
        strat = choose_exploit_strategy(state)
        if str(strat.strategy_id).strip().lower() == "js_shell_cmd_exec":
            return True
    except Exception:
        pass
    return False


def detect_nxoff_libc_free_hint(state: Dict[str, Any]) -> bool:
    if not isinstance(state, dict):
        return False
    protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    nx_raw = protections.get("nx", None)
    nx_disabled = (nx_raw is False) or (str(nx_raw or "").strip().lower() in {"0", "false", "off", "disabled", "no"})
    if not nx_disabled:
        return False
    control_rip = bool(caps.get("control_rip", False))
    offset_to_rip = int(caps.get("offset_to_rip", 0) or 0)
    if (not control_rip) or offset_to_rip <= 0:
        return False
    has_leak = str(caps.get("has_leak", "unknown")).strip().lower()
    write_primitive = str(caps.get("write_primitive", "unknown")).strip().lower()
    if has_leak in {"yes", "possible"} or write_primitive in {"yes", "possible"}:
        return False
    return True


def _run_capture_quick(cmd: List[str], timeout_sec: float = 3.0) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            check=False,
            timeout=max(1.0, float(timeout_sec)),
        )
        return int(p.returncode), str(p.stdout or ""), str(p.stderr or "")
    except subprocess.TimeoutExpired as e:
        return 124, str(getattr(e, "stdout", "") or ""), str(getattr(e, "stderr", "") or "timeout")
    except Exception as e:
        return 1, "", str(e)


def _quick_binary_has_binsh_literal(binary_abs: str) -> bool:
    path = str(binary_abs or "").strip()
    if (not path) or (not os.path.isfile(path)):
        return False
    needles = (b"/bin/sh", b"/bin//sh")
    overlap = 16
    tail = b""
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                blob = tail + chunk
                low = blob.lower()
                if any(n in low for n in needles):
                    return True
                tail = blob[-overlap:] if len(blob) > overlap else blob
    except Exception:
        return False
    return False


def _quick_binary_imports_system(binary_abs: str) -> bool:
    path = str(binary_abs or "").strip()
    if (not path) or (not os.path.isfile(path)):
        return False
    if shutil.which("readelf"):
        rc, out, _ = _run_capture_quick(["readelf", "-Ws", path], timeout_sec=3.0)
        if rc == 0 and out:
            low = out.lower()
            if re.search(r"\bsystem(@@|@|$)", low):
                return True
    if shutil.which("nm"):
        rc, out, _ = _run_capture_quick(["nm", "-D", path], timeout_sec=3.0)
        if rc == 0 and out:
            low = out.lower()
            if re.search(r"\bsystem(@@|@|$)", low):
                return True
    return False


def _quick_main_calls_system(binary_abs: str) -> Tuple[bool, str]:
    path = str(binary_abs or "").strip()
    if (not path) or (not os.path.isfile(path)):
        return False, "binary_missing"
    if not shutil.which("objdump"):
        return False, "objdump_missing"
    rc, out, err = _run_capture_quick(["objdump", "-d", path], timeout_sec=4.0)
    if rc != 0:
        return False, f"objdump_rc={rc}:{(err or '').strip()[:120]}"
    in_main = False
    scanned = 0
    for line in out.splitlines():
        s = str(line or "").strip()
        if (not in_main) and re.match(r"^[0-9a-fA-F]+ <main>:$", s):
            in_main = True
            continue
        if in_main and re.match(r"^[0-9a-fA-F]+ <[^>]+>:$", s):
            break
        if not in_main:
            continue
        scanned += 1
        low = s.lower()
        if ("call" in low) and (("<system@plt>" in low) or ("<system>" in low)):
            return True, "main_calls_system"
        if scanned >= 320:
            break
    return False, "main_no_system_call"


def quick_detect_direct_system_binsh(state: Dict[str, Any]) -> Dict[str, Any]:
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    binary_rel = str(challenge.get("binary_path", "")).strip()
    binary_abs = binary_rel if os.path.isabs(binary_rel) else os.path.abspath(os.path.join(ROOT_DIR, binary_rel))

    exists = bool(binary_abs and os.path.isfile(binary_abs))
    result: Dict[str, Any] = {
        "generated_utc": utc_now(),
        "binary_path": binary_rel,
        "binary_abs": binary_abs,
        "exists": exists,
        "matched": False,
        "reason": "",
        "system_import": False,
        "main_calls_system": False,
        "main_call_reason": "",
        "binsh_literal": False,
    }
    if not exists:
        result["reason"] = "binary_missing"
        return result

    result["system_import"] = bool(_quick_binary_imports_system(binary_abs))
    main_calls_system, main_reason = _quick_main_calls_system(binary_abs)
    result["main_calls_system"] = bool(main_calls_system)
    result["main_call_reason"] = str(main_reason)
    result["binsh_literal"] = bool(_quick_binary_has_binsh_literal(binary_abs))
    matched = bool(result["main_calls_system"] and result["binsh_literal"])
    result["matched"] = matched
    if matched:
        result["reason"] = "main_calls_system+binsh_literal"
    else:
        result["reason"] = "no_direct_system_signature"
    return result


def apply_direct_system_binsh_shortcut(state_path: str, session_id: str) -> Tuple[bool, str]:
    state = load_json(state_path)
    probe = quick_detect_direct_system_binsh(state)
    report_rel = f"artifacts/reports/quick_strategy_{session_id}.json"
    report_abs = os.path.join(ROOT_DIR, report_rel)
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)

    applied = False
    if bool(probe.get("matched", False)):
        caps = state.setdefault("capabilities", {})
        if not bool(caps.get("system_call_observed", False)):
            caps["system_call_observed"] = True
            applied = True

        exp = state.setdefault("session", {}).setdefault("exp", {})
        if str(exp.get("strategy_hint", "")).strip().lower() != "direct_system_binsh":
            exp["strategy_hint"] = "direct_system_binsh"
            applied = True

        static = state.setdefault("static_analysis", {})
        hypos = static.get("hypotheses", [])
        if not isinstance(hypos, list):
            hypos = []
        has_direct_hypo = False
        for h in hypos:
            if not isinstance(h, dict):
                continue
            if str(h.get("type", "")).strip().lower() == "direct_system_binsh":
                has_direct_hypo = True
                break
        if not has_direct_hypo:
            hypos.append(
                {
                    "id": "h00_direct_system_binsh",
                    "type": "direct_system_binsh",
                    "statement": "binary quick scan matched main->system('/bin/sh')",
                    "verify_with": "local exp direct shell probe",
                    "confidence": "high",
                }
            )
            static["hypotheses"] = hypos
            applied = True

    state.setdefault("challenge", {}).setdefault("fastpath", {})["direct_system_binsh"] = bool(
        probe.get("matched", False)
    )
    state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
        "quick_strategy_report"
    ] = report_rel

    report_doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "kind": "quick_strategy",
        "applied": bool(applied),
        "strategy_hint": str(
            state.get("session", {}).get("exp", {}).get("strategy_hint", "")
        ).strip(),
        "probe": probe,
    }
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report_doc, f, ensure_ascii=False, indent=2)
    save_json(state_path, state)
    return bool(applied), report_rel


def choose_forced_minimal_strategy_hint(state: Dict[str, Any]) -> str:
    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    hint = str(exp.get("strategy_hint", "")).strip().lower()
    if hint and hint not in {"fuzz_probe", "rip_control_probe"}:
        return hint

    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    if bool(caps.get("system_call_observed", False)) and (not bool(caps.get("control_rip", False))):
        return "direct_system_binsh"
    if detect_lua_runtime_exec_hint(state):
        return "js_shell_cmd_exec"
    if detect_repl_cmd_exec_hint(state):
        return "js_shell_cmd_exec"
    if detect_nxoff_libc_free_hint(state):
        return "direct_execve_shell"
    try:
        strat = choose_exploit_strategy(state)
        sid = str(strat.strategy_id or "").strip().lower()
        if sid and sid not in {"fuzz_probe", "rip_control_probe"}:
            return sid
    except Exception:
        pass
    return "ret2win"


def _is_weak_exp_strategy(raw: Any) -> bool:
    return str(raw or "").strip().lower() in {"fuzz_probe", "rip_control_probe"}


def _should_force_exp_regen_after_unsolved(
    state: Dict[str, Any],
    *,
    verify_report: str,
    last_error: str,
) -> Tuple[bool, str, str]:
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    if bool(exp.get("local_verify_passed", False)):
        return False, "", ""

    exp_status = str(exp.get("status", "")).strip().lower()
    strategy = str(exp.get("strategy", "")).strip().lower()
    strategy_hint = str(exp.get("strategy_hint", "")).strip().lower()
    verify_detail = _read_verify_report_detail(str(verify_report or "").strip(), max_error_chars=220)
    verify_last_error = str(verify_detail.get("last_error", "")).strip().lower()
    low_error = " ".join(
        x
        for x in (
            str(last_error or "").strip().lower(),
            verify_last_error,
        )
        if x
    )
    forced_hint = choose_forced_minimal_strategy_hint(state)

    if exp_status == "stub_generated":
        reason = f"stub-generated exp remained unsolved (strategy={strategy or 'unknown'})"
        return True, reason, forced_hint

    if _is_weak_exp_strategy(strategy) or _is_weak_exp_strategy(strategy_hint):
        reason = (
            "weak exp strategy remained unsolved: "
            f"strategy={strategy or 'unknown'}, hint={strategy_hint or 'none'}"
        )
        return True, reason, forced_hint

    if "weak exploit closure" in low_error:
        reason = f"weak exploit closure remained unsolved (strategy={strategy or 'unknown'})"
        return True, reason, forced_hint

    return False, "", ""


def _normalize_strategy_hint(raw: Any) -> str:
    s = str(raw or "").strip().lower()
    alias = {
        "direct_system": "direct_system_binsh",
        "system_binsh": "direct_system_binsh",
        "system_shell": "direct_system_binsh",
        "system_direct": "direct_system_binsh",
    }
    return alias.get(s, s)


def _normalize_strategy_hint_cycle(raw: Any, state: Dict[str, Any] | None = None) -> List[str]:
    items: List[str] = []
    if isinstance(raw, list):
        items = [_normalize_strategy_hint(x) for x in raw]
    elif str(raw or "").strip():
        items = [_normalize_strategy_hint(x) for x in str(raw).split(",")]
    seed = ""
    if isinstance(state, dict):
        try:
            seed = _normalize_strategy_hint(choose_forced_minimal_strategy_hint(state))
        except Exception:
            seed = ""
    defaults = [
        seed,
        "ret2win",
        "ret2libc",
        "fmtstr_got_write",
        "fmtstr_wp_fastpath",
        "direct_execve_shell",
        "direct_system_binsh",
        "js_shell_cmd_exec",
    ]
    out: List[str] = []
    seen = set()
    for x in items + defaults:
        s = _normalize_strategy_hint(x)
        if (not s) or (s in seen):
            continue
        seen.add(s)
        out.append(s)
    return out


def _pick_next_strategy_hint(state: Dict[str, Any], cycle: List[str]) -> Tuple[str, str, str, List[str]]:
    norm_cycle = _normalize_strategy_hint_cycle(cycle, state=state)
    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    current_hint = _normalize_strategy_hint(exp.get("strategy_hint", ""))
    current_strategy = _normalize_strategy_hint(exp.get("strategy", ""))
    anchor = current_hint or current_strategy
    if not norm_cycle:
        return "", current_hint, current_strategy, []
    if anchor in norm_cycle:
        idx = norm_cycle.index(anchor)
        for shift in range(1, len(norm_cycle) + 1):
            cand = norm_cycle[(idx + shift) % len(norm_cycle)]
            if cand != current_hint:
                return cand, current_hint, current_strategy, norm_cycle
        return "", current_hint, current_strategy, norm_cycle
    return norm_cycle[0], current_hint, current_strategy, norm_cycle


def write_strategy_route_switch_report(
    *,
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
    out = os.path.join(ROOT_DIR, rel)
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
    session_id: str,
    loop_idx: int,
    no_progress_loops: int,
    no_new_evidence_sec: float,
    reasons: List[str],
) -> str:
    rel = f"artifacts/reports/hint_gate_{session_id}_{loop_idx:02d}.json"
    out = os.path.join(ROOT_DIR, rel)
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
    out = os.path.join(ROOT_DIR, rel)
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


def _extract_remote_target(state: Dict[str, Any]) -> Tuple[str, int]:
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    target = remote.get("target", {}) if isinstance(remote.get("target", {}), dict) else {}
    host = str(target.get("host", "")).strip()
    port = int(target.get("port", 0) or 0)
    if host and port > 0:
        return host, port

    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    for key in ("remote", "target"):
        obj = challenge.get(key, {}) if isinstance(challenge.get(key, {}), dict) else {}
        h = str(obj.get("host", "")).strip()
        p = int(obj.get("port", 0) or 0)
        if h and p > 0:
            return h, p

    host = str(challenge.get("remote_host", "")).strip()
    port = int(challenge.get("remote_port", 0) or 0)
    if host and port > 0:
        return host, port
    return "", 0


def run_remote_target_preflight(
    *,
    state_path: str,
    session_id: str,
    cfg: Dict[str, Any],
    notes: List[str],
) -> Tuple[bool, str, str]:
    if not bool(cfg.get("enabled", True)):
        return True, "", ""

    state = load_json(state_path)
    host, port = _extract_remote_target(state)
    if (not host) or int(port or 0) <= 0:
        return True, "", ""

    timeout_sec = max(0.8, float(cfg.get("timeout_sec", 2.5) or 2.5))
    service_read_timeout_sec = max(0.2, float(cfg.get("service_read_timeout_sec", 0.9) or 0.9))
    disable_service_probe = bool(cfg.get("disable_service_probe", False))
    stop_on_unreachable = bool(cfg.get("stop_on_unreachable", False))
    warn_on_silent = bool(cfg.get("warn_on_silent", True))

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_rel = f"artifacts/reports/remote_preflight_{session_id}_{ts}.json"
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "remote_preflight.py"),
        "--host",
        host,
        "--port",
        str(int(port)),
        "--timeout-sec",
        str(float(timeout_sec)),
        "--service-read-timeout-sec",
        str(float(service_read_timeout_sec)),
        "--report",
        report_rel,
    ]
    if disable_service_probe:
        cmd.append("--disable-service-probe")

    p = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
    )

    out_obj: Dict[str, Any] = {}
    if p.stdout.strip():
        try:
            raw = json.loads(p.stdout)
            if isinstance(raw, dict):
                out_obj = raw
        except Exception:
            out_obj = {}
    report_abs = os.path.join(ROOT_DIR, report_rel)
    if (not out_obj) and os.path.exists(report_abs):
        try:
            raw = load_json(report_abs)
            if isinstance(raw, dict):
                out_obj = raw
        except Exception:
            out_obj = {}
    if not out_obj:
        out_obj = {
            "ok": False,
            "error": (p.stderr.strip() or p.stdout.strip() or "remote preflight failed"),
            "service_silent": False,
            "report": report_rel,
        }
    if "report" not in out_obj:
        out_obj["report"] = report_rel

    preflight_ok = bool(out_obj.get("ok", False))
    service_silent = bool(out_obj.get("service_silent", False))
    block_reason = str(out_obj.get("block_reason", "")).strip()
    best_target = str(out_obj.get("best_target", "")).strip()
    if best_target and best_target != host:
        notes.append(f"remote preflight candidate: host={host} best_target={best_target}")
    if service_silent and warn_on_silent:
        notes.append("remote preflight: target reachable but banner/menu is silent; verify prompt sync before exploit")

    state2 = load_json(state_path)
    remote = state2.setdefault("session", {}).setdefault("remote", {})
    target = remote.setdefault("target", {})
    if isinstance(target, dict):
        target["host"] = host
        target["port"] = int(port)
    remote["last_preflight_report"] = str(out_obj.get("report", report_rel)).strip() or report_rel
    remote["last_preflight_ok"] = bool(preflight_ok)
    remote["last_preflight_utc"] = utc_now()
    remote["last_preflight_silent"] = bool(service_silent)
    if best_target:
        remote["best_target"] = best_target

    latest = state2.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["remote_preflight_report"] = remote["last_preflight_report"]
    save_json(state_path, state2)

    if preflight_ok:
        return True, remote["last_preflight_report"], ""

    reason = block_reason or str(out_obj.get("error", "")).strip() or "remote preflight failed"
    notes.append(f"remote preflight failed: {reason}")
    if stop_on_unreachable:
        return False, remote["last_preflight_report"], reason
    return True, remote["last_preflight_report"], reason


def save_stage_cache(stage: str, state: Dict[str, Any], binary_sha256: str) -> str:
    if not binary_sha256:
        return ""
    patch = extract_stage_cache_patch(stage, state)
    if not patch:
        return ""
    p = stage_cache_path(binary_sha256, stage)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    doc = {
        "cache_schema_version": CACHE_SCHEMA_VERSION,
        "generated_utc": utc_now(),
        "stage": stage,
        "binary_sha256": binary_sha256,
        "state_patch": patch,
    }
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return repo_rel(p)


def _merge_dict(base: Dict[str, Any], patch: Dict[str, Any], overwrite: bool) -> Dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, dict):
            src = out.get(k, {})
            if not isinstance(src, dict):
                src = {}
            out[k] = _merge_dict(src, v, overwrite)
            continue
        if (k not in out) or overwrite:
            out[k] = v
            continue
        current = out.get(k)
        if (current in ("", None, [], {})) and (v not in ("", None, [], {})):
            out[k] = v
    return out


def apply_stage_cache(stage: str, state: Dict[str, Any], binary_sha256: str, overwrite: bool = False) -> Tuple[bool, str]:
    if not binary_sha256:
        return False, ""
    p = stage_cache_path(binary_sha256, stage)
    if not os.path.exists(p):
        return False, ""
    try:
        with open(p, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except Exception:
        return False, ""
    patch = doc.get("state_patch", {})
    if not isinstance(patch, dict):
        return False, ""
    if int(doc.get("cache_schema_version", 0) or 0) != CACHE_SCHEMA_VERSION:
        return False, ""
    merged = _merge_dict(state, patch, overwrite=overwrite)
    if not cache_patch_is_valid(stage, merged):
        return False, ""
    state.clear()
    state.update(merged)
    return True, repo_rel(p)


def state_digest(state: Dict[str, Any]) -> str:
    protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    latest = state.get("latest_bases", {}) if isinstance(state.get("latest_bases", {}), dict) else {}

    hypos = static.get("hypotheses", []) if isinstance(static.get("hypotheses", []), list) else []
    evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
    pie = str(latest.get("pie_base", "")).strip()
    rip = bool(caps.get("control_rip", False)) or str(caps.get("rip_control", "")).strip().lower() == "yes"

    return (
        f"arch={protections.get('arch','?')},"
        f"pie={protections.get('pie',None)},"
        f"hypos={len(hypos)},"
        f"evidence={len(evid)},"
        f"pie_base={'set' if pie else 'unset'},"
        f"rip_control={rip}"
    )


def make_cache_hit_artifacts(state: Dict[str, Any], session_id: str, loop_idx: int, stage: str, cache_rel: str) -> None:
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    if stage == "recon":
        log_rel = f"artifacts/logs/cache_{session_id}_{loop_idx:02d}_recon.log"
        rep_rel = f"artifacts/reports/cache_{session_id}_{loop_idx:02d}_recon.json"
        os.makedirs(os.path.join(ROOT_DIR, "artifacts", "logs"), exist_ok=True)
        os.makedirs(os.path.join(ROOT_DIR, "artifacts", "reports"), exist_ok=True)
        append_file(os.path.join(ROOT_DIR, log_rel), f"[cache-hit] stage=recon source={cache_rel}\n")
        with open(os.path.join(ROOT_DIR, rep_rel), "w", encoding="utf-8") as f:
            json.dump({"generated_utc": utc_now(), "stage": stage, "cache": cache_rel}, f, ensure_ascii=False, indent=2)
        latest["recon_log"] = log_rel
        latest["recon_report"] = rep_rel
        return
    if stage == "ida_slice":
        raw_rel = f"artifacts/logs/cache_{session_id}_{loop_idx:02d}_ida_raw.log"
        json_rel = f"artifacts/ida/cache_{session_id}_{loop_idx:02d}_slice.json"
        md_rel = f"artifacts/ida/cache_{session_id}_{loop_idx:02d}_slice.md"
        os.makedirs(os.path.join(ROOT_DIR, "artifacts", "logs"), exist_ok=True)
        os.makedirs(os.path.join(ROOT_DIR, "artifacts", "ida"), exist_ok=True)
        append_file(os.path.join(ROOT_DIR, raw_rel), f"[cache-hit] stage=ida_slice source={cache_rel}\n")
        with open(os.path.join(ROOT_DIR, json_rel), "w", encoding="utf-8") as f:
            json.dump({"generated_utc": utc_now(), "stage": stage, "cache": cache_rel}, f, ensure_ascii=False, indent=2)
        with open(os.path.join(ROOT_DIR, md_rel), "w", encoding="utf-8") as f:
            f.write(f"# cache hit\n\n- stage: {stage}\n- cache: {cache_rel}\n")
        latest["ida_raw_log"] = raw_rel
        latest["ida_slice_json"] = json_rel
        latest["ida_slice_md"] = md_rel
        return
    if stage == "gdb_evidence":
        raw_rel = f"artifacts/gdb/cache_{session_id}_{loop_idx:02d}_raw.txt"
        sum_rel = f"artifacts/gdb/cache_{session_id}_{loop_idx:02d}_summary.json"
        os.makedirs(os.path.join(ROOT_DIR, "artifacts", "gdb"), exist_ok=True)
        with open(os.path.join(ROOT_DIR, raw_rel), "w", encoding="utf-8") as f:
            f.write(f"[cache-hit] stage={stage} source={cache_rel}\n")
        with open(os.path.join(ROOT_DIR, sum_rel), "w", encoding="utf-8") as f:
            json.dump({"generated_utc": utc_now(), "stage": stage, "cache": cache_rel}, f, ensure_ascii=False, indent=2)
        latest["gdb_raw"] = raw_rel
        latest["gdb_summary"] = sum_rel


def ensure_session(state: Dict[str, Any], forced_session_id: str = "") -> str:
    session = state.setdefault("session", {})
    sid = forced_session_id or str(session.get("session_id", "")).strip()
    if not sid:
        sid = f"sess_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    session["session_id"] = sid
    sess_prefix = f"sessions/{sid}/"
    session.setdefault("created_utc", utc_now())
    session.setdefault("status", "initialized")
    session.setdefault("codex_enabled", True)
    session.setdefault("codex_pid", None)
    session.setdefault("challenge_source_dir", "")
    session.setdefault("challenge_work_dir", state.get("challenge", {}).get("workdir", ""))
    conv = str(session.get("conversation_log", "")).strip()
    if (not conv) or (not conv.startswith(sess_prefix)):
        session["conversation_log"] = f"sessions/{sid}/conversation.log"
    prompt = str(session.get("prompt_file", "")).strip()
    if (not prompt) or (not prompt.startswith(sess_prefix)):
        session["prompt_file"] = f"sessions/{sid}/prompt.txt"

    exp = session.setdefault("exp", {})
    exp_path = str(exp.get("path", "")).strip()
    if (not exp_path) or (not exp_path.startswith(sess_prefix)):
        exp["path"] = f"sessions/{sid}/exp/exp.py"
    exp.setdefault("status", "enabled")
    exp.setdefault("generated_utc", "")
    remote = session.setdefault("remote", {})
    remote.setdefault("ask_pending", False)
    remote.setdefault("request_file", "")
    remote.setdefault("requested_utc", "")
    remote.setdefault("answer", "")
    remote.setdefault("answered_utc", "")
    remote.setdefault("target", {"host": "", "port": 0})
    remote.setdefault("last_preflight_report", "")
    remote.setdefault("last_remote_report", "")
    remote.setdefault("last_remote_ok", False)

    session_dir = os.path.join(ROOT_DIR, "sessions", sid)
    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(os.path.join(session_dir, "exp"), exist_ok=True)
    os.makedirs(os.path.join(session_dir, "transactions"), exist_ok=True)

    return sid


def append_file(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        f.write(text)


def run_script(cmd: List[str], log_path: str) -> int:
    p = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=False)
    append_file(log_path, f"\n$ {' '.join(cmd)}\n")
    if p.stdout:
        append_file(log_path, p.stdout)
    if p.stderr:
        append_file(log_path, p.stderr)
    return int(p.returncode)


def run_mcp_self_heal(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    reason: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    notes: List[str] | None = None,
) -> str:
    return _run_mcp_self_heal_impl(
        root_dir=ROOT_DIR,
        state_path=state_path,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        reason=reason,
        health_cfg=health_cfg,
        codex_bin=codex_bin,
        notes=notes,
        load_json_fn=load_json,
        save_json_fn=save_json,
    )


def _health_required_variants(required: List[str], health_cfg: Dict[str, Any]) -> List[List[str]]:
    base = [str(x).strip() for x in required if str(x).strip()]
    if not base:
        base = ["pyghidra-mcp", "gdb"]

    # 默认将 pyghidra-mcp <-> pyghidra_bridge 视为等价后端，减少瞬态切换造成的误判。
    alias_map: Dict[str, List[str]] = {
        "pyghidra-mcp": ["pyghidra_bridge"],
        "pyghidra_bridge": ["pyghidra-mcp"],
    }
    cfg_alias = health_cfg.get("server_aliases", {})
    if isinstance(cfg_alias, dict):
        for k, v in cfg_alias.items():
            key = str(k).strip()
            if not key:
                continue
            vals: List[str] = []
            if isinstance(v, list):
                vals = [str(x).strip() for x in v if str(x).strip()]
            else:
                sv = str(v).strip()
                if sv:
                    vals = [sv]
            if vals:
                alias_map[key] = vals

    variants: List[List[str]] = [base]
    for idx, name in enumerate(base):
        for alt in alias_map.get(name, []):
            v = list(base)
            v[idx] = alt
            variants.append(v)

    dedup: List[List[str]] = []
    seen = set()
    for v in variants:
        key = tuple(v)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(v)
    return dedup


def _run_health_check_once(
    *,
    codex_bin: str,
    timeout_sec: float,
    authority: str,
    required: List[str],
    report_rel: str,
    functional_probe: bool = False,
    probe_timeout_sec: float = 12.0,
    probe_nonfatal: bool = False,
) -> Tuple[bool, str]:
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "health_check_mcp.py"),
        "--codex-bin",
        codex_bin,
        "--timeout-sec",
        str(timeout_sec),
        "--require",
        ",".join(required),
        "--authority",
        authority,
        "--report",
        report_rel,
        "--json",
    ]
    if functional_probe:
        cmd.append("--functional-probe")
        cmd.extend(["--probe-timeout-sec", str(max(3.0, float(probe_timeout_sec or 12.0)))])
        if probe_nonfatal:
            cmd.append("--probe-nonfatal")
    p = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=False)
    detail = ""
    if p.stdout.strip():
        try:
            obj = json.loads(p.stdout)
            if isinstance(obj, dict):
                reasons = obj.get("reasons", [])
                if isinstance(reasons, list) and reasons:
                    detail = "; ".join(str(x) for x in reasons[:3])
        except Exception:
            detail = ""
    if (not detail) and p.stderr.strip():
        detail = p.stderr.strip()[-300:]
    return (p.returncode == 0), detail


def write_binary_identity_report(
    *,
    state_path: str,
    session_id: str,
    stage_tag: str,
    note: str = "",
) -> str:
    state = load_json(state_path)
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    binary_rel = str(challenge.get("binary_path", "")).strip()
    cur_sid = str(state.get("session", {}).get("session_id", "")).strip() if isinstance(state.get("session", {}), dict) else ""
    if (cur_sid != str(session_id).strip()) or (not binary_rel):
        meta_path = os.path.join(ROOT_DIR, "sessions", str(session_id).strip(), "meta.json")
        if os.path.exists(meta_path):
            try:
                meta_obj = load_json(meta_path)
                ch_meta = meta_obj.get("challenge", {}) if isinstance(meta_obj.get("challenge", {}), dict) else {}
                alt = str(ch_meta.get("binary_path", "")).strip()
                if alt:
                    binary_rel = alt
            except Exception:
                pass
    binary_abs = binary_rel if os.path.isabs(binary_rel) else os.path.abspath(os.path.join(ROOT_DIR, binary_rel))

    exists = bool(binary_abs and os.path.isfile(binary_abs))
    sha256 = ""
    size = 0
    mtime_utc = ""
    if exists:
        try:
            sha256 = file_sha256(binary_abs)
        except Exception:
            sha256 = ""
        try:
            st = os.stat(binary_abs)
            size = int(st.st_size)
            mtime_utc = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            size = 0
            mtime_utc = ""

    tag = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(stage_tag or "check")).strip("._-") or "check"
    out_rel = f"artifacts/reports/binary_identity_{session_id}_{tag}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "stage_tag": tag,
        "note": str(note or "").strip(),
        "binary_path": binary_rel,
        "binary_abs": binary_abs,
        "exists": exists,
        "sha256": sha256,
        "size": size,
        "mtime_utc": mtime_utc,
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["binary_identity_report"] = out_rel
    if sha256:
        state.setdefault("challenge", {})["binary_sha256"] = sha256
    save_json(state_path, state)
    return out_rel


def run_mcp_health_check(
    *,
    state_path: str,
    session_id: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    notes: List[str],
) -> bool:
    if not bool(health_cfg.get("check_before_run", True)):
        return True

    required = health_cfg.get("required_servers", ["pyghidra-mcp", "gdb"])
    if not isinstance(required, list):
        required = ["pyghidra-mcp", "gdb"]
    required = [str(x).strip() for x in required if str(x).strip()]
    strict = bool(health_cfg.get("strict", False))
    timeout_sec = float(health_cfg.get("timeout_sec", 8.0) or 8.0)
    functional_probe = bool(health_cfg.get("functional_probe_before_run", True))
    probe_timeout_sec = float(health_cfg.get("functional_probe_timeout_sec", max(8.0, timeout_sec)) or max(8.0, timeout_sec))
    probe_nonfatal = bool(health_cfg.get("functional_probe_nonfatal", False))
    authority = str(health_cfg.get("authority", "project_config")).strip() or "project_config"
    if authority not in {"project_config", "codex_registry"}:
        authority = "project_config"

    enable_alias_fallback = bool(health_cfg.get("enable_alias_fallback", True))
    required_variants = _health_required_variants(required, health_cfg) if enable_alias_fallback else [required]
    ok = False
    detail = ""
    report_rel = f"artifacts/reports/health_mcp_{session_id}.json"
    used_variant = required

    for i, req_variant in enumerate(required_variants, start=1):
        report_try = report_rel if i == 1 else report_rel.replace(".json", f"_v{i:02d}.json")
        ok_try, detail_try = _run_health_check_once(
            codex_bin=codex_bin,
            timeout_sec=timeout_sec,
            authority=authority,
            required=req_variant,
            report_rel=report_try,
            functional_probe=functional_probe,
            probe_timeout_sec=probe_timeout_sec,
            probe_nonfatal=probe_nonfatal,
        )
        report_rel = report_try
        used_variant = req_variant
        if ok_try:
            ok = True
            detail = ""
            break
        if detail_try:
            detail = detail_try

    if not ok:
        notes.append("MCP health check 未通过")
        if detail:
            notes.append(f"MCP health reasons: {detail[:200]}")
    elif used_variant != required:
        notes.append(f"MCP health fallback: {'/'.join(required)} -> {'/'.join(used_variant)}")
        ident_rel = write_binary_identity_report(
            state_path=state_path,
            session_id=session_id,
            stage_tag="mcp_fallback",
            note=f"required={'/'.join(required)} used={'/'.join(used_variant)}",
        )
        notes.append(f"binary identity checked: {ident_rel}")

    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["mcp_health_report"] = report_rel
    save_json(state_path, state)

    if strict and (not ok):
        state = load_json(state_path)
        state.setdefault("session", {})["status"] = "mcp_health_failed"
        state["session"]["last_error"] = "mcp health check failed"
        save_json(state_path, state)
        return False
    return True


def _check_dir_rw(path: str, label: str) -> Tuple[bool, str, bool]:
    target = os.path.abspath(str(path or "").strip()) if str(path or "").strip() else ""
    if not target:
        return False, f"{label} is empty", False
    created = False
    try:
        if not os.path.isdir(target):
            os.makedirs(target, exist_ok=True)
            created = True
    except Exception as e:
        return False, f"{label} mkdir failed: {e}", created
    if not os.path.isdir(target):
        return False, f"{label} is not a directory: {target}", created
    probe = os.path.join(target, f".dirge_rw_probe_{os.getpid()}_{int(time.time() * 1000)}")
    try:
        with open(probe, "w", encoding="utf-8") as f:
            f.write("ok\n")
        os.unlink(probe)
        return True, "", created
    except Exception as e:
        return False, f"{label} not writable: {e}", created


def _has_live_pyghidra_process(project_path: str) -> bool:
    p = str(project_path or "").strip()
    if not p:
        return False
    try:
        ps = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=1.8,
        )
    except Exception:
        return False
    if int(ps.returncode) != 0:
        return False
    for line in str(ps.stdout or "").splitlines():
        s = str(line).strip()
        if not s:
            continue
        low = s.lower()
        if ("pyghidra-mcp" not in low) and ("mcp_jsonline_bridge.py" not in low):
            continue
        if p in s:
            return True
    return False


def _remove_stale_mcp_locks(project_path: str, project_name: str) -> List[str]:
    removed: List[str] = []
    base = str(project_path or "").strip()
    name = str(project_name or "").strip()
    if (not base) or (not name):
        return removed
    if _has_live_pyghidra_process(base):
        return removed
    for fn in (f"{name}.lock", f"{name}.lock~"):
        p = os.path.join(base, fn)
        try:
            if os.path.exists(p):
                os.unlink(p)
                removed.append(repo_rel(p))
        except Exception:
            continue
    return removed


def run_mcp_hard_preflight(
    *,
    state_path: str,
    session_id: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    notes: List[str],
) -> Tuple[bool, str, str]:
    enabled = bool(health_cfg.get("hard_preflight_enabled", True))
    strict = bool(health_cfg.get("hard_preflight_strict", True))
    if not enabled:
        return True, "", ""

    report_rel = f"artifacts/reports/mcp_hard_preflight_{session_id}.json"
    report_abs = os.path.join(ROOT_DIR, report_rel)
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)

    required = health_cfg.get("required_servers", ["pyghidra-mcp", "gdb"])
    if not isinstance(required, list):
        required = ["pyghidra-mcp", "gdb"]
    required = [str(x).strip() for x in required if str(x).strip()]

    runtime_root = str(os.environ.get("GHIDRA_RUNTIME_ROOT", "")).strip()
    project_path = str(os.environ.get("GHIDRA_MCP_PROJECT_PATH", "")).strip()
    project_name = str(os.environ.get("GHIDRA_MCP_PROJECT_NAME", "my_project")).strip() or "my_project"

    checks: Dict[str, Any] = {}
    issues: List[str] = []
    fixes: List[str] = []

    rt_ok, rt_err, rt_created = _check_dir_rw(runtime_root, "GHIDRA_RUNTIME_ROOT")
    checks["runtime_root"] = {
        "path": runtime_root,
        "ok": bool(rt_ok),
        "created": bool(rt_created),
        "error": rt_err,
    }
    if rt_created:
        fixes.append("created runtime root")
    if not rt_ok and rt_err:
        issues.append(rt_err)

    pp_ok, pp_err, pp_created = _check_dir_rw(project_path, "GHIDRA_MCP_PROJECT_PATH")
    checks["project_path"] = {
        "path": project_path,
        "ok": bool(pp_ok),
        "created": bool(pp_created),
        "error": pp_err,
    }
    if pp_created:
        fixes.append("created project path")
    if not pp_ok and pp_err:
        issues.append(pp_err)

    pn_ok = bool(project_name) and bool(re.fullmatch(r"[A-Za-z0-9_.-]+", project_name))
    checks["project_name"] = {
        "value": project_name,
        "ok": bool(pn_ok),
        "error": ("" if pn_ok else "invalid GHIDRA_MCP_PROJECT_NAME"),
    }
    if not pn_ok:
        issues.append("invalid GHIDRA_MCP_PROJECT_NAME")

    py_aliases = {"pyghidra-mcp", "pyghidra_bridge"}
    need_py_alias = any(x in py_aliases for x in required)
    alias_variants = _health_required_variants(required, health_cfg)
    seen_py_aliases: Set[str] = set()
    for row in alias_variants:
        for x in row:
            s = str(x).strip().lower()
            if s in py_aliases:
                seen_py_aliases.add(s)
    alias_mapping_ok = (not need_py_alias) or (len(seen_py_aliases) >= 2)
    checks["alias_mapping"] = {
        "required_servers": required,
        "variants": alias_variants,
        "seen_pyghidra_aliases": sorted(seen_py_aliases),
        "ok": bool(alias_mapping_ok),
    }
    if need_py_alias and (not alias_mapping_ok):
        issues.append("pyghidra alias mapping incomplete (need pyghidra-mcp<->pyghidra_bridge)")

    removed_locks = _remove_stale_mcp_locks(project_path, project_name)
    checks["removed_stale_locks"] = removed_locks
    if removed_locks:
        fixes.append("removed stale mcp lock files")

    alias_probe_enabled = bool(health_cfg.get("hard_preflight_alias_probe", True))
    alias_probe_timeout = float(health_cfg.get("hard_preflight_alias_probe_timeout_sec", 3.5) or 3.5)
    alias_probe_results: List[Dict[str, Any]] = []
    if alias_probe_enabled and need_py_alias:
        for alias in ("pyghidra-mcp", "pyghidra_bridge"):
            probe_report_rel = report_rel.replace(".json", f"_{alias.replace('-', '_')}.json")
            ok_try, detail_try = _run_health_check_once(
                codex_bin=codex_bin,
                timeout_sec=alias_probe_timeout,
                authority="codex_registry",
                required=[alias],
                report_rel=probe_report_rel,
                functional_probe=False,
            )
            alias_probe_results.append(
                {
                    "alias": alias,
                    "ok": bool(ok_try),
                    "detail": str(detail_try or "").strip(),
                    "report": probe_report_rel,
                }
            )
        if not any(bool(x.get("ok", False)) for x in alias_probe_results):
            issues.append("pyghidra alias probe failed in codex registry")
    checks["alias_probe"] = {
        "enabled": bool(alias_probe_enabled),
        "timeout_sec": float(alias_probe_timeout),
        "results": alias_probe_results,
    }

    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "strict": bool(strict),
        "enabled": bool(enabled),
        "ok": len(issues) == 0,
        "issues": issues,
        "fixes": fixes,
        "checks": checks,
    }
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["mcp_hard_preflight_report"] = report_rel
    save_json(state_path, state)

    if issues:
        detail = "; ".join(issues[:3])
        notes.append(f"mcp hard preflight issues: {detail}")
        if strict:
            return False, report_rel, detail
        return True, report_rel, detail
    notes.append("mcp hard preflight ok")
    return True, report_rel, ""


def tail_text_file(path: str, max_bytes: int = 12000) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            read_n = min(size, max(512, int(max_bytes)))
            f.seek(-read_n, os.SEEK_END)
            data = f.read(read_n)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def detect_stage_log_signature(log_path: str) -> str:
    txt = tail_text_file(log_path, max_bytes=24000).lower()
    if not txt:
        return ""
    checks = [
        ("mcp startup: no servers", "mcp startup: no servers"),
        ("transport closed", "mcp transport closed"),
        ("stream disconnected", "codex stream disconnected"),
        ("channel closed", "codex channel closed"),
        ("handshaking", "mcp handshaking failed"),
        ("initialize response", "mcp initialize response failed"),
        # 仅接受结构化状态信号，避免把提示词中的“analysis pending”误判为真实阻塞。
        ("analysis_complete\": false", "ghidra analysis pending"),
        ("analysis_complete\":false", "ghidra analysis pending"),
        ("analysis_complete: false", "ghidra analysis pending"),
        ("analysis_complete=false", "ghidra analysis pending"),
        ("failed to load configuration", "codex config load failed"),
    ]
    hits: List[str] = []
    for needle, tag in checks:
        if needle in txt:
            hits.append(tag)
    if not hits:
        return ""
    dedup: List[str] = []
    seen = set()
    for h in hits:
        if h in seen:
            continue
        seen.add(h)
        dedup.append(h)
    return "; ".join(dedup[:3])


def _extract_first_json_object(text: str, start: int = 0) -> Tuple[Any, int]:
    i = text.find("{", max(0, int(start)))
    if i < 0:
        return None, -1
    depth = 0
    in_str = False
    esc = False
    for j in range(i, len(text)):
        ch = text[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == "\"":
                in_str = False
            continue
        if ch == "\"":
            in_str = True
            continue
        if ch == "{":
            depth += 1
            continue
        if ch == "}":
            depth -= 1
            if depth == 0:
                blob = text[i : j + 1]
                try:
                    return json.loads(blob), (j + 1)
                except Exception:
                    return None, -1
    return None, -1


def _extract_tool_result_object(log_text: str, tool_name: str) -> Dict[str, Any]:
    if not log_text.strip() or not tool_name.strip():
        return {}
    pat = re.compile(rf"^{re.escape(tool_name)}\(.*\)\s+success in .*:$", re.MULTILINE)
    matches = list(pat.finditer(log_text))
    if not matches:
        return {}
    m = matches[-1]
    obj, _ = _extract_first_json_object(log_text, m.end())
    return obj if isinstance(obj, dict) else {}


def _tool_obj_payload_dict(tool_obj: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(tool_obj, dict):
        return {}
    sc = tool_obj.get("structuredContent", {})
    if isinstance(sc, dict) and sc:
        return sc
    content = tool_obj.get("content", [])
    if not isinstance(content, list):
        return {}
    for it in content:
        if not isinstance(it, dict):
            continue
        if str(it.get("type", "")).strip() != "text":
            continue
        txt = str(it.get("text", "") or "").strip()
        if not txt:
            continue
        try:
            parsed = json.loads(txt)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return {}


def try_recover_recon_from_log(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    log_rel: str,
) -> Tuple[bool, str]:
    log_abs = os.path.join(ROOT_DIR, log_rel)
    if not os.path.exists(log_abs):
        return False, ""
    txt = tail_text_file(log_abs, max_bytes=300000)
    if not txt.strip():
        return False, ""

    meta_obj = _extract_tool_result_object(txt, "pyghidra-mcp.list_project_binary_metadata")
    imp_obj = _extract_tool_result_object(txt, "pyghidra-mcp.list_imports")
    bins_obj = _extract_tool_result_object(txt, "pyghidra-mcp.list_project_binaries")
    if not meta_obj:
        return False, ""

    meta = _tool_obj_payload_dict(meta_obj)
    imports_doc = _tool_obj_payload_dict(imp_obj)
    bins_doc = _tool_obj_payload_dict(bins_obj) if bins_obj else {}
    if not meta:
        return False, ""

    import_items = imports_doc.get("imports", []) if isinstance(imports_doc.get("imports", []), list) else []
    import_names: List[str] = []
    for it in import_items:
        if isinstance(it, dict):
            nm = str(it.get("name", "")).strip()
        else:
            nm = str(it).strip()
        if nm:
            import_names.append(nm)
    if not import_names:
        # 超时时 list_imports 的 JSON 可能被截断，尝试从日志残段提取 name 字段。
        m_imp = re.search(r"tool pyghidra-mcp\.list_imports\(\{.*", txt, flags=re.S)
        imp_tail = txt[m_imp.start() :] if m_imp else txt
        import_names = re.findall(r'"name"\s*:\s*"([^"]+)"', imp_tail)
    import_names = list(dict.fromkeys(import_names))
    imports_recovered = bool(import_names)

    state = load_json(state_path)
    if not import_names:
        # 超时或中断时允许 metadata-only 降级恢复，避免 recon 在超时中反复空转。
        prev_io = state.get("io_profile", {}) if isinstance(state.get("io_profile", {}), dict) else {}
        prev_imports = prev_io.get("imports", []) if isinstance(prev_io.get("imports", []), list) else []
        import_names = [str(x).strip() for x in prev_imports if str(x).strip()]
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    bin_rel = str(challenge.get("binary_path", "")).strip()
    bin_abs = bin_rel if os.path.isabs(bin_rel) else os.path.abspath(os.path.join(ROOT_DIR, bin_rel))

    canonical_binary_name = ""
    binary_analyzed = False
    programs = bins_doc.get("programs", []) if isinstance(bins_doc.get("programs", []), list) else []
    for p in programs:
        if not isinstance(p, dict):
            continue
        fp = str(p.get("file_path", "")).strip()
        if fp and os.path.abspath(fp) == bin_abs:
            canonical_binary_name = str(p.get("name", "")).strip()
            binary_analyzed = bool(p.get("analyzed", False))
            break
    if not canonical_binary_name:
        m_name = re.search(r'canonical\s+[`"]?binary_name[`"]?\s*(?:为|is|:)\s*[`"]([^`"\s]+)', txt)
        if m_name:
            canonical_binary_name = str(m_name.group(1)).strip()
    if not binary_analyzed:
        if re.search(r"\banalyzed\b", txt, flags=re.IGNORECASE):
            binary_analyzed = True

    proc = str(meta.get("Processor", "")).strip().lower()
    addr_sz = str(meta.get("Address Size", "")).strip()
    arch = "unknown"
    if proc == "x86":
        arch = "amd64" if addr_sz == "64" else "i386"
    elif proc:
        arch = proc
    elf_type = str(meta.get("ELF File Type", "")).strip().lower()
    pie = ("shared object" in elf_type) or ("dyn" in elf_type)

    protections = state.setdefault("protections", {})
    protections["arch"] = arch
    protections["pie"] = bool(pie)
    if import_names:
        protections["canary"] = ("__stack_chk_fail" in import_names)
    protections.setdefault("nx", "unknown")
    protections.setdefault("relro", "unknown")

    io_profile = state.setdefault("io_profile", {})
    io_profile["imports"] = import_names[:32]
    io_profile["input_functions"] = [x for x in import_names if x in {"read", "gets", "fgets", "scanf", "__isoc99_scanf"}]
    io_profile["sink_functions"] = [x for x in import_names if x in {"system", "puts", "printf", "write"}]

    challenge["binary_name"] = canonical_binary_name or str(challenge.get("binary_name", "")).strip()
    challenge["analysis_ready"] = bool(binary_analyzed)
    pyghidra = challenge.setdefault("pyghidra", {})
    pyghidra["binary_name"] = canonical_binary_name
    pyghidra["binary_analyzed"] = bool(binary_analyzed)
    pyghidra["analysis_ready"] = bool(binary_analyzed)
    pyghidra["imports_recovered"] = bool(imports_recovered)
    state["challenge"] = challenge

    state.setdefault("summary", {})["next_actions"] = [
        "进入 ida_slice：定位输入函数调用链与可控数据路径",
        "进入 gdb_evidence：确认崩溃形态并提取 pie_base",
    ]
    prog = state.setdefault("progress", {})
    obj = prog.setdefault("objectives", {})
    obj.setdefault("score", int(obj.get("score", 0) or 0))
    obj.setdefault("target_achieved", bool(obj.get("target_achieved", False)))

    report_rel = f"artifacts/reports/recon_report_{session_id}_{loop_idx:02d}_hardstep.json"
    report_abs = os.path.join(ROOT_DIR, report_rel)
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)
    report_doc = {
        "session_id": session_id,
        "loop": loop_idx,
        "mode": "hardstep_log_recovery",
        "binary_path": bin_rel,
        "binary_name": canonical_binary_name,
        "binary_analyzed": bool(binary_analyzed),
        "metadata": meta,
        "imports": import_names,
        "imports_recovered": imports_recovered,
        "protections": protections,
        "io_profile": io_profile,
        "source_log": log_rel,
        "generated_utc": utc_now(),
    }
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report_doc, f, ensure_ascii=False, indent=2)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["recon_log"] = log_rel
    latest["recon_report"] = report_rel
    save_json(state_path, state)
    return True, report_rel


def try_recover_ida_from_log(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    log_rel: str,
) -> Tuple[bool, str, str]:
    log_abs = os.path.join(ROOT_DIR, log_rel)
    if not os.path.exists(log_abs):
        return False, "", ""
    txt = tail_text_file(log_abs, max_bytes=350000)
    if not txt.strip():
        return False, "", ""

    has_decompile = ("tool pyghidra-mcp.decompile_function(" in txt)
    has_callgraph = ("tool pyghidra-mcp.gen_callgraph(" in txt)
    has_xref = ("tool pyghidra-mcp.list_cross_references(" in txt)
    if not (has_decompile or has_callgraph or has_xref):
        return False, "", ""

    xref_targets = re.findall(r'tool pyghidra-mcp\.list_cross_references\(\{"binary_name":"[^"]+","name_or_address":"([^"]+)"', txt)
    xref_targets = list(dict.fromkeys([x.strip() for x in xref_targets if str(x).strip()]))
    callgraph_targets = re.findall(r'tool pyghidra-mcp\.gen_callgraph\(\{"binary_name":"[^"]+","function_name":"([^"]+)"', txt)
    callgraph_targets = list(dict.fromkeys([x.strip() for x in callgraph_targets if str(x).strip()]))

    state = load_json(state_path)
    static = state.setdefault("static_analysis", {})
    entrypoints = static.get("entrypoints", [])
    if not isinstance(entrypoints, list):
        entrypoints = []
    if not entrypoints:
        ep = [{"name": "main", "source": "hardstep_log_recovery"}]
        if callgraph_targets:
            ep[0]["name"] = callgraph_targets[0]
        entrypoints = ep

    suspects = static.get("suspects", [])
    if not isinstance(suspects, list):
        suspects = []
    if not suspects:
        for t in xref_targets[:4]:
            suspects.append({"name": t, "source": "xref_log"})
        if not suspects:
            suspects = [{"name": "read", "source": "fallback"}, {"name": "__isoc99_scanf", "source": "fallback"}]

    hypotheses = static.get("hypotheses", [])
    if not isinstance(hypotheses, list):
        hypotheses = []
    if not hypotheses:
        hypotheses = [
            {
                "id": f"h{loop_idx:02d}_stack_input",
                "type": "stack_overflow",
                "statement": "输入函数调用链可达主逻辑，存在栈溢出/覆盖返回地址可能。",
                "verify_with": "gdb_evidence: crash + pc_offset",
            },
            {
                "id": f"h{loop_idx:02d}_ret2win",
                "type": "ret2win",
                "statement": "程序存在可重定向控制流到目标函数（ret2win）路径。",
                "verify_with": "gdb_evidence: control_rip + target jump",
            },
            {
                "id": f"h{loop_idx:02d}_system",
                "type": "ret2libc",
                "statement": "导入符号中存在 system，可能构成 ret2libc/ret2text 调用链。",
                "verify_with": "gdb_evidence: call chain / registers",
            },
        ]
    hypotheses = hypotheses[:3]

    static["entrypoints"] = entrypoints
    static["suspects"] = suspects
    static["hypotheses"] = hypotheses

    json_rel = f"artifacts/ida/ida_slice_{session_id}_{loop_idx:02d}_hardstep.json"
    md_rel = f"artifacts/ida/ida_slice_{session_id}_{loop_idx:02d}_hardstep.md"
    json_abs = os.path.join(ROOT_DIR, json_rel)
    md_abs = os.path.join(ROOT_DIR, md_rel)
    os.makedirs(os.path.dirname(json_abs), exist_ok=True)

    ida_doc = {
        "session_id": session_id,
        "loop": loop_idx,
        "mode": "hardstep_log_recovery",
        "entrypoints": entrypoints,
        "suspects": suspects,
        "hypotheses": hypotheses,
        "evidence": {
            "has_decompile": has_decompile,
            "has_callgraph": has_callgraph,
            "has_xref": has_xref,
            "xref_targets": xref_targets,
            "callgraph_targets": callgraph_targets,
        },
        "source_log": log_rel,
        "generated_utc": utc_now(),
    }
    with open(json_abs, "w", encoding="utf-8") as f:
        json.dump(ida_doc, f, ensure_ascii=False, indent=2)
    with open(md_abs, "w", encoding="utf-8") as f:
        f.write("# IDA Slice Recovery (Hardstep)\n\n")
        f.write(f"- session: `{session_id}`\n")
        f.write(f"- loop: `{loop_idx}`\n")
        f.write(f"- source_log: `{log_rel}`\n")
        f.write(f"- decompile: `{has_decompile}`\n")
        f.write(f"- callgraph: `{has_callgraph}`\n")
        f.write(f"- xref: `{has_xref}`\n")
        f.write(f"- suspects: `{', '.join(str(x.get('name', '')) for x in suspects[:6])}`\n")

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["ida_raw_log"] = log_rel
    latest["ida_slice_json"] = json_rel
    latest["ida_slice_md"] = md_rel
    state.setdefault("summary", {})["next_actions"] = [
        "进入 gdb_evidence：确认 PIE 基址与崩溃证据",
        "在 gdb 中验证 offset_to_rip 与控制流能力",
    ]
    save_json(state_path, state)
    return True, json_rel, md_rel


def _extract_asm_excerpt(text: str, max_lines: int = 48) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    seen = set()
    patterns = [
        re.compile(r"^\s*(?:=>\s*)?0x[0-9a-fA-F]{4,}\b.*$"),
        re.compile(r"^\s*[0-9a-fA-F]{4,}:\s+(?:[0-9a-fA-F]{2}\s+){1,16}.*$", re.IGNORECASE),
    ]
    for line in text.splitlines():
        s = line.rstrip()
        if not s:
            continue
        hit = any(p.match(s) for p in patterns)
        if not hit:
            continue
        norm = s[:200]
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
        if len(out) >= max_lines:
            break
    return out


def _extract_tool_excerpt(text: str, max_lines: int = 24) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    seen = set()
    for line in text.splitlines():
        s = line.strip()
        if (not s) or (not s.startswith("tool pyghidra-mcp.")):
            continue
        norm = s[:200]
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
        if len(out) >= max_lines:
            break
    return out


def write_ida_dual_evidence_bundle(state_path: str, session_id: str, loop_idx: int) -> str:
    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    ida_json_rel = str(latest.get("ida_slice_json", "")).strip()
    ida_md_rel = str(latest.get("ida_slice_md", "")).strip()
    ida_raw_rel = str(latest.get("ida_raw_log", "")).strip()
    gdb_raw_rel = str(latest.get("gdb_raw", "")).strip()
    if (not ida_json_rel) and (not ida_md_rel) and (not ida_raw_rel):
        return ""

    summary_excerpt = ""
    if ida_md_rel:
        ida_md_abs = os.path.join(ROOT_DIR, ida_md_rel)
        if os.path.exists(ida_md_abs):
            try:
                with open(ida_md_abs, "r", encoding="utf-8", errors="ignore") as f:
                    summary_excerpt = f.read(1500).strip()
            except Exception:
                summary_excerpt = ""

    asm_source_rel = ""
    asm_excerpt: List[str] = []
    if gdb_raw_rel:
        gdb_raw_abs = os.path.join(ROOT_DIR, gdb_raw_rel)
        if os.path.exists(gdb_raw_abs):
            asm_source_rel = gdb_raw_rel
            asm_excerpt = _extract_asm_excerpt(tail_text_file(gdb_raw_abs, max_bytes=160000), max_lines=48)
    if (not asm_excerpt) and ida_raw_rel:
        ida_raw_abs = os.path.join(ROOT_DIR, ida_raw_rel)
        if os.path.exists(ida_raw_abs):
            asm_source_rel = ida_raw_rel
            ida_tail = tail_text_file(ida_raw_abs, max_bytes=160000)
            asm_excerpt = _extract_asm_excerpt(ida_tail, max_lines=48)
            if not asm_excerpt:
                asm_excerpt = _extract_tool_excerpt(ida_tail, max_lines=24)
    if not asm_excerpt:
        fallback = [ln.strip() for ln in summary_excerpt.splitlines() if ln.strip()][:12] if summary_excerpt else []
        asm_excerpt = fallback if fallback else ["(no asm lines captured; refer to raw logs)"]

    out_rel = f"artifacts/ida/ida_dual_evidence_{session_id}_{loop_idx:02d}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "refs": {
            "ida_slice_json": ida_json_rel,
            "ida_slice_md": ida_md_rel,
            "ida_raw_log": ida_raw_rel,
            "asm_source": asm_source_rel,
        },
        "summary_excerpt": summary_excerpt,
        "asm_excerpt": asm_excerpt,
        "note": "双通道证据：静态摘要 + 汇编片段（优先 gdb_raw，回退 ida_raw_log）。",
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    latest["ida_dual_evidence"] = out_rel
    save_json(state_path, state)
    return out_rel


def _session_tag(raw: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(raw or "").strip())
    s = s.strip("._-")
    return s or "shared"


def configure_session_mcp_env(session_id: str) -> Dict[str, Any]:
    keys = [
        "DIRGE_SESSION_ID",
        "PWN_SESSION_ID",
        "GHIDRA_RUNTIME_ROOT",
        "GHIDRA_MCP_PROJECT_PATH",
        "GHIDRA_MCP_PROJECT_NAME",
        "GHIDRA_MCP_HOME",
        "GHIDRA_MCP_XDG_CONFIG_HOME",
        "GHIDRA_MCP_XDG_CACHE_HOME",
        "CODEX_RUNTIME_HOME",
        "JAVA_TOOL_OPTIONS",
    ]
    prev = {k: os.environ.get(k) for k in keys}
    sid = str(session_id or "").strip()
    tag = _session_tag(sid)
    os.environ["DIRGE_SESSION_ID"] = sid
    os.environ["PWN_SESSION_ID"] = sid

    # 默认每个会话独立 Ghidra runtime/project，降低跨题锁污染与 transport 抖动。
    if str(os.environ.get("DIRGE_SHARED_GHIDRA_PROJECT", "0")).strip() != "1":
        gh_root = str(os.environ.get("GHIDRA_RUNTIME_ROOT", "/tmp/project_dirge_ghidra")).strip() or "/tmp/project_dirge_ghidra"
        session_root = os.path.join(gh_root, tag)
        project_path = os.path.join(session_root, "project")
        home_path = os.path.join(session_root, "home")
        xdg_cfg = os.path.join(home_path, ".config")
        xdg_cache = os.path.join(home_path, ".cache")
        os.makedirs(project_path, exist_ok=True)
        os.makedirs(xdg_cfg, exist_ok=True)
        os.makedirs(xdg_cache, exist_ok=True)
        os.environ["GHIDRA_RUNTIME_ROOT"] = gh_root
        os.environ["GHIDRA_MCP_PROJECT_PATH"] = project_path
        os.environ.setdefault("GHIDRA_MCP_PROJECT_NAME", "my_project")
        os.environ["GHIDRA_MCP_HOME"] = home_path
        os.environ["GHIDRA_MCP_XDG_CONFIG_HOME"] = xdg_cfg
        os.environ["GHIDRA_MCP_XDG_CACHE_HOME"] = xdg_cache
        if not str(os.environ.get("CODEX_RUNTIME_HOME", "")).strip():
            uid = str(os.environ.get("UID", "1000")).strip() or "1000"
            os.environ["CODEX_RUNTIME_HOME"] = f"/tmp/project_dirge_codex_home_{uid}_{tag}"
    # 统一 headless，减少 pyghidra 在无稳定显示环境下的 AWTError。
    jto = str(os.environ.get("JAVA_TOOL_OPTIONS", "")).strip()
    if "-Djava.awt.headless=true" not in jto:
        os.environ["JAVA_TOOL_OPTIONS"] = (jto + " -Djava.awt.headless=true").strip() if jto else "-Djava.awt.headless=true"
    return prev


def restore_env(prev: Dict[str, Any]) -> None:
    for k, v in prev.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = str(v)


def _repo_rel_existing(path_like: str) -> str:
    p = str(path_like or "").strip()
    if not p:
        return ""
    ap = p if os.path.isabs(p) else os.path.abspath(os.path.join(ROOT_DIR, p))
    if not os.path.exists(ap):
        return ""
    try:
        rel = os.path.relpath(ap, ROOT_DIR)
    except Exception:
        return ""
    if rel.startswith(".."):
        return ""
    return rel


def _find_latest_exp_verify_report(session_id: str, loop_idx: int) -> str:
    prefer = os.path.join(ROOT_DIR, "artifacts", "reports", f"exp_verify_{session_id}_{max(0, int(loop_idx)):02d}.json")
    if os.path.exists(prefer):
        return repo_rel(prefer)
    pat = os.path.join(ROOT_DIR, "artifacts", "reports", f"exp_verify_{session_id}_*.json")
    cands = []
    for p in glob.glob(pat):
        base = os.path.basename(p)
        m_sum = re.match(rf"^exp_verify_{re.escape(session_id)}_(\d+)\.json$", base)
        if m_sum:
            loop_no = int(m_sum.group(1))
            cands.append((2, loop_no, 0, p))
            continue
        m_att = re.match(rf"^exp_verify_{re.escape(session_id)}_(\d+)_(\d+)\.json$", base)
        if m_att:
            loop_no = int(m_att.group(1))
            att_no = int(m_att.group(2))
            cands.append((1, loop_no, att_no, p))
    if not cands:
        return ""
    cands.sort(key=lambda x: (x[0], x[1], x[2], os.path.getmtime(x[3]) if os.path.exists(x[3]) else 0.0), reverse=True)
    return repo_rel(cands[0][3])


def ensure_exploit_artifact_links(state_path: str, session_id: str, loop_idx: int, verify_report_hint: str = "") -> Tuple[str, str]:
    state = load_json(state_path)
    sess = state.setdefault("session", {})
    exp = sess.setdefault("exp", {})
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})

    plan_rel = _repo_rel_existing(str(latest.get("exp_plan_report", "")).strip())
    if not plan_rel:
        plan_rel = _repo_rel_existing(str(exp.get("plan_report", "")).strip())
    if not plan_rel:
        plan_rel = _repo_rel_existing(f"artifacts/reports/exp_plan_{session_id}.json")
    if plan_rel:
        latest["exp_plan_report"] = plan_rel
        exp["plan_report"] = plan_rel

    verify_rel = _repo_rel_existing(str(verify_report_hint).strip())
    if not verify_rel:
        verify_rel = _repo_rel_existing(str(latest.get("exp_verify_report", "")).strip())
    if not verify_rel:
        verify_rel = _repo_rel_existing(str(exp.get("verify_report", "")).strip())
    if not verify_rel:
        verify_rel = _find_latest_exp_verify_report(session_id, loop_idx)
    if verify_rel:
        latest["exp_verify_report"] = verify_rel
        exp["verify_report"] = verify_rel

    local_rel = _repo_rel_existing(str(exp.get("local_path", "")).strip())
    if local_rel:
        latest["exp_local_path"] = local_rel
        exp["local_path"] = local_rel
    remote_rel = _repo_rel_existing(str(exp.get("remote_path", "")).strip())
    if remote_rel:
        latest["exp_remote_path"] = remote_rel
        exp["remote_path"] = remote_rel

    save_json(state_path, state)
    return plan_rel, verify_rel


def _parse_any_int(v: Any) -> int:
    if isinstance(v, int):
        return int(v)
    s = str(v or "").strip().lower()
    if not s:
        return 0
    try:
        return int(s, 16) if s.startswith("0x") else int(s, 10)
    except Exception:
        return 0


def _latest_file_by_patterns(patterns: List[str]) -> str:
    cands: List[str] = []
    for pat in patterns:
        if not pat:
            continue
        cands.extend(glob.glob(os.path.join(ROOT_DIR, pat)))
    cands = [p for p in cands if os.path.isfile(p)]
    if not cands:
        return ""
    cands.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    return repo_rel(cands[0])


def normalize_latest_artifact_keys(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    stage_log_rel: str = "",
) -> Dict[str, str]:
    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    changed: Dict[str, str] = {}

    def _set_if_missing(key: str, value: str) -> None:
        v = str(value or "").strip()
        if not v:
            return
        if str(latest.get(key, "")).strip():
            return
        latest[key] = v
        changed[key] = v

    stage_log = str(stage_log_rel or "").strip()
    if stage == "recon":
        _set_if_missing("recon_log", stage_log)
        _set_if_missing(
            "recon_report",
            _latest_file_by_patterns(
                [
                    f"artifacts/reports/recon_report_{session_id}_{loop_idx:02d}*.json",
                    f"artifacts/reports/recon_report_{session_id}_*.json",
                    f"artifacts/ida/recon_{session_id}_*.json",
                ]
            ),
        )
    if stage == "ida_slice":
        _set_if_missing("ida_raw_log", stage_log)
        _set_if_missing(
            "ida_slice_json",
            _latest_file_by_patterns(
                [
                    f"artifacts/ida/ida_slice_{session_id}_{loop_idx:02d}*.json",
                    f"artifacts/ida/ida_slice_{session_id}_*.json",
                ]
            ),
        )
        _set_if_missing(
            "ida_slice_md",
            _latest_file_by_patterns(
                [
                    f"artifacts/ida/ida_slice_{session_id}_{loop_idx:02d}*.md",
                    f"artifacts/ida/ida_slice_{session_id}_*.md",
                ]
            ),
        )
    if stage == "gdb_evidence":
        _set_if_missing(
            "gdb_clusters",
            _latest_file_by_patterns(
                [
                    f"artifacts/reports/{session_id}_crash_clusters.json",
                    f"artifacts/reports/*{session_id}*cluster*.json",
                ]
            ),
        )
        _set_if_missing(
            "capabilities_report",
            _latest_file_by_patterns(
                [
                    f"artifacts/reports/capabilities_{session_id}_{loop_idx:02d}.json",
                    f"artifacts/reports/capabilities_{session_id}_*.json",
                ]
            ),
        )
    if exploit_stage_level(stage) >= 0:
        ensure_exploit_artifact_links(state_path=state_path, session_id=session_id, loop_idx=loop_idx)
        state = load_json(state_path)
        latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
        exp = state.setdefault("session", {}).setdefault("exp", {})
        _set_if_missing("exp_plan_report", str(exp.get("plan_report", "")).strip())
        _set_if_missing("exp_verify_report", str(exp.get("verify_report", "")).strip())

    if changed:
        save_json(state_path, state)
    return changed


def write_symbol_map_artifact(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    source_log_rel: str = "",
) -> str:
    state = load_json(state_path)
    static = state.get("static_analysis", {}) if isinstance(state.get("static_analysis", {}), dict) else {}
    entries: Dict[str, Dict[str, Any]] = {}

    for key in ["entrypoints", "suspects", "hypotheses"]:
        arr = static.get(key, [])
        if not isinstance(arr, list):
            continue
        for it in arr:
            if not isinstance(it, dict):
                continue
            name = str(it.get("name", "") or it.get("symbol", "") or it.get("type", "")).strip()
            if not name:
                continue
            addr = 0
            for ak in ["addr", "address", "target_addr", "ea", "call_addr", "func_addr"]:
                addr = _parse_any_int(it.get(ak, 0))
                if addr > 0:
                    break
            if addr <= 0:
                continue
            entries[name] = {"name": name, "address": hex(addr), "source": key}

    # 尝试从日志中抽取 name/address 对，支持地址化 xref 缓存。
    log_rel = str(source_log_rel or "").strip()
    if log_rel:
        log_abs = os.path.join(ROOT_DIR, log_rel)
        if os.path.exists(log_abs):
            txt = tail_text_file(log_abs, max_bytes=260000)
            for m in re.finditer(r'"name"\s*:\s*"([^"]+)"[^\n\r]*?"address"\s*:\s*"(0x[0-9a-fA-F]+)"', txt):
                nm = str(m.group(1)).strip()
                av = str(m.group(2)).strip()
                if nm and av:
                    entries.setdefault(nm, {"name": nm, "address": av, "source": "ida_log"})
            for m in re.finditer(r'"address"\s*:\s*"(0x[0-9a-fA-F]+)"[^\n\r]*?"name"\s*:\s*"([^"]+)"', txt):
                av = str(m.group(1)).strip()
                nm = str(m.group(2)).strip()
                if nm and av:
                    entries.setdefault(nm, {"name": nm, "address": av, "source": "ida_log"})

    if not entries:
        return ""

    out_rel = f"artifacts/ida/symbol_map_{session_id}_{loop_idx:02d}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    symbol_items = sorted(entries.values(), key=lambda x: (x.get("name", ""), x.get("address", "")))
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_utc": utc_now(),
                "session_id": session_id,
                "loop": int(loop_idx),
                "count": len(symbol_items),
                "symbols": symbol_items,
                "source_log": log_rel,
                "note": "L1 地址化查询缓存：后续 xref/callsite 优先使用 address，减少名称歧义。",
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["symbol_map"] = out_rel
    save_json(state_path, state)
    return out_rel


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
) -> None:
    _update_stage_timing_state_impl(
        state_path=state_path,
        stage=stage,
        loop_idx=loop_idx,
        started_utc=started_utc,
        ended_utc=ended_utc,
        elapsed_sec=elapsed_sec,
        attempts=attempts,
        ok=ok,
        load_json_fn=load_json,
        save_json_fn=save_json,
        utc_now_fn=utc_now,
    )


def sync_exp_verify_artifacts(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    exp_verify_report: str,
) -> Dict[str, Any]:
    return _sync_exp_verify_artifacts_impl(
        state_path=state_path,
        session_id=session_id,
        loop_idx=loop_idx,
        exp_verify_report=exp_verify_report,
        load_json_fn=load_json,
        save_json_fn=save_json,
        ensure_exploit_artifact_links_fn=ensure_exploit_artifact_links,
    )


def write_ida_blocker_report(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    reason: str,
    log_rel: str,
) -> str:
    log_abs = os.path.join(ROOT_DIR, log_rel) if log_rel else ""
    tail = tail_text_file(log_abs, max_bytes=220000) if (log_abs and os.path.exists(log_abs)) else ""
    low = tail.lower()
    sigs: List[str] = []
    checks = [
        ("analysis_complete\": false", "analysis_complete=false"),
        ("analysis_complete: false", "analysis_complete=false"),
        ("transport closed", "transport_closed"),
        ("serde error", "serde_error"),
        ("expected value at line 1 column 1", "serde_invalid_json"),
        ("closedexception", "ghidra_closed_exception"),
        ("file is closed", "ghidra_file_closed"),
        ("unable to lock project", "ghidra_project_lock"),
        ("lockexception", "ghidra_project_lock"),
    ]
    for needle, tag in checks:
        if needle in low:
            sigs.append(tag)
    if not sigs and reason:
        sigs.append(_shorten_text(reason, 160))
    sigs = list(dict.fromkeys([x for x in sigs if x]))

    out_rel = f"artifacts/ida/ida_blocker_{session_id}_{loop_idx:02d}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "stage": "ida_slice",
        "reason": str(reason or "").strip(),
        "signatures": sigs,
        "source_log": log_rel,
        "note": "IDA/Ghidra 阶段阻塞记录；当前轮按 fail-open 策略允许继续到 gdb_evidence。",
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    state = load_json(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["ida_blocker_report"] = out_rel
    if log_rel:
        latest["ida_raw_log"] = log_rel
    blockers = state.setdefault("summary", {}).setdefault("blockers", [])
    blocker_line = f"ida_slice blocked(loop={loop_idx}): {', '.join(sigs) if sigs else 'unknown'}"
    if isinstance(blockers, list) and blocker_line not in blockers:
        blockers.append(blocker_line)
    save_json(state_path, state)
    return out_rel


def run_stage_mcp_gate(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
) -> Tuple[bool, str, str]:
    return _run_stage_mcp_gate_impl(
        state_path=state_path,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        health_cfg=health_cfg,
        codex_bin=codex_bin,
        health_required_variants_fn=_health_required_variants,
        run_health_check_once_fn=_run_health_check_once,
        is_analysis_transient_error_fn=_is_analysis_transient_error,
        write_binary_identity_report_fn=write_binary_identity_report,
        run_mcp_self_heal_fn=run_mcp_self_heal,
        load_json_fn=load_json,
        save_json_fn=save_json,
        sleep_fn=time.sleep,
    )


def stage_counter_key(stage: str) -> str:
    if exploit_stage_level(stage) >= 0:
        return "exploit_runs"
    return {
        "recon": "recon_runs",
        "ida_slice": "ida_calls",
        "gdb_evidence": "gdb_runs",
    }.get(stage, "")


def get_path_value(data: Dict[str, Any], path: str) -> Tuple[bool, Any]:
    cur: Any = data
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return False, None
    return True, cur


def validate_stage_runner_spec(state: Dict[str, Any], stage_spec: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    if not isinstance(latest, dict):
        latest = {}

    for key in stage_spec.get("required_artifact_keys", []):
        p = str(latest.get(key, "")).strip()
        if not p:
            errors.append(f"required artifact key missing/empty: latest.paths.{key}")
            continue
        ap = os.path.join(ROOT_DIR, p) if not os.path.isabs(p) else p
        if not os.path.exists(ap):
            errors.append(f"required artifact file not found: latest.paths.{key} -> {p}")

    for path in stage_spec.get("required_state_paths", []):
        ok, value = get_path_value(state, str(path))
        if not ok:
            errors.append(f"required state path missing: {path}")
            continue
        if value is None:
            errors.append(f"required state path is null: {path}")
            continue
        if isinstance(value, str) and not value.strip():
            errors.append(f"required state path empty: {path}")
            continue
        if isinstance(value, list) and len(value) == 0:
            errors.append(f"required state path list empty: {path}")
            continue

    def _value_present(value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, str):
            return bool(value.strip())
        if isinstance(value, list):
            return len(value) > 0
        return True

    req_last_evid = stage_spec.get("required_last_evidence_paths", [])
    req_last_any = stage_spec.get("required_last_evidence_any_of_paths", [])
    has_last_requirements = (
        (isinstance(req_last_evid, list) and bool(req_last_evid))
        or (isinstance(req_last_any, list) and bool(req_last_any))
    )
    if has_last_requirements:
        dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
        evid = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
        if not evid:
            errors.append("required last evidence missing: dynamic_evidence.evidence is empty")
        else:
            last = evid[-1] if isinstance(evid[-1], dict) else {}
            if not isinstance(last, dict):
                errors.append("required last evidence invalid: dynamic_evidence.evidence[-1] is not object")
            else:
                if isinstance(req_last_evid, list):
                    for path in req_last_evid:
                        ok, value = get_path_value(last, str(path))
                        if not ok:
                            errors.append(f"required last evidence path missing: {path}")
                            continue
                        if not _value_present(value):
                            errors.append(f"required last evidence path empty: {path}")
                            continue
                if isinstance(req_last_any, list) and req_last_any:
                    any_ok = False
                    norm_paths = [str(x).strip() for x in req_last_any if str(x).strip()]
                    for path in norm_paths:
                        ok, value = get_path_value(last, path)
                        if ok and _value_present(value):
                            any_ok = True
                            break
                    if (not any_ok) and norm_paths:
                        errors.append(
                            "required last evidence any_of not satisfied: "
                            + ", ".join(norm_paths)
                        )
    return errors


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

    key = stage_counter_key(stage)
    if key:
        now_stage = int(counters.get(key, 0) or 0)
        before_stage = int(before_counters.get(key, 0) or 0)
        if now_stage <= before_stage:
            counters[key] = before_stage + 1

    progress["stage"] = stage
    progress["last_updated_utc"] = utc_now()
    return after


def compact_hint_text(s: str, max_chars: int) -> str:
    txt = " ".join(str(s or "").split())
    if max_chars <= 0:
        return txt
    if len(txt) <= max_chars:
        return txt
    return txt[: max_chars - 3] + "..."


def build_stage_prompt(stage: str, context: Dict[str, str], contract_hint: str = "") -> str:
    extra = f" {contract_hint.strip()}" if contract_hint.strip() else ""
    digest = str(context.get("state_digest", "")).strip()
    digest_hint = f" 当前状态摘要: {digest}。" if digest else ""
    bin_rel = str(context.get("binary_path", "")).strip()
    bin_abs = str(context.get("binary_path_abs", "")).strip()
    if (not bin_abs) and bin_rel:
        if os.path.isabs(bin_rel):
            bin_abs = bin_rel
        else:
            bin_abs = os.path.abspath(os.path.join(ROOT_DIR, bin_rel))
    strict_mcp_hint = (
        "仅允许 MCP 调用与最小落盘；禁止仓库遍历/环境排查命令"
        "（ls/rg/find/sed/cat/ps/kill/history）。"
        "禁止先做 MCP 资源探测（list_mcp_resources/list_mcp_resource_templates）。"
        "直接调用本阶段约定工具并在一次回复内完成。"
        "禁止调用 session_api.py stop 或写 stop.requested.json。"
    )
    if stage == "bundle_l0_l4":
        return (
            "一次完成 L0->L2（MCP-only，最小查询）。"
            "仅保留必要证据：protections、hypotheses、pie_base、evidence_id。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN={context.get('binary_path','')}。"
            f"{digest_hint}{extra}"
        )
    if stage == "bundle_l0_l2":
        return (
            "一次完成 L0->L2（MCP-only，最小查询）。"
            "必须更新 protections/io_profile/static_analysis/dynamic_evidence/latest_bases.pie_base。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN={context.get('binary_path','')}。"
            f"{digest_hint}{extra}"
        )
    if stage == "recon":
        return (
            "执行 L0 Recon（MCP-only，禁止大输出）。"
            "仅收集 protections 与 IO 轮廓，避免重复探测。"
            "按固定顺序执行："
            "1) import_binary(binary_path)；"
            "2) list_project_binaries（按 file_path 精确匹配拿 canonical binary_name）；"
            "若第2步未匹配到目标，允许再调用一次 list_project_binaries 刷新后继续。"
            "若第二次仍未匹配，直接选 basename 相同的最新条目作为 canonical binary_name 并继续，不再刷新。"
            "3) list_project_binary_metadata(binary_name)；"
            "4) import-ready 门控：若 metadata.analysis_complete!=true，轮询 metadata（最多 3 次）直到 true；"
            "若仍为 false，立即以 'analysis pending' 失败返回，不要继续切片相关调用。"
            "5) list_imports(binary_name, query='puts|system|read|gets|fgets|scanf|printf|__stack_chk_fail|setvbuf|alarm|signal|write', limit<=24)。"
            "禁止重试同一失败参数，禁止额外工具扩展。"
            "调用预算：最多 7 次 MCP 调用，拿到最小证据后立即结束。"
            f"{strict_mcp_hint}"
            f"SID={context.get('session_id','')} BIN_REL={bin_rel} BIN_ABS={bin_abs}。"
            f"{digest_hint}{extra}"
        )
    if stage == "ida_slice":
        base = IDAAdapter().build_prompt(context)
        base += (
            " 切片前必须校验 import-ready：list_project_binary_metadata(canonical binary_name) 且 analysis_complete=true；"
            " 若不满足，直接返回 'analysis pending' 并结束本阶段，禁止盲目反编译重试。"
            " 先生成或复用 symbol_map（name->0xaddr），后续 xref/callsite 查询优先使用 address。"
            " 对歧义符号禁止反复按名字重试，必须切到 0x 地址查询。"
        )
        sym_map = str(context.get("symbol_map", "")).strip()
        if sym_map:
            base += f" 已有 symbol_map: {sym_map}。"
        active_hids = str(context.get("active_hypothesis_ids", "")).strip()
        if active_hids:
            base += f" 当前活跃 hypothesis: {active_hids}。"
        if digest_hint:
            base += digest_hint
        if extra:
            base += extra
        return base
    if stage == "gdb_evidence":
        base = GDBAdapter().build_prompt(context)
        base += " 限制输出：回溯<=8帧，栈窗<=32 qword，仅关键寄存器与 mappings。"
        repl_hint = str(context.get("repl_cmd_exec_hint", "")).strip().lower() in {"1", "true", "yes"}
        if repl_hint:
            base += (
                " 目标疑似 REPL/命令执行：不要默认 cyclic 崩溃探测。"
                "优先验证输入语义/回显边界、可执行表达式形态、命令执行路径（如 child_process/exec/eval）与输出噪声过滤。"
            )
        mm = str(context.get("mutation_manifest", "")).strip()
        mids = str(context.get("mutation_input_ids", "")).strip()
        if mm:
            base += f" 本轮输入变异清单: {mm}。"
        if mids:
            base += f" 请优先尝试输入 ID: {mids}。"
        if digest_hint:
            base += digest_hint
        if extra:
            base += extra
        return base
    if exploit_stage_level(stage) >= 0:
        allow_remote_exp = str(context.get("allow_remote_exp", "")).strip().lower() in {"1", "true", "yes"}
        repl_hint = str(context.get("repl_cmd_exec_hint", "")).strip().lower() in {"1", "true", "yes"}
        nxoff_hint = str(context.get("nxoff_libc_free_hint", "")).strip().lower() in {"1", "true", "yes"}
        remote_hint = "允许在脚本里预留远程连接参数（host/port），但自动流程不主动远程交互。" if allow_remote_exp else "仅写本地脚本，不做远程交互。"
        repl_extra = ""
        if repl_hint:
            repl_extra = (
                " 题型疑似 JS/REPL 命令执行：优先生成表达式注入链（console.log/require('child_process').execSync）。"
                "先打 marker 再读 flag，默认同时尝试 /flag、flag、./flag；避免依赖 /bin/bash。"
            )
        nxoff_extra = ""
        if nxoff_hint:
            nxoff_extra = (
                " 目标疑似 NX=off 且已可控 RIP：优先输出不依赖 libc 基址的可执行链"
                "（direct_execve/ret2win/短链），不要先盲打 ret2libc 偏移。"
            )
        return (
            f"请基于已有证据执行 {stage} 阶段并更新本地 exp 文件。"
            f"会话ID: {context.get('session_id','')}。"
            f"二进制: {context.get('binary_path','')}。"
            f"exp 路径: {context.get('exp_path','')}。"
            "优先保证环境同构：若题目目录可识别 loader/libc bundle，先按该对齐运行；"
            "若无 bundle 再回退 process(binary) 语义，并保持两种启动方式可切换。"
            "I/O 读取必须避免吞字节：recvuntil 超时分支不得清空未消费缓冲；"
            "关键泄露禁止用不稳定的 recvuntil+recvline 链式解析。"
            "泄露解析禁止写死长度阈值（例如 >=40）；必须按分隔符解析并兼容 32~64 字节波动。"
            "进入远程全链路前先核对关键偏移三元组（system/pop rdi/binsh）并输出校验日志。"
            "若存在 secret/校验字段，优先按明确终止符读取（例如 b'\\x01\\n'，drop=False）后再解析。"
            "若远端 stage1 频繁 EOF，先做 stage1 成功率基线测试；低于阈值时停止硬撞并请求额外提示。"
            "远端提示流可能不先发固定菜单，需支持主动发送轻量触发（如 n）并重同步。"
            "实现必须按里程碑逐点自检并输出可定位日志：libc leak -> secret leak -> fake meta 生效 -> 可分配到目标记录/栈地址。"
            "最终触发前，必须重新等待关键菜单提示（如 'Note:'）后再发最后一次分配；"
            "若提示缺失则立即停止并打印最近 I/O 窗口，不要盲目继续撞偏移。"
            "shell 成功判定以 marker/flag 输出为准，不要依赖 id 或 /dev/null 权限。"
            f"{repl_extra}"
            f"{nxoff_extra}"
            f"{remote_hint} 并更新 state.session.exp.status='updated'。"
            f"{digest_hint}{extra}"
        )
    raise RuntimeError(f"unknown stage: {stage}")


def _is_truthy_flag(v: Any) -> bool:
    if isinstance(v, bool):
        return bool(v)
    s = str(v or "").strip().lower()
    return s in {"1", "true", "yes", "on"}


def _manual_exp_regen_locked(
    state_doc: Dict[str, Any] | None = None,
    exp_cfg: Dict[str, Any] | None = None,
) -> bool:
    exp_doc: Dict[str, Any] = {}
    if isinstance(exp_cfg, dict):
        exp_doc = exp_cfg
    elif isinstance(state_doc, dict):
        sess = state_doc.get("session", {}) if isinstance(state_doc.get("session", {}), dict) else {}
        exp_doc = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}

    for k in ("manual_lock", "disable_auto_regen", "manual_rewrite", "manual_keep"):
        if _is_truthy_flag(exp_doc.get(k, False)):
            return True
    return _is_truthy_flag(os.environ.get("DIRGE_LOCK_MANUAL_EXP", "0"))


def run_exp_plugin(
    state: Dict[str, Any],
    state_path: str,
    session_id: str,
    metrics: SessionMetrics,
    preserve_existing: bool = False,
) -> Tuple[bool, str]:
    manual_lock = _manual_exp_regen_locked(state_doc=state)
    effective_preserve_existing = bool(preserve_existing or manual_lock)
    exp_rel = str(state.get("session", {}).get("exp", {}).get("path", "")).strip()
    if not exp_rel:
        exp_rel = f"sessions/{session_id}/exp/exp.py"
        state.setdefault("session", {}).setdefault("exp", {})["path"] = exp_rel

    exp_abs = os.path.abspath(os.path.join(ROOT_DIR, exp_rel))
    try:
        info = generate_exp_stub(
            exp_abs,
            state,
            session_id,
            root_dir=ROOT_DIR,
            preserve_existing=effective_preserve_existing,
        )
        exp_status = str(info.get("exp_status", "stub_generated")).strip() or "stub_generated"
        state.setdefault("session", {}).setdefault("exp", {})["status"] = exp_status
        state["session"]["exp"]["manual_lock_active"] = bool(manual_lock)
        state["session"]["exp"]["preserve_existing_effective"] = bool(effective_preserve_existing)
        state["session"]["exp"]["generated_utc"] = info.get("generated_utc", "")
        if info.get("strategy"):
            state["session"]["exp"]["strategy"] = info.get("strategy")
        if info.get("local_path"):
            lp = os.path.relpath(os.path.abspath(str(info.get("local_path"))), ROOT_DIR)
            state["session"]["exp"]["local_path"] = lp
            state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})["exp_local_path"] = lp
        if info.get("remote_path"):
            rp = os.path.relpath(os.path.abspath(str(info.get("remote_path"))), ROOT_DIR)
            state["session"]["exp"]["remote_path"] = rp
            state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})["exp_remote_path"] = rp
        if info.get("plan_report"):
            state["session"]["exp"]["plan_report"] = info.get("plan_report")
            latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
            latest["exp_plan_report"] = str(info.get("plan_report"))
        save_json(state_path, state)
        metrics.exploit_attempts += 1
        return True, ""
    except Exception as e:
        state.setdefault("session", {}).setdefault("exp", {})["status"] = "error"
        state["session"]["exp"]["last_error"] = str(e)
        save_json(state_path, state)
        metrics.exploit_attempts += 1
        return False, str(e)


def run_exp_verify(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    verify_cfg: Dict[str, Any],
    log_path: str,
) -> Tuple[bool, str, str]:
    enabled = bool(verify_cfg.get("enabled", True))
    if not enabled:
        return True, "", ""

    repeat = max(1, int(verify_cfg.get("repeat", 1) or 1))
    min_passes = int(verify_cfg.get("min_passes", repeat) or repeat)
    min_passes = max(1, min(min_passes, repeat))
    verify_mode = str(verify_cfg.get("verify_mode", "auto") or "auto").strip().lower()
    if verify_mode not in {"quick", "full", "auto"}:
        verify_mode = "auto"
    quick_then_full = bool(verify_cfg.get("quick_then_full", True))

    attempts: List[Dict[str, Any]] = []
    pass_count = 0
    run_env_defaults_raw = verify_cfg.get("run_env_defaults", {})
    run_env_defaults: Dict[str, str] = {}
    if isinstance(run_env_defaults_raw, dict):
        for k, v in run_env_defaults_raw.items():
            key = str(k).strip()
            if not key.startswith("PWN_"):
                continue
            val = str(v).strip()
            if not val:
                continue
            run_env_defaults[key] = val
    state_now = load_json(state_path)
    read_len_guess = _pick_read_len_from_state(state_now)
    if read_len_guess > 0 and "PWN_READ_LEN" not in run_env_defaults:
        run_env_defaults["PWN_READ_LEN"] = str(read_len_guess)

    for i in range(1, repeat + 1):
        attempt_report_rel = f"artifacts/reports/exp_verify_{session_id}_{loop_idx:02d}_{i:02d}.json"
        cmd = [
            sys.executable,
            os.path.join(ROOT_DIR, "scripts", "verify_local_exp.py"),
            "--state",
            state_path,
            "--session-id",
            session_id,
            "--loop",
            str(loop_idx),
            "--report",
            attempt_report_rel,
        ]
        if bool(verify_cfg.get("run", False)):
            cmd.append("--run")
            timeout_sec = float(verify_cfg.get("run_timeout_sec", 4.0) or 4.0)
            cmd.extend(["--run-timeout-sec", str(timeout_sec)])
            cmd.extend(["--verify-mode", verify_mode])
            if verify_mode == "auto" and quick_then_full:
                cmd.append("--quick-then-full")
            if bool(verify_cfg.get("run_strict", False)):
                cmd.append("--run-strict")
            if bool(verify_cfg.get("check_success_markers", True)):
                success_markers = verify_cfg.get(
                    "success_markers",
                    ["__PWN_VERIFY_OK__", "flag{", "you pwned me", "remember you forever"],
                )
                if isinstance(success_markers, list):
                    marks = [str(x).strip() for x in success_markers if str(x).strip()]
                else:
                    marks = [x.strip() for x in str(success_markers or "").split(",") if x.strip()]
                if marks:
                    cmd.extend(["--success-markers", ",".join(marks)])
                success_regexes = verify_cfg.get(
                    "success_regexes",
                    [
                        r"flag\{[^\n}]{1,200}\}",
                        r"ctf\{[^\n}]{1,200}\}",
                        r"cyberpeace\{[^\n}]{1,200}\}",
                    ],
                )
                if isinstance(success_regexes, list):
                    regexes = [str(x).strip() for x in success_regexes if str(x).strip()]
                else:
                    regexes = [x.strip() for x in str(success_regexes or "").split(",") if x.strip()]
                if regexes:
                    cmd.extend(["--success-regexes", ",".join(regexes)])
            else:
                cmd.append("--no-success-marker-check")
            if run_env_defaults:
                for k in sorted(run_env_defaults.keys()):
                    cmd.extend(["--env", f"{k}={run_env_defaults[k]}"])
        python_bin = str(verify_cfg.get("python_bin", "")).strip()
        if python_bin:
            cmd.extend(["--python", python_bin])

        p = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True, check=False)
        append_file(log_path, f"\n$ {' '.join(cmd)}\n")
        if p.stdout:
            append_file(log_path, p.stdout)
        if p.stderr:
            append_file(log_path, p.stderr)

        ok = int(p.returncode) == 0
        if ok:
            pass_count += 1
        report_rel = ""
        err = ""
        if p.stdout.strip():
            try:
                obj = json.loads(p.stdout)
                if isinstance(obj, dict):
                    report_rel = str(obj.get("report", "")).strip()
                    err = str(obj.get("error", "")).strip()
            except Exception:
                pass
        if (not err) and p.stderr.strip():
            err = p.stderr.strip()[-200:]
        attempts.append(
            {
                "attempt": i,
                "ok": ok,
                "rc": int(p.returncode),
                "report": report_rel or attempt_report_rel,
                "error": err,
            }
        )

    summary_ok = pass_count >= min_passes
    summary_rel = f"artifacts/reports/exp_verify_{session_id}_{loop_idx:02d}.json"
    summary_abs = os.path.join(ROOT_DIR, summary_rel)
    os.makedirs(os.path.dirname(summary_abs), exist_ok=True)
    with open(summary_abs, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_utc": utc_now(),
                "session_id": session_id,
                "loop": loop_idx,
                "repeat": repeat,
                "min_passes": min_passes,
                "verify_mode": verify_mode,
                "quick_then_full": quick_then_full,
                "pass_count": pass_count,
                "ok": summary_ok,
                "attempts": attempts,
            },
            f,
            ensure_ascii=False,
            indent=2,
        )

    detail = ""
    if not summary_ok:
        detail = f"local exp verify insufficient passes: {pass_count}/{repeat} (<{min_passes})"
        verify_detail = _read_verify_report_detail(summary_rel, max_error_chars=260)
        detail_parts: List[str] = []
        last_err = str(verify_detail.get("last_error", "")).strip()
        if last_err:
            detail_parts.append(f"last_error={_shorten_text(last_err, 180)}")
        run_steps_summary = str(verify_detail.get("run_steps_summary", "")).strip()
        if run_steps_summary:
            detail_parts.append(f"run_steps={_shorten_text(run_steps_summary, 180)}")
        static_findings = verify_detail.get("static_findings", [])
        if isinstance(static_findings, list) and static_findings:
            detail_parts.append(f"static={_shorten_text(str(static_findings[0]), 140)}")
        runtime_findings = verify_detail.get("runtime_findings", [])
        if isinstance(runtime_findings, list) and runtime_findings:
            detail_parts.append(f"runtime={_shorten_text(str(runtime_findings[0]), 140)}")
        stage_evidence = verify_detail.get("stage_evidence", {})
        if isinstance(stage_evidence, dict) and stage_evidence:
            s1_attempts = int(stage_evidence.get("stage1_attempts", 0) or 0)
            s1_eof = int(stage_evidence.get("stage1_eof_attempts", 0) or 0)
            s1_rate = stage_evidence.get("stage1_success_proxy_rate", None)
            last_stage = str(stage_evidence.get("last_stage", "")).strip()
            detail_parts.append(
                f"stage1={max(0, s1_attempts - s1_eof)}/{s1_attempts},eof={s1_eof},rate={s1_rate},last_stage={last_stage or 'N/A'}"
            )
        if detail_parts:
            detail = detail + " | " + "; ".join(detail_parts)
    return summary_ok, summary_rel, detail


def _shorten_text(s: str, max_chars: int) -> str:
    txt = " ".join(str(s or "").split())
    if max_chars <= 0:
        return txt
    if len(txt) <= max_chars:
        return txt
    return txt[: max_chars - 3] + "..."


def _read_verify_report_detail(report_rel: str, max_error_chars: int = 500) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "summary_report": report_rel,
        "summary_ok": None,
        "attempt_count": 0,
        "last_attempt_report": "",
        "last_error": "",
        "run_rc": None,
        "run_timeout": None,
        "run_stdout": "",
        "run_stderr": "",
        "run_steps_summary": "",
        "static_findings": [],
        "runtime_findings": [],
        "stage_evidence": {},
    }
    if not report_rel:
        return out
    summary_abs = os.path.join(ROOT_DIR, report_rel) if not os.path.isabs(report_rel) else report_rel
    if not os.path.exists(summary_abs):
        return out
    try:
        with open(summary_abs, "r", encoding="utf-8") as f:
            summary = json.load(f)
    except Exception:
        return out
    if not isinstance(summary, dict):
        return out
    out["summary_ok"] = bool(summary.get("ok", False))
    attempts = summary.get("attempts", []) if isinstance(summary.get("attempts", []), list) else []
    out["attempt_count"] = len(attempts)
    if not attempts:
        return out
    last = attempts[-1] if isinstance(attempts[-1], dict) else {}
    if not isinstance(last, dict):
        return out
    out["last_attempt_report"] = str(last.get("report", "")).strip()
    out["last_error"] = _shorten_text(str(last.get("error", "")).strip(), max_error_chars)

    attempt_report_rel = out["last_attempt_report"]
    if not attempt_report_rel:
        return out
    attempt_abs = os.path.join(ROOT_DIR, attempt_report_rel) if not os.path.isabs(attempt_report_rel) else attempt_report_rel
    if not os.path.exists(attempt_abs):
        return out
    try:
        with open(attempt_abs, "r", encoding="utf-8") as f:
            detail = json.load(f)
    except Exception:
        return out
    if not isinstance(detail, dict):
        return out
    run = detail.get("run", {}) if isinstance(detail.get("run", {}), dict) else {}
    pyc = detail.get("py_compile", {}) if isinstance(detail.get("py_compile", {}), dict) else {}
    run_stderr = _shorten_text(str(run.get("stderr_tail", "")).strip(), max_error_chars)
    run_stdout = _shorten_text(str(run.get("stdout_tail", "")).strip(), max_error_chars)
    out["run_stderr"] = run_stderr
    out["run_stdout"] = run_stdout
    py_stderr = _shorten_text(str(pyc.get("stderr", "")).strip(), max_error_chars)
    if run_stderr:
        out["last_error"] = run_stderr
    elif run_stdout:
        out["last_error"] = run_stdout
    elif py_stderr:
        out["last_error"] = py_stderr
    sf = detail.get("static_findings", [])
    if isinstance(sf, list):
        out["static_findings"] = [
            _shorten_text(str(x).strip(), max_error_chars)
            for x in sf
            if str(x).strip()
        ][:4]

    runtime_findings: List[str] = []
    low_stdout = run_stdout.lower()
    low_stderr = run_stderr.lower()
    low_merged = (run_stdout + "\n" + run_stderr).lower()
    if "failed to detect libc leak" in low_stdout:
        runtime_findings.append("runtime leak detection unstable (failed to detect libc leak)")
    js_exec_tokens = ("javascript", "node", "repl", "child_process", "execsync", "vm2", "require(")
    js_hits = sum(1 for t in js_exec_tokens if t in (low_stdout + "\n" + run_stderr.lower()))
    if js_hits >= 2:
        runtime_findings.append(
            "runtime hints look like JS/REPL command-exec target; avoid stack-overflow fuzz_probe template"
        )
    state_machine_tokens = (
        "state machine",
        "battle",
        "fight",
        "round",
        "hp",
        "remember you forever",
    )
    state_hits = sum(1 for t in state_machine_tokens if t in low_stdout)
    if state_hits >= 2 and (not any(x in low_stdout for x in ("two connection", "dual", "race"))):
        runtime_findings.append(
            "interactive/state-machine signals detected; parallel-check same-account dual-connection race branch early"
        )
    leak_vals = re.findall(r"\bleak\s+[a-z0-9_]+=0x([0-9a-f]+)", low_stdout)
    if (("reconnect" in low_stdout) or ("remote-retry" in low_stdout) or ("retry" in low_stdout)) and (len(leak_vals) >= 2):
        runtime_findings.append("multiple leaks observed with reconnect/retry; avoid cross-connection libc-base mixing under ASLR")
    if any(v.endswith(("0a", "0d")) for v in leak_vals):
        runtime_findings.append("leak candidate ended with 0a/0d; likely newline/control-byte contamination")
    if ("\x1b[" in run_stdout) or ("\u001b[" in run_stdout):
        runtime_findings.append("runtime output contains ANSI escape sequences; leak parser should sanitize control bytes")
    if ("/bin/bash" in low_merged) and ("not found" in low_merged):
        runtime_findings.append("remote shell path mismatch (/bin/bash not found); prefer /bin/sh-compatible chain")
    if (("scanf(\"%4s" in low_merged) or ("scanf('%4s" in low_merged)) and ("read(0," in low_merged):
        runtime_findings.append("scanf/read mixed input stream detected; enable PWN_INPUT_ALIGN_MODE=auto (or scanf4_read)")
    if "broken pipe" in low_merged:
        runtime_findings.append("broken pipe observed; likely input stream desync, try staged send cadence/input alignment")
    if ("stack smashing detected" in low_merged) or ("*** stack smashing detected ***" in low_merged):
        runtime_findings.append("stack smashing detected; re-check payload length/canary boundary and keep post-exploit commands short")
    menu_noise_hits = len(re.findall(r"(?:choose|choice|menu|option|invalid option|wrong choice)", low_merged))
    if menu_noise_hits >= 6:
        runtime_findings.append("runtime output menu-noise high; filter non-menu lines before judging command execution")
    if (
        (
            ("candidate" in low_stdout)
            or ("try system_off" in low_stdout)
            or ("bruteforce" in low_stdout)
            or ("blind guess" in low_stdout)
        )
        and ("dt_hash" not in low_stdout)
        and ("gnu_hash" not in low_stdout)
        and ("dynelf" not in low_stdout)
    ):
        runtime_findings.append("runtime offset search looks brute-force heavy; prefer same-connection evidence or ELF dynamic table proof")

    stage_ev = run.get("stage_evidence", {}) if isinstance(run.get("stage_evidence", {}), dict) else {}
    if stage_ev:
        out["stage_evidence"] = {
            "stage1_attempts": int(stage_ev.get("stage1_attempts", 0) or 0),
            "stage1_eof_attempts": int(stage_ev.get("stage1_eof_attempts", 0) or 0),
            "stage1_success_proxy_attempts": int(stage_ev.get("stage1_success_proxy_attempts", 0) or 0),
            "stage1_success_proxy_rate": stage_ev.get("stage1_success_proxy_rate", None),
            "stage1_post_recv_raw_len_max": int(stage_ev.get("stage1_post_recv_raw_len_max", 0) or 0),
            "invalid_option_count": int(stage_ev.get("invalid_option_count", 0) or 0),
            "wrong_choice_count": int(stage_ev.get("wrong_choice_count", 0) or 0),
            "menu_prompt_hits": int(stage_ev.get("menu_prompt_hits", 0) or 0),
            "last_stage": str(stage_ev.get("last_stage", "")).strip(),
            "leak_values_hex_tail": (
                stage_ev.get("leak_values_hex_tail", [])
                if isinstance(stage_ev.get("leak_values_hex_tail", []), list)
                else []
            ),
        }
        s1_attempts = int(stage_ev.get("stage1_attempts", 0) or 0)
        s1_eof = int(stage_ev.get("stage1_eof_attempts", 0) or 0)
        s1_invalid = int(stage_ev.get("invalid_option_count", 0) or 0)
        s1_wrong = int(stage_ev.get("wrong_choice_count", 0) or 0)
        s1_rate_raw = stage_ev.get("stage1_success_proxy_rate", None)
        try:
            s1_rate = float(s1_rate_raw) if s1_rate_raw is not None else None
        except Exception:
            s1_rate = None
        if s1_attempts >= 2 and s1_eof > 0:
            runtime_findings.append(
                f"remote stage1 EOF observed in {s1_eof}/{s1_attempts} attempts; prioritize stage1 baseline stabilization"
            )
        if s1_attempts >= 3 and s1_rate is not None and s1_rate < 0.35:
            runtime_findings.append(
                f"remote stage1 success proxy rate low ({s1_rate:.2f}); pause full-chain retries and request hint earlier"
            )
        if (s1_invalid + s1_wrong) > 0:
            runtime_findings.append(
                f"menu sync drift signs observed (invalid_option={s1_invalid}, wrong_choice={s1_wrong}); validate recvuntil/sendlineafter boundaries"
            )
    if runtime_findings:
        out["runtime_findings"] = list(dict.fromkeys(runtime_findings))[:4]

    out["run_rc"] = run.get("rc", None)
    out["run_timeout"] = run.get("timeout", None)
    run_steps = run.get("run_steps", []) if isinstance(run.get("run_steps", []), list) else []
    if run_steps:
        step_lines: List[str] = []
        for step in run_steps[:4]:
            if not isinstance(step, dict):
                continue
            mode = str(step.get("verify_mode", "")).strip() or "unknown"
            rc = step.get("rc", None)
            timeout = bool(step.get("timeout", False))
            marker_hit = step.get("marker_hit", None)
            regex_hit = step.get("regex_hit", None)
            ok = bool(step.get("ok", False))
            step_lines.append(
                f"{mode}:ok={1 if ok else 0},rc={rc},timeout={1 if timeout else 0},marker={marker_hit},regex={regex_hit}"
            )
        out["run_steps_summary"] = "; ".join(step_lines)
    return out


def classify_verify_autofix_block_reason(detail: Dict[str, Any], force_until_success: bool = False) -> str:
    msg = str(detail.get("last_error", "")).strip().lower()
    run_rc = detail.get("run_rc", None)
    run_timeout = bool(detail.get("run_timeout", False))
    run_steps_summary = str(detail.get("run_steps_summary", "")).strip()
    static_findings = detail.get("static_findings", [])
    runtime_findings = detail.get("runtime_findings", [])
    has_static_findings = isinstance(static_findings, list) and any(str(x).strip() for x in static_findings)
    has_runtime_findings = isinstance(runtime_findings, list) and any(str(x).strip() for x in runtime_findings)
    runtime_join = ""
    if isinstance(runtime_findings, list):
        runtime_join = " ".join(str(x).strip().lower() for x in runtime_findings if str(x).strip())
    low_steps = run_steps_summary.lower()
    if "weak exploit closure" in msg:
        return "weak exploit closure"
    if "menu sync drift" in msg:
        return "menu sync drift"
    if "menu sync baseline" in msg:
        return "menu sync drift"
    if runtime_join and (
        ("menu sync drift signs observed" in runtime_join)
        or ("menu sync drift suspected" in runtime_join)
    ):
        return "menu sync drift"
    if runtime_join and ("js/repl command-exec target" in runtime_join):
        return "js repl command-exec target"
    if runtime_join and ("scanf/read mixed input stream" in runtime_join):
        return "scanf/read input alignment required"
    if runtime_join and ("remote shell path mismatch" in runtime_join):
        return "remote shell path mismatch"
    if runtime_join and (
        ("remote stage1 success proxy rate low" in runtime_join)
        or ("remote stage1 eof observed" in runtime_join)
    ):
        return "remote stage1 unstable"
    if run_timeout or (run_rc == 124) or ("rc=124" in low_steps) or ("timeout=1" in low_steps):
        return "runtime timed out"
    if (
        (not force_until_success)
        and (not msg)
        and (run_rc == 1)
        and (not run_timeout)
        and (not has_static_findings)
        and (not has_runtime_findings)
        and (not run_steps_summary)
    ):
        # 仅有“运行失败”但无可操作错误信息时，Codex 修复命中率低且成本高，直接快速失败。
        return "no actionable runtime error"
    if not msg:
        return ""
    checks = [
        ("out of pty devices", "runtime pty exhausted"),
        ("no suitable python found", "runtime python missing"),
        ("no module named 'pwn'", "pwntools missing in runtime python"),
        ("operation not permitted", "runtime network/permission blocked"),
        ("name or service not known", "dns resolve failed"),
        ("temporary failure in name resolution", "dns resolve failed"),
        ("could not resolve hostname", "dns resolve failed"),
        ("connection refused", "remote refused"),
        ("/bin/bash: not found", "remote shell path mismatch"),
        ("bin/bash: not found", "remote shell path mismatch"),
        ("timed out", "runtime timed out"),
    ]
    for needle, reason in checks:
        if needle in msg:
            return reason
    return ""


def _read_exp_source_snippet(exp_path: str, max_chars: int = 3200) -> str:
    rel = str(exp_path or "").strip()
    if (not rel) or max_chars <= 0:
        return ""
    abs_path = rel if os.path.isabs(rel) else os.path.join(ROOT_DIR, rel)
    if not os.path.isfile(abs_path):
        return ""
    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception:
        return ""
    if not text:
        return ""
    limit = max(240, int(max_chars))
    if len(text) <= limit:
        return text
    head = max(120, limit // 2)
    tail = max(120, limit - head)
    return text[:head] + "\n# ... truncated ...\n" + text[-tail:]


def evaluate_terminal_exploit_precheck(
    state: Dict[str, Any],
    *,
    stage: str,
    terminal_stage: str,
    terminal_unsolved_streak: int,
    enabled: bool,
    terminal_stage_only: bool,
    min_unsolved_loops: int,
    weak_strategies: Set[str],
) -> Tuple[str, Dict[str, Any]]:
    if not enabled:
        return "", {}
    if exploit_stage_level(stage) < 0:
        return "", {}
    if terminal_stage_only and terminal_stage and stage != terminal_stage:
        return "", {}
    if max(0, int(min_unsolved_loops or 0)) > 0 and int(terminal_unsolved_streak or 0) < int(min_unsolved_loops or 0):
        return "", {}

    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    strategy = str(exp.get("strategy", "")).strip().lower()
    if (not strategy) or (strategy not in weak_strategies):
        return "", {}

    caps = state.get("capabilities", {}) if isinstance(state.get("capabilities", {}), dict) else {}
    has_leak = str(caps.get("has_leak", "unknown")).strip().lower()
    write_primitive = str(caps.get("write_primitive", "unknown")).strip().lower()
    ret2win_verified = bool(caps.get("ret2win_path_verified", False))
    system_observed = bool(caps.get("system_call_observed", False))
    control_rip = bool(caps.get("control_rip", False))
    offset_to_rip = int(caps.get("offset_to_rip", 0) or 0)
    protections = state.get("protections", {}) if isinstance(state.get("protections", {}), dict) else {}
    nx_raw = protections.get("nx", None)
    nx_disabled = (nx_raw is False) or (str(nx_raw or "").strip().lower() in {"0", "false", "off", "disabled", "no"})

    closure = (
        has_leak in {"possible", "yes"}
        or write_primitive in {"possible", "yes"}
        or ret2win_verified
        or system_observed
        or (nx_disabled and control_rip and offset_to_rip > 0)
    )
    detail = {
        "strategy": strategy,
        "terminal_unsolved_streak": int(terminal_unsolved_streak or 0),
        "has_leak": has_leak,
        "write_primitive": write_primitive,
        "ret2win_path_verified": ret2win_verified,
        "system_call_observed": system_observed,
        "control_rip": control_rip,
        "offset_to_rip": offset_to_rip,
        "nx": nx_raw,
        "nx_off_libc_free_path": bool(nx_disabled and control_rip and offset_to_rip > 0),
        "closure_signals_present": bool(closure),
    }
    if closure:
        return "", detail

    reason = (
        f"weak exploit closure: strategy={strategy}, has_leak={has_leak}, "
        f"write_primitive={write_primitive}, ret2win_path_verified={int(ret2win_verified)}, "
        f"system_call_observed={int(system_observed)}"
    )
    return reason, detail


def write_exploit_precheck_report(
    *,
    session_id: str,
    loop_idx: int,
    stage: str,
    reason: str,
    detail: Dict[str, Any],
) -> str:
    rel = f"artifacts/reports/exploit_precheck_{session_id}_{loop_idx:02d}_{stage}.json"
    out = os.path.join(ROOT_DIR, rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": int(loop_idx),
        "stage": str(stage).strip(),
        "ok": False,
        "last_error": str(reason or "").strip(),
        "run_rc": 68,
        "run_timeout": False,
        "run_steps_summary": "",
        "static_findings": [],
        "runtime_findings": ["weak exploit closure precheck triggered"],
        "detail": detail if isinstance(detail, dict) else {},
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return rel


def _is_timeout_like_error(msg: str) -> bool:
    low = str(msg or "").strip().lower()
    if not low:
        return False
    needles = (
        "return code=124",
        " rc=124",
        "timeout",
        "timed out",
        "deadline exceeded",
        "transport closed",
        "channel closed",
        "mcp handshaking",
        "mcp initialize response",
        "mcp startup: no servers",
    )
    return any(x in low for x in needles)


def _is_analysis_transient_error(msg: str) -> bool:
    low = str(msg or "").strip().lower()
    if not low:
        return False
    needles = (
        "analysis incomplete",
        "analysis_complete=false",
        "transport closed",
        "closedexception",
        "file is closed",
        "unable to lock project",
        "lockexception",
    )
    return any(x in low for x in needles)


def build_exploit_autofix_prompt(
    *,
    session_id: str,
    stage: str,
    binary_path: str,
    exp_path: str,
    verify_report: str,
    verify_detail: Dict[str, Any],
    exp_source_snippet: str = "",
) -> str:
    last_error = _shorten_text(str(verify_detail.get("last_error", "")).strip(), 600)
    run_stdout = _shorten_text(str(verify_detail.get("run_stdout", "")).strip(), 600)
    run_steps_summary = _shorten_text(str(verify_detail.get("run_steps_summary", "")).strip(), 320)
    run_rc = verify_detail.get("run_rc", None)
    run_timeout = verify_detail.get("run_timeout", None)
    static_findings = verify_detail.get("static_findings", [])
    if isinstance(static_findings, list):
        static_findings = [str(x).strip() for x in static_findings if str(x).strip()]
    else:
        static_findings = []
    runtime_findings = verify_detail.get("runtime_findings", [])
    if isinstance(runtime_findings, list):
        runtime_findings = [str(x).strip() for x in runtime_findings if str(x).strip()]
    else:
        runtime_findings = []
    static_hint = "；".join(static_findings[:3]) if static_findings else "N/A"
    runtime_hint = "；".join(runtime_findings[:3]) if runtime_findings else "N/A"
    retry_hint = ""
    low_err = f"{last_error}\n{run_stdout}".lower()
    if "remote-retry" in low_err:
        retry_hint = "检测到 remote-retry 失败；优先修复远端同步/泄露解析，不要只增大重试次数。"
    snippet_hint = ""
    if exp_source_snippet:
        snippet_hint = (
            "以下是 exp.py 摘要（已截断）；优先直接基于该内容修改，避免先遍历仓库或读取整文件：\n"
            "```python\n"
            f"{exp_source_snippet}\n"
            "```"
        )
    return (
        f"执行 {stage} 自动修复：只修改 {exp_path}，目标是通过本地 verify_local_exp --run。"
        "禁止仓库遍历/环境排查命令（ls/rg/find/sed/cat/awk/head/tail/ps/kill/history）。"
        "禁止执行 python/bash/zsh 读文件命令；优先直接基于已给摘要做最小补丁。"
        "禁止调用 session_api.py stop 或写 stop.requested.json。"
        "只做最小修改并保持远程参数化能力（PWN_REMOTE_HOST/PWN_REMOTE_PORT）。"
        "修复优先级：先环境同构（本地启动语义与官方一致），再修 I/O 读取完整性，再修末段偏移。"
        "先做最小可证据闭环：先证明可写 GOT（如 atoi@got）并可控调用，再进入 libc/system 偏移定位。"
        "关键读取要求：recvuntil 超时不得清空内部缓冲；secret 优先按明确终止符读取并保留终止符。"
        "进入远程全链路前先核对关键偏移三元组（system/pop rdi/binsh）；任一不确定时先停在校验步骤。"
        "泄露解析禁止写死阈值（如 >=40）；必须按实际分隔符解析并兼容 32~64 长度波动。"
        "L3 脚本必须采用二进制安全输出处理（decode errors=ignore），并对混合输出做泄露候选提取（hex 文本+原始字节，页对齐与地址区间过滤）。"
        "所有 libc base/system 计算必须来自同一连接的泄露，禁止跨连接混算（ASLR）。"
        "若需要写 atoi@got（32-bit），写入值必须按有符号 int32 语义转换后再发送十进制。"
        "偏移定位优先同连接多点泄露或 ELF 动态表证据（如 DT_HASH/GNU_HASH），不要做大规模盲猜。"
        "若 stage1 在远端成功率长期偏低（尤其频繁 EOF），先做 stage1 成功率基线测试，低于阈值立即暂停并请求提示。"
        "若题目是交互战斗/状态机，前 10 分钟内必须并行验证“同账号双连接竞态”分支，不要只押单连接路径。"
        "远程利用至少保留双路径模板：A) 常规泄露->ret2libc；B) GOT 重定向（如 puts@got->gets@got->system('/bin/sh')）。"
        "若存在隐藏分支（如 0x2333），每次发送前后都要按菜单边界 recv 同步并保留短延时，避免错位成 Invalid option。"
        "远端提示流不稳定时，允许主动发送轻量触发（如 n\\n）后再同步，不要假设先出现固定提示。"
        "shell 成功判据以 marker/flag 输出为准，不要依赖 id 命令或 /dev/null 可用性。"
        "若题型是格式化字符串（如 printf(user_input)），优先验证参数位与目标写入（如 %10$n）并以分支命中 marker 判定成功。"
        f"SID={session_id} BIN={binary_path}。"
        f"verify_report={verify_report} run_rc={run_rc} timeout={run_timeout}。"
        f"静态风险提示: {static_hint}。运行风险提示: {runtime_hint}。"
        f"run_steps: {run_steps_summary if run_steps_summary else 'N/A'}。"
        f"run_stdout_tail: {run_stdout if run_stdout else 'N/A'}。"
        f"最近失败信息: {last_error if last_error else 'N/A'}。"
        f"{retry_hint}"
        f"{snippet_hint}"
    )


def write_clusters(state: Dict[str, Any], session_id: str) -> Tuple[str, List[Dict[str, Any]]]:
    evid = state.get("dynamic_evidence", {}).get("evidence", [])
    if not isinstance(evid, list):
        evid = []
    clusters = cluster_evidence([x for x in evid if isinstance(x, dict)])

    out_rel = f"artifacts/reports/{session_id}_crash_clusters.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump({"updated_utc": utc_now(), "clusters": clusters}, f, ensure_ascii=False, indent=2)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["gdb_clusters"] = out_rel
    dynamic = state.setdefault("dynamic_evidence", {})
    dynamic["clusters"] = clusters
    if clusters:
        top = clusters[0]
        summary = state.setdefault("summary", {})
        summary["current_best_guess"] = (
            f"top_cluster signal={top.get('signal','')} location={top.get('location','')} count={top.get('count',0)}"
        )
    return out_rel, clusters


def refresh_global_kpi(global_path: str, current_metrics: SessionMetrics) -> None:
    _refresh_global_kpi_impl(
        root_dir=ROOT_DIR,
        global_path=global_path,
        current_metrics=current_metrics,
        metrics_from_dict_fn=SessionMetrics.from_dict,
        write_global_kpi_fn=write_global_kpi,
    )


def write_realtime_kpi_snapshot(
    *,
    enabled: bool,
    metrics: SessionMetrics,
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
) -> None:
    _write_realtime_kpi_snapshot_impl(
        enabled=enabled,
        metrics=metrics,
        per_session_abs=per_session_abs,
        global_kpi_abs=global_kpi_abs,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        started_utc=started_utc,
        ended_utc=ended_utc,
        elapsed_sec=elapsed_sec,
        ok=ok,
        rc=rc,
        failure_category=failure_category,
        tx_meta_rel=tx_meta_rel,
        log_rel=log_rel,
        refresh_global_kpi_fn=refresh_global_kpi,
        load_json_fn=load_json,
        repo_rel_fn=repo_rel,
        utc_now_fn=utc_now,
    )


def merge_external_metric_counters(metrics: SessionMetrics, metrics_path: str) -> None:
    if not os.path.exists(metrics_path):
        return
    try:
        with open(metrics_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return
    if not isinstance(raw, dict):
        return
    for key in ["self_stop_blocked", "remote_connect_attempts", "autofix_rounds_total"]:
        try:
            v = int(raw.get(key, 0) or 0)
        except Exception:
            v = 0
        if v <= 0:
            continue
        cur = int(getattr(metrics, key, 0) or 0)
        if v > cur:
            setattr(metrics, key, v)


def sync_meta_from_state(session_id: str, state: Dict[str, Any], report_rel: str = "", metrics_rel: str = "") -> None:
    _sync_meta_from_state_impl(
        ROOT_DIR,
        session_id,
        state,
        report_rel=report_rel,
        metrics_rel=metrics_rel,
        utc_now_fn=utc_now,
    )


def sync_state_meta_cli(session_id: str, state_path: str = DEFAULT_STATE, report_rel: str = "", metrics_rel: str = "") -> None:
    _sync_state_meta_cli_impl(
        ROOT_DIR,
        session_id,
        state_path=state_path,
        report_rel=report_rel,
        metrics_rel=metrics_rel,
    )


def maybe_prepare_remote_prompt(
    *,
    state: Dict[str, Any],
    state_path: str,
    session_id: str,
    remote_prompt_cfg: Dict[str, Any],
    enable_exploit: bool,
    allow_remote_exp: bool,
    stage_results: List[Dict[str, Any]],
    notes: List[str],
) -> str:
    if not bool(remote_prompt_cfg.get("enabled", True)):
        return ""
    if not enable_exploit:
        return ""
    if not allow_remote_exp:
        return ""
    if not any(exploit_stage_level(str(x.get("stage", ""))) >= 0 for x in stage_results):
        return ""

    exp = state.get("session", {}).get("exp", {}) if isinstance(state.get("session", {}).get("exp", {}), dict) else {}
    local_verified = bool(exp.get("local_verify_passed", False))
    if (not local_verified) and (not bool(remote_prompt_cfg.get("ask_when_local_verify_failed", False))):
        return ""

    control_dir = os.path.join(ROOT_DIR, "sessions", session_id, "control")
    os.makedirs(control_dir, exist_ok=True)
    req_rel = f"sessions/{session_id}/control/remote.requested.json"
    req_abs = os.path.join(ROOT_DIR, req_rel)
    generated = utc_now()

    req_doc = {
        "generated_utc": generated,
        "session_id": session_id,
        "status": "pending",
        "message": "本地 exp 已完成验证。是否连接远程？如果同意，请填写 host 与 port。",
        "required_fields": ["host", "port"],
        "defaults": {"host": "", "port": 0},
        "local_verify_passed": local_verified,
        "exp_path": str(exp.get("path", "")).strip(),
    }
    with open(req_abs, "w", encoding="utf-8") as f:
        json.dump(req_doc, f, ensure_ascii=False, indent=2)

    sess = state.setdefault("session", {})
    remote = sess.setdefault("remote", {})
    remote["ask_pending"] = True
    remote["request_file"] = req_rel
    remote["requested_utc"] = generated
    remote.setdefault("answer", "")
    remote.setdefault("answered_utc", "")
    remote.setdefault("target", {"host": "", "port": 0})
    remote.setdefault("last_preflight_report", "")
    remote.setdefault("last_remote_report", "")
    remote.setdefault("last_remote_ok", False)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["remote_prompt_request"] = req_rel
    save_json(state_path, state)
    notes.append("已生成远程连接询问（pending）")
    return req_rel


def _read_seed_from_path(path: str, max_bytes: int) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""


def prepare_mutation_inputs(
    state: Dict[str, Any],
    session_id: str,
    loop_idx: int,
    mutation_cfg: Dict[str, Any],
) -> Tuple[str, List[Dict[str, Any]]]:
    enabled = bool(mutation_cfg.get("enabled", True))
    if not enabled:
        return "", []

    max_total = int(mutation_cfg.get("max_total_inputs", 16) or 16)
    max_len = int(mutation_cfg.get("max_len", 512) or 512)
    max_seed_files = int(mutation_cfg.get("max_seed_files", 4) or 4)
    seed_strings = mutation_cfg.get("seed_strings", ["AAAA", "%p%p%p", "A" * 64, "A" * 128])
    if not isinstance(seed_strings, list):
        seed_strings = ["AAAA", "%p%p%p", "A" * 64]

    dynamic = state.setdefault("dynamic_evidence", {})
    inputs = dynamic.setdefault("inputs", [])
    if not isinstance(inputs, list):
        inputs = []
        dynamic["inputs"] = inputs

    seeds: List[bytes] = []
    for s in seed_strings:
        if isinstance(s, str) and s:
            seeds.append(s.encode("latin-1", errors="ignore"))

    hist_paths: List[str] = []
    for item in reversed(inputs):
        if not isinstance(item, dict):
            continue
        p = str(item.get("path", "")).strip()
        if p:
            hist_paths.append(p)
        if len(hist_paths) >= max_seed_files:
            break
    for p in hist_paths:
        ap = os.path.join(ROOT_DIR, p) if not os.path.isabs(p) else p
        b = _read_seed_from_path(ap, max_len)
        if b:
            seeds.append(b)

    if not seeds:
        seeds = [b"A" * 64]

    corpus: List[bytes] = []
    seen = set()
    per_seed_limit = max(4, max_total // max(1, len(seeds)))
    for seed in seeds:
        muts = generate_mutations(seed, max_len=max_len, limit=per_seed_limit)
        for m in muts:
            if m in seen:
                continue
            seen.add(m)
            corpus.append(m)
            if len(corpus) >= max_total:
                break
        if len(corpus) >= max_total:
            break

    if not corpus:
        return "", []

    prefix_rel = f"artifacts/inputs/{session_id}_l{loop_idx:02d}_mut"
    prefix_abs = os.path.join(ROOT_DIR, prefix_rel)
    os.makedirs(os.path.dirname(prefix_abs), exist_ok=True)
    files_abs = write_mutations(prefix_abs, corpus)

    existing_ids = set()
    for item in inputs:
        if isinstance(item, dict):
            iid = str(item.get("input_id", "")).strip()
            if iid:
                existing_ids.add(iid)
    next_index = len(existing_ids) + 1

    new_items: List[Dict[str, Any]] = []
    existing_paths = {str(x.get("path", "")).strip() for x in inputs if isinstance(x, dict)}
    for p_abs in files_abs:
        p_rel = repo_rel(p_abs)
        if p_rel in existing_paths:
            continue
        input_id = f"inp_{session_id}_{next_index:04d}"
        while input_id in existing_ids:
            next_index += 1
            input_id = f"inp_{session_id}_{next_index:04d}"
        existing_ids.add(input_id)
        next_index += 1

        item = {
            "input_id": input_id,
            "path": p_rel,
            "origin": "mutation",
            "loop": loop_idx,
            "stage": "gdb_evidence",
            "size": os.path.getsize(p_abs),
            "created_utc": utc_now(),
        }
        inputs.append(item)
        new_items.append(item)

    if not new_items:
        return "", []

    manifest_rel = f"artifacts/inputs/{session_id}_l{loop_idx:02d}_mutations.json"
    manifest_abs = os.path.join(ROOT_DIR, manifest_rel)
    manifest = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": loop_idx,
        "count": len(new_items),
        "inputs": new_items,
    }
    with open(manifest_abs, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["gdb_mutation_manifest"] = manifest_rel
    return manifest_rel, new_items


def write_loop_decision_report(
    session_id: str,
    loop_idx: int,
    plan: List[str],
    notes: List[str],
    active_hypothesis_ids: List[str],
    mutation_manifest: str = "",
) -> str:
    out_rel = f"artifacts/reports/decision_{session_id}_{loop_idx:02d}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    doc = {
        "generated_utc": utc_now(),
        "session_id": session_id,
        "loop": loop_idx,
        "stage_plan": plan,
        "notes": notes,
        "active_hypothesis_ids": active_hypothesis_ids,
        "mutation_manifest": mutation_manifest,
    }
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return out_rel


def apply_objective_state(state: Dict[str, Any], eval_obj: Dict[str, Any], report_rel: str = "") -> None:
    progress = state.setdefault("progress", {})
    obj = progress.setdefault("objectives", {})
    obj["score"] = int(eval_obj.get("score", 0) or 0)
    obj["target_achieved"] = bool(eval_obj.get("target_achieved", False))
    obj["competition_target_achieved"] = bool(eval_obj.get("competition_target_achieved", False))
    obj["competition_reasons"] = (
        list(eval_obj.get("competition_reasons", []))
        if isinstance(eval_obj.get("competition_reasons", []), list)
        else []
    )
    obj["required_stages"] = list(eval_obj.get("required_stages", [])) if isinstance(eval_obj.get("required_stages", []), list) else []
    obj["missing_stages"] = list(eval_obj.get("missing_stages", [])) if isinstance(eval_obj.get("missing_stages", []), list) else []
    obj["blockers"] = list(eval_obj.get("blockers", [])) if isinstance(eval_obj.get("blockers", []), list) else []
    obj["last_eval_utc"] = str(eval_obj.get("generated_utc", utc_now()))
    if report_rel:
        obj["last_objective_report"] = report_rel


def tx_prefix(session_id: str, loop_idx: int, stage: str) -> str:
    return _tx_prefix_impl(ROOT_DIR, session_id, loop_idx, stage)


def write_tx_snapshot(session_id: str, loop_idx: int, stage: str, kind: str, state: Dict[str, Any]) -> str:
    return _write_tx_snapshot_impl(
        root_dir=ROOT_DIR,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        kind=kind,
        state=state,
        repo_rel_fn=repo_rel,
    )


def write_tx_meta(session_id: str, loop_idx: int, stage: str, data: Dict[str, Any]) -> str:
    return _write_tx_meta_impl(
        root_dir=ROOT_DIR,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        data=data,
        repo_rel_fn=repo_rel,
    )


def next_loop_index(session_id: str) -> int:
    return _next_loop_index_impl(root_dir=ROOT_DIR, session_id=session_id)


def build_failure_context(
    *,
    stage: str,
    rc: int,
    err: str,
    failure_category: str,
    attempt_records: List[Dict[str, Any]],
    log_rel: str,
    exp_verify_report: str,
) -> Dict[str, Any]:
    return _build_failure_context_impl(
        root_dir=ROOT_DIR,
        stage=stage,
        rc=rc,
        err=err,
        failure_category=failure_category,
        attempt_records=attempt_records,
        log_rel=log_rel,
        exp_verify_report=exp_verify_report,
        tail_text_file_fn=tail_text_file,
        detect_stage_log_signature_fn=detect_stage_log_signature,
        read_verify_report_detail_fn=_read_verify_report_detail,
        shorten_text_fn=_shorten_text,
        utc_now_fn=utc_now,
    )


def write_failure_report(
    session_id: str,
    loop_idx: int,
    stage: str,
    reason: str,
    tx_meta_rel: str,
    log_rel: str,
    context: Dict[str, Any] | None = None,
) -> str:
    return _write_failure_report_impl(
        root_dir=ROOT_DIR,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        reason=reason,
        tx_meta_rel=tx_meta_rel,
        log_rel=log_rel,
        context=context,
        shorten_text_fn=_shorten_text,
        utc_now_fn=utc_now,
    )


def write_cost_fuse_report(
    *,
    session_id: str,
    max_codex_calls: int,
    max_prompt_chars: int,
    max_wall_time_sec: float,
    max_autofix_rounds: int,
    metrics: SessionMetrics,
    triggered: bool,
    reason: str,
) -> str:
    return _write_cost_fuse_report_impl(
        ROOT_DIR,
        session_id,
        max_codex_calls,
        max_prompt_chars,
        max_wall_time_sec,
        max_autofix_rounds,
        metrics,
        triggered,
        reason,
        utc_now_fn=utc_now,
    )


def write_exploit_rewrite_report(
    *,
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
    metrics: SessionMetrics,
) -> str:
    return _write_exploit_rewrite_report_impl(
        ROOT_DIR,
        session_id,
        terminal_stage,
        reason,
        solved,
        loops_executed,
        base_max_loops,
        extra_loops_budget,
        rewrite_elapsed_sec,
        same_error_streak,
        non_actionable_verify_streak,
        last_error,
        last_verify_report,
        exp_path,
        stage_results,
        metrics,
        shorten_text_fn=_shorten_text,
        utc_now_fn=utc_now,
    )


def write_acceptance_report(
    *,
    session_id: str,
    metrics: SessionMetrics,
    final_state: Dict[str, Any],
    acceptance_cfg: Dict[str, Any],
    terminal_stage: str,
) -> Tuple[str, bool]:
    return _write_acceptance_report_impl(
        ROOT_DIR,
        session_id,
        metrics,
        final_state,
        acceptance_cfg,
        terminal_stage,
        exploit_stage_level_fn=exploit_stage_level,
        utc_now_fn=utc_now,
    )


def write_summary_report(path: str, session_id: str, stage_results: List[Dict[str, Any]], state: Dict[str, Any], notes: List[str]) -> None:
    _write_summary_report_impl(path, session_id, stage_results, state, notes, utc_now_fn=utc_now)


def write_timeline_report(
    session_id: str, stage_results: List[Dict[str, Any]], metrics: SessionMetrics, state: Dict[str, Any] | None = None
) -> str:
    return _write_timeline_report_impl(
        ROOT_DIR,
        session_id,
        stage_results,
        metrics,
        state=state,
        exploit_stage_level_fn=exploit_stage_level,
        utc_now_fn=utc_now,
    )


def write_timing_report(
    session_id: str, stage_results: List[Dict[str, Any]], metrics: SessionMetrics, state: Dict[str, Any] | None = None
) -> str:
    return _write_timing_report_impl(
        ROOT_DIR,
        session_id,
        stage_results,
        metrics,
        state=state,
        exploit_stage_level_fn=exploit_stage_level,
        utc_now_fn=utc_now,
    )


def main() -> int:
    ap = argparse.ArgumentParser(description="Run automated MCP-first session workflow")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--budget", default=DEFAULT_BUDGET)
    ap.add_argument("--stage-contracts", default=DEFAULT_STAGE_CONTRACTS)
    ap.add_argument("--stage-runner", default=DEFAULT_STAGE_RUNNER)
    ap.add_argument("--session-id", default="")
    ap.add_argument("--max-loops", type=int, default=0)
    ap.add_argument("--allow-codex-missing", action="store_true")
    ap.add_argument("--skip-validate", action="store_true")
    ap.add_argument("--skip-verifier", action="store_true")
    ap.add_argument("--skip-contracts", action="store_true")
    ap.add_argument("--fresh-loops", action="store_true", help="start loop index from 1 instead of resuming by transactions")
    ap.add_argument("--continue-on-failure", action="store_true")
    ap.add_argument("--fast", action="store_true", help="enable fast profile for lower latency/token usage")
    ap.add_argument("--no-fast", action="store_true", help="disable fast profile even when policy enables it by default")
    args = ap.parse_args()

    if not os.path.exists(args.state):
        print(f"[run_session] state not found: {args.state}", file=sys.stderr)
        return 2

    state = load_json(args.state)
    sid = ensure_session(state, forced_session_id=args.session_id)
    save_json(args.state, state)
    binary_guard_corrected = False
    binary_guard_report_rel = ""
    binary_guard_summary = ""

    policy = try_load_yaml(args.policy)
    budget_cfg = try_load_yaml(args.budget)
    contracts = {} if args.skip_contracts else try_load_yaml(args.stage_contracts)
    stage_runner_cfg = try_load_yaml(args.stage_runner)
    automation = policy.get("automation", {}) if isinstance(policy.get("automation", {}), dict) else {}
    decision_cfg = automation.get("decision", {}) if isinstance(automation.get("decision", {}), dict) else {}
    decision_cfg = dict(decision_cfg)
    streamlined_cfg = automation.get("streamlined", {}) if isinstance(automation.get("streamlined", {}), dict) else {}
    mutation_cfg = decision_cfg.get("input_mutation", {}) if isinstance(decision_cfg.get("input_mutation", {}), dict) else {}
    recovery_cfg = automation.get("recovery", {}) if isinstance(automation.get("recovery", {}), dict) else {}
    objective_cfg = automation.get("objectives", {}) if isinstance(automation.get("objectives", {}), dict) else {}
    cap_cfg = automation.get("capability_inference", {}) if isinstance(automation.get("capability_inference", {}), dict) else {}
    exp_verify_cfg = automation.get("exploit_verify", {}) if isinstance(automation.get("exploit_verify", {}), dict) else {}
    exp_verify_mode = str(exp_verify_cfg.get("verify_mode", "auto") or "auto").strip().lower()
    if exp_verify_mode not in {"quick", "full", "auto"}:
        exp_verify_mode = "auto"
    exp_verify_quick_then_full = bool(exp_verify_cfg.get("quick_then_full", True))
    exploit_autofix_cfg = automation.get("exploit_autofix", {}) if isinstance(automation.get("exploit_autofix", {}), dict) else {}
    remote_prompt_cfg = automation.get("remote_prompt", {}) if isinstance(automation.get("remote_prompt", {}), dict) else {}
    remote_preflight_cfg = automation.get("remote_preflight", {}) if isinstance(automation.get("remote_preflight", {}), dict) else {}
    exploit_stage_cfg = automation.get("exploit_stage", {}) if isinstance(automation.get("exploit_stage", {}), dict) else {}
    unified_cfg = automation.get("unified_solve", {}) if isinstance(automation.get("unified_solve", {}), dict) else {}
    mcp_health_cfg = automation.get("mcp_health", {}) if isinstance(automation.get("mcp_health", {}), dict) else {}
    context_cfg = automation.get("context", {}) if isinstance(automation.get("context", {}), dict) else {}
    stop_control_cfg = automation.get("stop_control", {}) if isinstance(automation.get("stop_control", {}), dict) else {}
    stage_cache_cfg = automation.get("stage_cache", {}) if isinstance(automation.get("stage_cache", {}), dict) else {}
    hard_step_cfg = automation.get("hard_step", {}) if isinstance(automation.get("hard_step", {}), dict) else {}
    cost_fuse_cfg = automation.get("cost_fuses", {}) if isinstance(automation.get("cost_fuses", {}), dict) else {}
    acceptance_cfg = automation.get("acceptance", {}) if isinstance(automation.get("acceptance", {}), dict) else {}
    fast_cfg = automation.get("fast_profile", {}) if isinstance(automation.get("fast_profile", {}), dict) else {}
    streamlined_enabled = bool(streamlined_cfg.get("enabled", True))
    force_terminal_cfg = bool(automation.get("force_reach_terminal_exploit_stage", True))
    codex_cfg = policy.get("codex", {}) if isinstance(policy.get("codex", {}), dict) else {}
    features = policy.get("features", {}) if isinstance(policy.get("features", {}), dict) else {}
    kpi_cfg = policy.get("kpi", {}) if isinstance(policy.get("kpi", {}), dict) else {}
    budget_hyp = budget_cfg.get("hypothesis_policy", {}) if isinstance(budget_cfg.get("hypothesis_policy", {}), dict) else {}
    drop_rule = budget_hyp.get("drop_rule", {}) if isinstance(budget_hyp.get("drop_rule", {}), dict) else {}
    loop_limits = budget_cfg.get("loop_limits", {}) if isinstance(budget_cfg.get("loop_limits", {}), dict) else {}
    max_mut_budget = loop_limits.get("max_mutation_inputs_per_loop", None)
    if isinstance(max_mut_budget, int):
        mutation_cfg.setdefault("max_total_inputs", max_mut_budget)

    fast_default = bool(fast_cfg.get("apply_by_default", False))
    fast_mode = bool(args.fast or (fast_default and (not args.no_fast)))

    enable_exploit = bool(features.get("enable_exploit", True))
    allow_remote_exp = bool(features.get("allow_remote_exp", False))
    state_features = state.get("project", {}).get("features", {}) if isinstance(state.get("project", {}).get("features", {}), dict) else {}
    if "enable_exploit" in state_features:
        enable_exploit = bool(state_features.get("enable_exploit"))
    if "allow_remote_exp" in state_features:
        allow_remote_exp = bool(state_features.get("allow_remote_exp"))

    stage_order = automation.get("stage_order", ["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"])
    if not isinstance(stage_order, list):
        stage_order = ["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"]
    stage_order = [str(x) for x in stage_order]

    if not enable_exploit:
        stage_order = [x for x in stage_order if exploit_stage_level(x) < 0]

    terminal_stage = terminal_exploit_stage(stage_order) if enable_exploit else ""
    force_terminal_stage = bool(force_terminal_cfg and terminal_stage)
    if force_terminal_stage:
        stage_order = ensure_terminal_stage_last(stage_order, terminal_stage)

    if not stage_order:
        print("[run_session] no stage to run")
        return 0

    verify_env_defaults_cfg = exp_verify_cfg.get("run_env_defaults", {})
    normalized_verify_env: Dict[str, str] = {}
    if isinstance(verify_env_defaults_cfg, dict):
        for k, v in verify_env_defaults_cfg.items():
            key = str(k).strip()
            if not key.startswith("PWN_"):
                continue
            val = str(v).strip()
            if not val:
                continue
            normalized_verify_env[key] = val
    auto_runtime_env: Dict[str, str] = {}
    runtime_guard: Dict[str, Any] = {}
    runtime_guard_rel = ""
    runtime_profile_rel = ""
    if enable_exploit:
        state_for_env = load_json(args.state)
        auto_runtime_env = discover_runtime_loader_bundle(state_for_env)
        runtime_guard = collect_runtime_abi_guard(state_for_env, auto_runtime_env)
        runtime_guard_rel = write_runtime_abi_guard_report(args.state, sid, runtime_guard)
        runtime_guard_mismatch = bool(runtime_guard.get("selected_mismatch", False))
        if runtime_guard_mismatch:
            for bad_key in (
                "PWN_LOADER",
                "PWN_LIBC_PATH",
                "PWN_LD_LIBRARY_PATH",
                "PWN_FORCE_LOADER",
                "PWN_LOCAL_PUTS_OFF",
                "PWN_LOCAL_READ_OFF",
                "PWN_LOCAL_SYSTEM_OFF",
                "PWN_LOCAL_BINSH_OFF",
            ):
                auto_runtime_env.pop(bad_key, None)
                normalized_verify_env.pop(bad_key, None)
        for k, v in auto_runtime_env.items():
            key = str(k).strip()
            val = str(v).strip()
            if (not key.startswith("PWN_")) or (not val):
                continue
            normalized_verify_env.setdefault(key, val)
        normalized_verify_env.setdefault("PWN_RUNTIME_GUARD_MISMATCH", "1" if runtime_guard_mismatch else "0")
        normalized_verify_env.setdefault("PWN_INPUT_ALIGN_MODE", "auto")
        if runtime_guard_mismatch:
            normalized_verify_env.setdefault("PWN_FMT_ROUTE", "free_got")
        else:
            normalized_verify_env.setdefault("PWN_FMT_ROUTE", "auto")
        runtime_profile_rel = write_runtime_env_profile(sid, auto_runtime_env)
    if normalized_verify_env or runtime_profile_rel:
        state = load_json(args.state)
        sess_exp = state.setdefault("session", {}).setdefault("exp", {})
        if normalized_verify_env:
            sess_exp["verify_env_defaults"] = normalized_verify_env
        if runtime_profile_rel:
            sess_exp["runtime_env_profile"] = runtime_profile_rel
            state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "runtime_env_profile"
            ] = runtime_profile_rel
        save_json(args.state, state)

    notes: List[str] = []
    lock = acquire_run_lock(ROOT_DIR, sid)
    if not lock.acquired:
        print(f"[run_session] {lock.error}", file=sys.stderr)
        return 4
    if lock.stale_reclaimed:
        notes.append("检测到并回收陈旧 run.lock")

    try:
        binary_guard_corrected, binary_guard_report_rel, binary_guard_summary = guard_binary_path_consistency(
            args.state, sid
        )
        state = load_json(args.state)
    except Exception:
        pass
    if binary_guard_report_rel:
        notes.append(f"binary path guard: {binary_guard_report_rel}")
    if binary_guard_corrected and binary_guard_summary:
        notes.append(f"binary path corrected: {binary_guard_summary}")

    clear_stop_on_start = bool(recovery_cfg.get("clear_stale_stop_request_on_start", True))
    if clear_stop_on_start:
        old_stop = read_stop_request(ROOT_DIR, sid)
        if old_stop:
            clear_stop_request(ROOT_DIR, sid)
            notes.append("启动时清理历史 stop 请求")

    unified_enabled = bool(unified_cfg.get("enabled", True))
    unified_loops = int(unified_cfg.get("max_loops", 1) or 1)
    if unified_enabled:
        # 统一解题模式：固定顺序跑到底，避免分阶段策略抖动导致未进入 exploit。
        decision_cfg["enable_adaptive_stage_order"] = False
    max_loops = args.max_loops if args.max_loops > 0 else int(automation.get("default_max_loops", 1) or 1)
    if unified_enabled and args.max_loops <= 0:
        max_loops = max(1, unified_loops)
    run_validate = (not args.skip_validate) and bool(automation.get("run_validate_state_before_each_stage", True))
    run_verifier = (not args.skip_verifier) and bool(automation.get("run_verifier_after_each_stage", True))
    stop_on_stage_failure = bool(automation.get("stop_on_stage_failure", True)) and (not args.continue_on_failure)
    auto_continue_mcp_failure_stages = recovery_cfg.get(
        "auto_continue_on_mcp_failure_stages",
        ["recon", "ida_slice", "gdb_evidence"],
    )
    if not isinstance(auto_continue_mcp_failure_stages, list):
        auto_continue_mcp_failure_stages = ["recon", "ida_slice", "gdb_evidence"]
    auto_continue_mcp_failure_set = {str(x).strip() for x in auto_continue_mcp_failure_stages if str(x).strip()}
    ida_fail_open_cfg = recovery_cfg.get("ida_fail_open", {}) if isinstance(recovery_cfg.get("ida_fail_open", {}), dict) else {}
    ida_fail_open_enabled = bool(ida_fail_open_cfg.get("enabled", True))
    ida_fail_open_categories_raw = ida_fail_open_cfg.get(
        "failure_categories",
        ["timeout", "mcp_transient", "stage_runtime_error"],
    )
    if not isinstance(ida_fail_open_categories_raw, list):
        ida_fail_open_categories_raw = ["timeout", "mcp_transient", "stage_runtime_error"]
    ida_fail_open_categories = {
        str(x).strip() for x in ida_fail_open_categories_raw if str(x).strip()
    }
    ida_fail_open_write_blocker = bool(ida_fail_open_cfg.get("write_blocker_report", True))
    block_self_stop = bool(stop_control_cfg.get("block_self_stop", True))
    mcp_stage_gate_enabled = bool(mcp_health_cfg.get("check_before_each_stage", True))
    mcp_stage_gate_fail_fast = bool(mcp_health_cfg.get("fail_fast_on_stage_unhealthy", True))
    mcp_stage_gate_stages = mcp_health_cfg.get("stage_gate_stages", ["recon", "ida_slice", "gdb_evidence"])
    if not isinstance(mcp_stage_gate_stages, list):
        mcp_stage_gate_stages = ["recon", "ida_slice", "gdb_evidence"]
    mcp_stage_gate_stage_set = {str(x).strip() for x in mcp_stage_gate_stages if str(x).strip()}
    ida_pre_stage_self_heal = bool(mcp_health_cfg.get("ida_pre_stage_self_heal", True))
    objective_enabled = bool(objective_cfg.get("enabled", True))
    objective_prioritize_missing = bool(objective_cfg.get("prioritize_missing_stages", True))
    objective_stop_on_achieved = bool(objective_cfg.get("stop_when_target_achieved", True))
    exploit_run_codex = bool(exploit_stage_cfg.get("run_codex", False))
    skip_intermediate_exploit = bool(exploit_stage_cfg.get("skip_intermediate_when_terminal", False))
    exploit_stage_codex_disable_mcp = bool(exploit_stage_cfg.get("codex_disable_mcp", True))
    exploit_stage_reuse_existing_exp = bool(exploit_stage_cfg.get("reuse_existing_exp", True))
    exploit_autofix_enabled = bool(exploit_autofix_cfg.get("enabled", True))
    exploit_autofix_run_codex_fix = bool(exploit_autofix_cfg.get("run_codex_fix", True))
    exploit_autofix_until_success = bool(exploit_autofix_cfg.get("until_success", False))
    exploit_autofix_force_until_success = bool(exploit_autofix_cfg.get("force_until_success", False))
    exploit_autofix_max_attempts = int(exploit_autofix_cfg.get("max_attempts", 3) or 3)
    exploit_autofix_max_attempts = max(0, exploit_autofix_max_attempts)
    exploit_autofix_require_success = bool(exploit_autofix_cfg.get("require_success", True))
    exploit_autofix_codex_timeout_sec = int(exploit_autofix_cfg.get("codex_timeout_sec", 60) or 60)
    exploit_autofix_timeout_backoff_sec = int(exploit_autofix_cfg.get("timeout_backoff_sec", 15) or 15)
    exploit_autofix_timeout_backoff_sec = max(0, exploit_autofix_timeout_backoff_sec)
    exploit_autofix_max_timeout_sec = int(exploit_autofix_cfg.get("max_timeout_sec", 90) or 90)
    exploit_autofix_max_timeout_sec = max(0, exploit_autofix_max_timeout_sec)
    exploit_autofix_stop_on_consecutive_timeout = int(
        exploit_autofix_cfg.get("stop_on_consecutive_timeout", 2) or 2
    )
    exploit_autofix_stop_on_consecutive_timeout = max(0, exploit_autofix_stop_on_consecutive_timeout)
    exploit_autofix_max_error_chars = int(exploit_autofix_cfg.get("max_error_chars", 500) or 500)
    exploit_autofix_max_error_chars = max(120, exploit_autofix_max_error_chars)
    exploit_autofix_source_snippet_chars = int(exploit_autofix_cfg.get("source_snippet_chars", 3200) or 3200)
    exploit_autofix_source_snippet_chars = max(0, min(12000, exploit_autofix_source_snippet_chars))
    exploit_autofix_disable_mcp = bool(exploit_autofix_cfg.get("disable_mcp", True))
    exploit_autofix_reasoning_effort = str(exploit_autofix_cfg.get("reasoning_effort", "high") or "high").strip().lower()
    if exploit_autofix_reasoning_effort not in {"minimal", "low", "medium", "high", "xhigh"}:
        exploit_autofix_reasoning_effort = ""
    if exploit_autofix_force_until_success:
        exploit_autofix_until_success = True
    exploit_rewrite_cfg = automation.get("exploit_rewrite", {}) if isinstance(automation.get("exploit_rewrite", {}), dict) else {}
    exploit_rewrite_enabled = bool(exploit_rewrite_cfg.get("enabled", True))
    exploit_rewrite_until_success = bool(exploit_rewrite_cfg.get("until_success", True))
    exploit_rewrite_max_extra_loops = max(0, int(exploit_rewrite_cfg.get("max_extra_loops", 4) or 4))
    exploit_rewrite_max_wall_sec = float(exploit_rewrite_cfg.get("max_wall_sec", 900.0) or 900.0)
    exploit_rewrite_stop_on_same_error_streak = max(
        0, int(exploit_rewrite_cfg.get("stop_on_same_error_streak", 0) or 0)
    )
    exploit_rewrite_reuse_without_ida = bool(exploit_rewrite_cfg.get("reuse_l0_l2_without_ida", True))
    exploit_rewrite_write_report = bool(exploit_rewrite_cfg.get("write_report", True))
    exploit_rewrite_force_terminal_after_l0_timeout_loops = max(
        0, int(exploit_rewrite_cfg.get("force_terminal_after_l0_timeout_loops", 2) or 2)
    )
    exploit_rewrite_force_stage_codex_after_unsolved_loops = max(
        0, int(exploit_rewrite_cfg.get("force_stage_codex_after_unsolved_loops", 3) or 3)
    )
    exploit_rewrite_skip_force_stage_codex_on_timeout_error = bool(
        exploit_rewrite_cfg.get("skip_force_stage_codex_on_timeout_error", True)
    )
    exploit_rewrite_stop_on_non_actionable_verify_streak = max(
        0, int(exploit_rewrite_cfg.get("stop_on_non_actionable_verify_streak", 3) or 3)
    )
    exploit_rewrite_request_hint_after_wall_sec = float(
        exploit_rewrite_cfg.get("request_hint_after_wall_sec", 0.0) or 0.0
    )
    exploit_rewrite_stop_on_request_hint = bool(
        exploit_rewrite_cfg.get("stop_on_request_hint", True)
    )
    stage_timeout_circuit_cfg = (
        recovery_cfg.get("stage_timeout_circuit", {})
        if isinstance(recovery_cfg.get("stage_timeout_circuit", {}), dict)
        else {}
    )
    stage_timeout_circuit_enabled = bool(stage_timeout_circuit_cfg.get("enabled", True))
    stage_timeout_circuit_stages_raw = stage_timeout_circuit_cfg.get("stages", ["recon", "ida_slice"])
    if not isinstance(stage_timeout_circuit_stages_raw, list):
        stage_timeout_circuit_stages_raw = ["recon", "ida_slice"]
    stage_timeout_circuit_stages = {
        str(x).strip() for x in stage_timeout_circuit_stages_raw if str(x).strip()
    }
    stage_timeout_circuit_failure_raw = stage_timeout_circuit_cfg.get(
        "failure_categories",
        ["timeout", "mcp_transient"],
    )
    if not isinstance(stage_timeout_circuit_failure_raw, list):
        stage_timeout_circuit_failure_raw = ["timeout", "mcp_transient"]
    stage_timeout_circuit_failure_categories = {
        str(x).strip() for x in stage_timeout_circuit_failure_raw if str(x).strip()
    }
    stage_timeout_circuit_consecutive_failures = max(
        1, int(stage_timeout_circuit_cfg.get("consecutive_failures", 2) or 2)
    )
    stage_timeout_circuit_cooldown_loops = max(
        1, int(stage_timeout_circuit_cfg.get("cooldown_loops", 2) or 2)
    )
    stage_timeout_circuit_skip_only_if_terminal_in_plan = bool(
        stage_timeout_circuit_cfg.get("skip_only_if_terminal_in_plan", True)
    )
    stage_timeout_circuit_require_exploit_enabled = bool(
        stage_timeout_circuit_cfg.get("require_exploit_enabled", True)
    )
    if not stage_timeout_circuit_stages or not stage_timeout_circuit_failure_categories:
        stage_timeout_circuit_enabled = False
    codex_unhealthy_cfg = (
        recovery_cfg.get("codex_unhealthy_cooldown", {})
        if isinstance(recovery_cfg.get("codex_unhealthy_cooldown", {}), dict)
        else {}
    )
    codex_unhealthy_enabled = bool(codex_unhealthy_cfg.get("enabled", True))
    codex_unhealthy_stages_raw = codex_unhealthy_cfg.get("stages", ["recon", "ida_slice"])
    if not isinstance(codex_unhealthy_stages_raw, list):
        codex_unhealthy_stages_raw = ["recon", "ida_slice"]
    codex_unhealthy_stages = {
        str(x).strip() for x in codex_unhealthy_stages_raw if str(x).strip()
    }
    codex_unhealthy_failure_raw = codex_unhealthy_cfg.get(
        "failure_categories",
        ["timeout", "mcp_transient"],
    )
    if not isinstance(codex_unhealthy_failure_raw, list):
        codex_unhealthy_failure_raw = ["timeout", "mcp_transient"]
    codex_unhealthy_failure_categories = {
        str(x).strip() for x in codex_unhealthy_failure_raw if str(x).strip()
    }
    codex_unhealthy_consecutive_failures = max(
        1, int(codex_unhealthy_cfg.get("consecutive_failures", 2) or 2)
    )
    codex_unhealthy_cooldown_loops = max(
        1, int(codex_unhealthy_cfg.get("cooldown_loops", 2) or 2)
    )
    codex_unhealthy_skip_only_if_terminal_in_plan = bool(
        codex_unhealthy_cfg.get("skip_only_if_terminal_in_plan", True)
    )
    codex_unhealthy_require_exploit_enabled = bool(
        codex_unhealthy_cfg.get("require_exploit_enabled", True)
    )
    if not codex_unhealthy_stages or not codex_unhealthy_failure_categories:
        codex_unhealthy_enabled = False
    exploit_precheck_cfg = (
        automation.get("exploit_precheck", {})
        if isinstance(automation.get("exploit_precheck", {}), dict)
        else {}
    )
    exploit_precheck_enabled = bool(exploit_precheck_cfg.get("enabled", True))
    exploit_precheck_terminal_stage_only = bool(exploit_precheck_cfg.get("terminal_stage_only", True))
    exploit_precheck_min_unsolved_loops = max(
        0, int(exploit_precheck_cfg.get("min_unsolved_loops", 1) or 1)
    )
    exploit_precheck_weak_raw = exploit_precheck_cfg.get(
        "weak_strategies",
        ["fuzz_probe", "rip_control_probe"],
    )
    if not isinstance(exploit_precheck_weak_raw, list):
        exploit_precheck_weak_raw = ["fuzz_probe", "rip_control_probe"]
    exploit_precheck_weak_strategies = {
        str(x).strip().lower() for x in exploit_precheck_weak_raw if str(x).strip()
    }
    if not exploit_precheck_weak_strategies:
        exploit_precheck_weak_strategies = {"fuzz_probe", "rip_control_probe"}
    exploit_precheck_force_minimal_rewrite_after_weak_streak = max(
        1,
        int(exploit_precheck_cfg.get("force_minimal_rewrite_after_weak_streak", 2) or 2),
    )
    strategy_route_cfg = (
        decision_cfg.get("strategy_route_switch", {})
        if isinstance(decision_cfg.get("strategy_route_switch", {}), dict)
        else {}
    )
    strategy_route_switch_enabled = bool(strategy_route_cfg.get("enabled", True))
    strategy_route_switch_no_progress_loops = max(
        1, int(strategy_route_cfg.get("no_progress_loops", 1) or 1)
    )
    strategy_route_switch_terminal_unsolved_loops = max(
        1, int(strategy_route_cfg.get("terminal_unsolved_streak", 1) or 1)
    )
    strategy_route_switch_weak_only = bool(strategy_route_cfg.get("only_when_weak_strategy", False))
    strategy_route_switch_reset_no_progress = bool(
        strategy_route_cfg.get("reset_no_progress_after_switch", True)
    )
    strategy_route_switch_request_hint_after = max(
        0, int(strategy_route_cfg.get("request_hint_after_switches", 0) or 0)
    )
    strategy_route_switch_write_report = bool(strategy_route_cfg.get("write_report", True))
    strategy_route_switch_cycle = _normalize_strategy_hint_cycle(
        strategy_route_cfg.get("cycle", []),
        state=state,
    )
    hint_gate_cfg = (
        decision_cfg.get("hint_request_gate", {})
        if isinstance(decision_cfg.get("hint_request_gate", {}), dict)
        else {}
    )
    hint_gate_enabled = bool(hint_gate_cfg.get("enabled", True))
    hint_gate_no_progress_loops = max(0, int(hint_gate_cfg.get("no_progress_loops", 2) or 2))
    hint_gate_no_new_evidence_sec = max(
        0.0,
        float(hint_gate_cfg.get("no_new_evidence_minutes", 30.0) or 30.0) * 60.0,
    )
    hint_gate_write_report = bool(hint_gate_cfg.get("write_report", True))
    hint_gate_stop_on_trigger = bool(hint_gate_cfg.get("stop_on_trigger", False))
    blind_mode_cfg = (
        decision_cfg.get("blind_mode", {})
        if isinstance(decision_cfg.get("blind_mode", {}), dict)
        else {}
    )
    blind_mode_enabled = bool(blind_mode_cfg.get("enabled", True))
    blind_mode_skip_static_stages = bool(blind_mode_cfg.get("skip_static_stages", True))
    blind_mode_skip_mcp_health_check = bool(blind_mode_cfg.get("skip_mcp_health_check", True))
    blind_mode_prefer_protocol_semantic_probe = bool(
        blind_mode_cfg.get("prefer_protocol_semantic_probe", True)
    )
    blind_mode_default_strategy_hint = _normalize_strategy_hint(
        blind_mode_cfg.get("default_strategy_hint", "js_shell_cmd_exec")
    ) or "js_shell_cmd_exec"
    blind_mode_route_switch_lock = bool(blind_mode_cfg.get("route_switch_lock", True))
    timeout_gate_cfg = (
        decision_cfg.get("timeout_no_evidence_gate", {})
        if isinstance(decision_cfg.get("timeout_no_evidence_gate", {}), dict)
        else {}
    )
    timeout_gate_enabled = bool(timeout_gate_cfg.get("enabled", True))
    timeout_gate_consecutive_loops = max(
        1, int(timeout_gate_cfg.get("consecutive_timeout_loops", 2) or 2)
    )
    timeout_gate_require_no_progress = bool(timeout_gate_cfg.get("require_no_progress", True))
    timeout_gate_blind_only = bool(timeout_gate_cfg.get("blind_mode_only", True))
    timeout_gate_write_report = bool(timeout_gate_cfg.get("write_report", True))
    timeout_gate_stop_on_trigger = bool(timeout_gate_cfg.get("stop_on_trigger", True))
    remote_preflight_enabled = bool(remote_preflight_cfg.get("enabled", True))
    remote_preflight_check_on_start = bool(remote_preflight_cfg.get("check_on_start", True))
    if unified_enabled:
        objective_prioritize_missing = False

    context_mode = str(context_cfg.get("mode", "full")).strip().lower() or "full"
    context_include_hypothesis_ids = bool(context_cfg.get("include_hypothesis_ids", True))
    context_include_mutations = bool(context_cfg.get("include_mutations", True))
    context_include_state_digest = bool(context_cfg.get("include_state_digest", False))
    context_contract_hint_max_chars = int(context_cfg.get("contract_hint_max_chars", 240) or 240)

    stage_cache_enabled = bool(stage_cache_cfg.get("enabled", False))
    stage_cache_overwrite = bool(stage_cache_cfg.get("overwrite", False))
    stage_cache_stages = stage_cache_cfg.get("stages", ["recon", "ida_slice", "gdb_evidence"])
    if not isinstance(stage_cache_stages, list):
        stage_cache_stages = ["recon", "ida_slice", "gdb_evidence"]
    stage_cache_stages_set = {str(x) for x in stage_cache_stages}

    bundle_cfg = stage_cache_cfg.get("bundle_l0_l2", {}) if isinstance(stage_cache_cfg.get("bundle_l0_l2", {}), dict) else {}
    bundle_l0_l2_enabled = bool(bundle_cfg.get("enabled", False))
    bundle_require_consecutive = bool(bundle_cfg.get("require_consecutive", True))
    bundle_include_exploit_stages = bool(bundle_cfg.get("include_exploit_stages", False))
    exploit_cache_cfg = (
        stage_cache_cfg.get("exploit_profile", {}) if isinstance(stage_cache_cfg.get("exploit_profile", {}), dict) else {}
    )
    exploit_profile_cache_enabled = bool(exploit_cache_cfg.get("enabled", False))
    exploit_profile_cache_overwrite = bool(exploit_cache_cfg.get("overwrite", False))

    def _norm_pattern_list(raw: Any) -> List[str]:
        if not isinstance(raw, list):
            return []
        out: List[str] = []
        seen = set()
        for x in raw:
            s = str(x).strip()
            if (not s) or (s in seen):
                continue
            seen.add(s)
            out.append(s)
        return out

    def _norm_stage_pattern_map(raw: Any) -> Dict[str, List[str]]:
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, List[str]] = {}
        for k, v in raw.items():
            key = str(k).strip()
            if not key:
                continue
            out[key] = _norm_pattern_list(v)
        return out

    def _norm_stage_int_map(raw: Any) -> Dict[str, int]:
        if not isinstance(raw, dict):
            return {}
        out: Dict[str, int] = {}
        for k, v in raw.items():
            key = str(k).strip()
            if not key:
                continue
            try:
                out[key] = max(0, int(v))
            except Exception:
                continue
        return out

    hard_step_enabled = bool(hard_step_cfg.get("enabled", True))
    hard_step_enforce_allowed_tools = bool(hard_step_cfg.get("enforce_allowed_tools", True))
    hard_step_default_max_tool_calls = max(0, int(hard_step_cfg.get("default_max_tool_calls", 0) or 0))
    hard_step_blocked_tools = _norm_pattern_list(
        hard_step_cfg.get(
            "blocked_tools",
            [
                "codex.list_mcp_resources*",
                "codex.list_mcp_resource_templates*",
            ],
        )
    )
    hard_step_stage_max = _norm_stage_int_map(hard_step_cfg.get("stage_max_tool_calls", {}))
    hard_step_stage_allow_extra = _norm_stage_pattern_map(hard_step_cfg.get("stage_allow_extra_tools", {}))
    hard_step_stage_block_extra = _norm_stage_pattern_map(hard_step_cfg.get("stage_block_extra_tools", {}))
    hard_step_direct_gdb_probe = bool(hard_step_cfg.get("direct_gdb_probe", True))

    max_codex_calls = int(cost_fuse_cfg.get("max_codex_calls", 0) or 0)
    max_prompt_chars = int(cost_fuse_cfg.get("max_prompt_chars", 0) or 0)
    max_wall_time_sec = float(cost_fuse_cfg.get("max_wall_time_sec", 0) or 0.0)
    max_autofix_rounds = int(cost_fuse_cfg.get("max_autofix_rounds", 0) or 0)
    conservative_self_stop_threshold = int(cost_fuse_cfg.get("conservative_self_stop_threshold", 0) or 0)
    conservative_autofix_threshold = int(cost_fuse_cfg.get("conservative_autofix_threshold", 0) or 0)

    codex_exec_args = codex_cfg.get("exec_args", ["--skip-git-repo-check", "--sandbox", "workspace-write"])
    if not isinstance(codex_exec_args, list) or (not codex_exec_args):
        codex_exec_args = ["--skip-git-repo-check", "--sandbox", "workspace-write"]
    codex_exec_args = [str(x) for x in codex_exec_args if str(x).strip()]

    codex_model = str(codex_cfg.get("model", "")).strip()
    stage_model_cfg_raw = codex_cfg.get("stage_model", {})
    codex_stage_model: Dict[str, str] = {}
    if isinstance(stage_model_cfg_raw, dict):
        for k, v in stage_model_cfg_raw.items():
            key = str(k).strip()
            val = str(v).strip()
            if key and val:
                codex_stage_model[key] = val

    codex_reasoning_effort = str(codex_cfg.get("model_reasoning_effort", "")).strip().lower()
    stage_effort_cfg_raw = codex_cfg.get("stage_model_reasoning_effort", {})
    codex_stage_reasoning_effort: Dict[str, str] = {}
    if isinstance(stage_effort_cfg_raw, dict):
        for k, v in stage_effort_cfg_raw.items():
            key = str(k).strip()
            val = str(v).strip().lower()
            if key and val:
                codex_stage_reasoning_effort[key] = val
    codex_internal_retry_on_nonzero = bool(codex_cfg.get("internal_retry_on_nonzero", False))

    if fast_mode:
        if args.max_loops <= 0:
            max_loops = max(1, int(fast_cfg.get("max_loops", 1) or 1))
        if bool(fast_cfg.get("disable_validate", True)):
            run_validate = False
        if bool(fast_cfg.get("disable_verifier", True)):
            run_verifier = False
        if bool(fast_cfg.get("disable_mcp_health", True)):
            mcp_health_cfg = dict(mcp_health_cfg)
            mcp_health_cfg["check_before_run"] = False
        if bool(fast_cfg.get("disable_mutation", True)):
            mutation_cfg = dict(mutation_cfg)
            mutation_cfg["enabled"] = False
        if bool(fast_cfg.get("disable_capability_inference", False)):
            cap_cfg = dict(cap_cfg)
            cap_cfg["enabled"] = False
        if bool(fast_cfg.get("disable_objective_engine", False)):
            objective_enabled = False
        if "block_self_stop" in fast_cfg:
            block_self_stop = bool(fast_cfg.get("block_self_stop"))
        if "disable_mcp_stage_gate" in fast_cfg:
            if bool(fast_cfg.get("disable_mcp_stage_gate")):
                mcp_stage_gate_enabled = False
        if "exploit_autofix_enabled" in fast_cfg:
            exploit_autofix_enabled = bool(fast_cfg.get("exploit_autofix_enabled"))
        if "exploit_autofix_run_codex_fix" in fast_cfg:
            exploit_autofix_run_codex_fix = bool(fast_cfg.get("exploit_autofix_run_codex_fix"))
        if "exploit_autofix_max_attempts" in fast_cfg:
            exploit_autofix_max_attempts = max(
                0, int(fast_cfg.get("exploit_autofix_max_attempts", exploit_autofix_max_attempts) or exploit_autofix_max_attempts)
            )
        if "exploit_autofix_until_success" in fast_cfg:
            exploit_autofix_until_success = bool(fast_cfg.get("exploit_autofix_until_success"))
        if "exploit_autofix_force_until_success" in fast_cfg:
            exploit_autofix_force_until_success = bool(fast_cfg.get("exploit_autofix_force_until_success"))
        if exploit_autofix_force_until_success:
            exploit_autofix_until_success = True
        if "exploit_autofix_require_success" in fast_cfg:
            exploit_autofix_require_success = bool(fast_cfg.get("exploit_autofix_require_success"))
        if "exploit_autofix_codex_timeout_sec" in fast_cfg:
            exploit_autofix_codex_timeout_sec = max(
                10, int(fast_cfg.get("exploit_autofix_codex_timeout_sec", exploit_autofix_codex_timeout_sec) or exploit_autofix_codex_timeout_sec)
            )
        if "exploit_autofix_timeout_backoff_sec" in fast_cfg:
            exploit_autofix_timeout_backoff_sec = max(
                0,
                int(
                    fast_cfg.get("exploit_autofix_timeout_backoff_sec", exploit_autofix_timeout_backoff_sec)
                    or exploit_autofix_timeout_backoff_sec
                ),
            )
        if "exploit_autofix_max_timeout_sec" in fast_cfg:
            exploit_autofix_max_timeout_sec = max(
                0,
                int(fast_cfg.get("exploit_autofix_max_timeout_sec", exploit_autofix_max_timeout_sec) or exploit_autofix_max_timeout_sec),
            )
        if "exploit_autofix_stop_on_consecutive_timeout" in fast_cfg:
            exploit_autofix_stop_on_consecutive_timeout = max(
                0,
                int(
                    fast_cfg.get("exploit_autofix_stop_on_consecutive_timeout", exploit_autofix_stop_on_consecutive_timeout)
                    or exploit_autofix_stop_on_consecutive_timeout
                ),
            )
        if "exploit_autofix_source_snippet_chars" in fast_cfg:
            exploit_autofix_source_snippet_chars = max(
                0,
                min(
                    12000,
                    int(
                        fast_cfg.get("exploit_autofix_source_snippet_chars", exploit_autofix_source_snippet_chars)
                        or exploit_autofix_source_snippet_chars
                    ),
                ),
            )
        if "exploit_autofix_disable_mcp" in fast_cfg:
            exploit_autofix_disable_mcp = bool(fast_cfg.get("exploit_autofix_disable_mcp"))
        if "exploit_autofix_reasoning_effort" in fast_cfg:
            val = str(fast_cfg.get("exploit_autofix_reasoning_effort", exploit_autofix_reasoning_effort)).strip().lower()
            if val in {"minimal", "low", "medium", "high", "xhigh"}:
                exploit_autofix_reasoning_effort = val
        if "exploit_stage_codex_disable_mcp" in fast_cfg:
            exploit_stage_codex_disable_mcp = bool(fast_cfg.get("exploit_stage_codex_disable_mcp"))
        if "exploit_stage_reuse_existing_exp" in fast_cfg:
            exploit_stage_reuse_existing_exp = bool(fast_cfg.get("exploit_stage_reuse_existing_exp"))
        if "exploit_rewrite_enabled" in fast_cfg:
            exploit_rewrite_enabled = bool(fast_cfg.get("exploit_rewrite_enabled"))
        if "exploit_rewrite_until_success" in fast_cfg:
            exploit_rewrite_until_success = bool(fast_cfg.get("exploit_rewrite_until_success"))
        if "exploit_rewrite_max_extra_loops" in fast_cfg:
            exploit_rewrite_max_extra_loops = max(
                0,
                int(fast_cfg.get("exploit_rewrite_max_extra_loops", exploit_rewrite_max_extra_loops) or exploit_rewrite_max_extra_loops),
            )
        if "exploit_rewrite_max_wall_sec" in fast_cfg:
            exploit_rewrite_max_wall_sec = float(
                fast_cfg.get("exploit_rewrite_max_wall_sec", exploit_rewrite_max_wall_sec) or exploit_rewrite_max_wall_sec
            )
        if "exploit_rewrite_stop_on_same_error_streak" in fast_cfg:
            exploit_rewrite_stop_on_same_error_streak = max(
                0,
                int(
                    fast_cfg.get(
                        "exploit_rewrite_stop_on_same_error_streak",
                        exploit_rewrite_stop_on_same_error_streak,
                    )
                    or exploit_rewrite_stop_on_same_error_streak
                ),
            )
        if "exploit_rewrite_reuse_without_ida" in fast_cfg:
            exploit_rewrite_reuse_without_ida = bool(fast_cfg.get("exploit_rewrite_reuse_without_ida"))
        if "exploit_rewrite_force_terminal_after_l0_timeout_loops" in fast_cfg:
            exploit_rewrite_force_terminal_after_l0_timeout_loops = max(
                0,
                int(
                    fast_cfg.get(
                        "exploit_rewrite_force_terminal_after_l0_timeout_loops",
                        exploit_rewrite_force_terminal_after_l0_timeout_loops,
                    )
                    or exploit_rewrite_force_terminal_after_l0_timeout_loops
                ),
            )
        if "exploit_rewrite_force_stage_codex_after_unsolved_loops" in fast_cfg:
            exploit_rewrite_force_stage_codex_after_unsolved_loops = max(
                0,
                int(
                    fast_cfg.get(
                        "exploit_rewrite_force_stage_codex_after_unsolved_loops",
                        exploit_rewrite_force_stage_codex_after_unsolved_loops,
                    )
                    or exploit_rewrite_force_stage_codex_after_unsolved_loops
                ),
            )
        if "exploit_rewrite_skip_force_stage_codex_on_timeout_error" in fast_cfg:
            exploit_rewrite_skip_force_stage_codex_on_timeout_error = bool(
                fast_cfg.get(
                    "exploit_rewrite_skip_force_stage_codex_on_timeout_error",
                    exploit_rewrite_skip_force_stage_codex_on_timeout_error,
                )
            )
        if "exploit_rewrite_stop_on_non_actionable_verify_streak" in fast_cfg:
            exploit_rewrite_stop_on_non_actionable_verify_streak = max(
                0,
                int(
                    fast_cfg.get(
                        "exploit_rewrite_stop_on_non_actionable_verify_streak",
                        exploit_rewrite_stop_on_non_actionable_verify_streak,
                    )
                    or exploit_rewrite_stop_on_non_actionable_verify_streak
                ),
            )
        if "exploit_rewrite_request_hint_after_wall_sec" in fast_cfg:
            exploit_rewrite_request_hint_after_wall_sec = float(
                fast_cfg.get(
                    "exploit_rewrite_request_hint_after_wall_sec",
                    exploit_rewrite_request_hint_after_wall_sec,
                )
                or exploit_rewrite_request_hint_after_wall_sec
            )
        if "exploit_rewrite_stop_on_request_hint" in fast_cfg:
            exploit_rewrite_stop_on_request_hint = bool(
                fast_cfg.get(
                    "exploit_rewrite_stop_on_request_hint",
                    exploit_rewrite_stop_on_request_hint,
                )
            )
        if "timeout_circuit_enabled" in fast_cfg:
            stage_timeout_circuit_enabled = bool(fast_cfg.get("timeout_circuit_enabled"))
        if "timeout_circuit_consecutive_failures" in fast_cfg:
            stage_timeout_circuit_consecutive_failures = max(
                1,
                int(
                    fast_cfg.get(
                        "timeout_circuit_consecutive_failures",
                        stage_timeout_circuit_consecutive_failures,
                    )
                    or stage_timeout_circuit_consecutive_failures
                ),
            )
        if "timeout_circuit_cooldown_loops" in fast_cfg:
            stage_timeout_circuit_cooldown_loops = max(
                1,
                int(
                    fast_cfg.get("timeout_circuit_cooldown_loops", stage_timeout_circuit_cooldown_loops)
                    or stage_timeout_circuit_cooldown_loops
                ),
            )
        if "timeout_circuit_skip_only_if_terminal_in_plan" in fast_cfg:
            stage_timeout_circuit_skip_only_if_terminal_in_plan = bool(
                fast_cfg.get(
                    "timeout_circuit_skip_only_if_terminal_in_plan",
                    stage_timeout_circuit_skip_only_if_terminal_in_plan,
                )
            )
        if "timeout_circuit_require_exploit_enabled" in fast_cfg:
            stage_timeout_circuit_require_exploit_enabled = bool(
                fast_cfg.get(
                    "timeout_circuit_require_exploit_enabled",
                    stage_timeout_circuit_require_exploit_enabled,
                )
            )
        if "codex_unhealthy_cooldown_enabled" in fast_cfg:
            codex_unhealthy_enabled = bool(fast_cfg.get("codex_unhealthy_cooldown_enabled"))
        if "codex_unhealthy_cooldown_consecutive_failures" in fast_cfg:
            codex_unhealthy_consecutive_failures = max(
                1,
                int(
                    fast_cfg.get(
                        "codex_unhealthy_cooldown_consecutive_failures",
                        codex_unhealthy_consecutive_failures,
                    )
                    or codex_unhealthy_consecutive_failures
                ),
            )
        if "codex_unhealthy_cooldown_loops" in fast_cfg:
            codex_unhealthy_cooldown_loops = max(
                1,
                int(
                    fast_cfg.get("codex_unhealthy_cooldown_loops", codex_unhealthy_cooldown_loops)
                    or codex_unhealthy_cooldown_loops
                ),
            )
        if "codex_unhealthy_cooldown_skip_only_if_terminal_in_plan" in fast_cfg:
            codex_unhealthy_skip_only_if_terminal_in_plan = bool(
                fast_cfg.get(
                    "codex_unhealthy_cooldown_skip_only_if_terminal_in_plan",
                    codex_unhealthy_skip_only_if_terminal_in_plan,
                )
            )
        if "codex_unhealthy_cooldown_require_exploit_enabled" in fast_cfg:
            codex_unhealthy_require_exploit_enabled = bool(
                fast_cfg.get(
                    "codex_unhealthy_cooldown_require_exploit_enabled",
                    codex_unhealthy_require_exploit_enabled,
                )
            )
        if "exploit_precheck_enabled" in fast_cfg:
            exploit_precheck_enabled = bool(fast_cfg.get("exploit_precheck_enabled"))
        if "exploit_precheck_terminal_stage_only" in fast_cfg:
            exploit_precheck_terminal_stage_only = bool(fast_cfg.get("exploit_precheck_terminal_stage_only"))
        if "exploit_precheck_min_unsolved_loops" in fast_cfg:
            exploit_precheck_min_unsolved_loops = max(
                0,
                int(
                    fast_cfg.get("exploit_precheck_min_unsolved_loops", exploit_precheck_min_unsolved_loops)
                    or exploit_precheck_min_unsolved_loops
                ),
            )
        if "exploit_precheck_force_minimal_rewrite_after_weak_streak" in fast_cfg:
            exploit_precheck_force_minimal_rewrite_after_weak_streak = max(
                1,
                int(
                    fast_cfg.get(
                        "exploit_precheck_force_minimal_rewrite_after_weak_streak",
                        exploit_precheck_force_minimal_rewrite_after_weak_streak,
                    )
                    or exploit_precheck_force_minimal_rewrite_after_weak_streak
                ),
            )
        if "strategy_route_switch_enabled" in fast_cfg:
            strategy_route_switch_enabled = bool(fast_cfg.get("strategy_route_switch_enabled"))
        if "strategy_route_switch_no_progress_loops" in fast_cfg:
            strategy_route_switch_no_progress_loops = max(
                1,
                int(
                    fast_cfg.get(
                        "strategy_route_switch_no_progress_loops",
                        strategy_route_switch_no_progress_loops,
                    )
                    or strategy_route_switch_no_progress_loops
                ),
            )
        if "strategy_route_switch_terminal_unsolved_loops" in fast_cfg:
            strategy_route_switch_terminal_unsolved_loops = max(
                1,
                int(
                    fast_cfg.get(
                        "strategy_route_switch_terminal_unsolved_loops",
                        strategy_route_switch_terminal_unsolved_loops,
                    )
                    or strategy_route_switch_terminal_unsolved_loops
                ),
            )
        if "strategy_route_switch_weak_only" in fast_cfg:
            strategy_route_switch_weak_only = bool(fast_cfg.get("strategy_route_switch_weak_only"))
        if "strategy_route_switch_reset_no_progress" in fast_cfg:
            strategy_route_switch_reset_no_progress = bool(
                fast_cfg.get("strategy_route_switch_reset_no_progress")
            )
        if "strategy_route_switch_request_hint_after" in fast_cfg:
            strategy_route_switch_request_hint_after = max(
                0,
                int(
                    fast_cfg.get(
                        "strategy_route_switch_request_hint_after",
                        strategy_route_switch_request_hint_after,
                    )
                    or strategy_route_switch_request_hint_after
                ),
            )
        if "strategy_route_switch_write_report" in fast_cfg:
            strategy_route_switch_write_report = bool(fast_cfg.get("strategy_route_switch_write_report"))
        if "strategy_route_switch_cycle" in fast_cfg:
            strategy_route_switch_cycle = _normalize_strategy_hint_cycle(
                fast_cfg.get("strategy_route_switch_cycle", strategy_route_switch_cycle),
                state=state,
            )
        if "hint_gate_enabled" in fast_cfg:
            hint_gate_enabled = bool(fast_cfg.get("hint_gate_enabled"))
        if "hint_gate_no_progress_loops" in fast_cfg:
            hint_gate_no_progress_loops = max(
                0,
                int(fast_cfg.get("hint_gate_no_progress_loops", hint_gate_no_progress_loops) or hint_gate_no_progress_loops),
            )
        if "hint_gate_no_new_evidence_minutes" in fast_cfg:
            hint_gate_no_new_evidence_sec = max(
                0.0,
                float(
                    fast_cfg.get("hint_gate_no_new_evidence_minutes", hint_gate_no_new_evidence_sec / 60.0)
                    or (hint_gate_no_new_evidence_sec / 60.0)
                )
                * 60.0,
            )
        if "hint_gate_write_report" in fast_cfg:
            hint_gate_write_report = bool(fast_cfg.get("hint_gate_write_report"))
        if "hint_gate_stop_on_trigger" in fast_cfg:
            hint_gate_stop_on_trigger = bool(fast_cfg.get("hint_gate_stop_on_trigger"))
        if "blind_mode_enabled" in fast_cfg:
            blind_mode_enabled = bool(fast_cfg.get("blind_mode_enabled"))
        if "blind_mode_skip_static_stages" in fast_cfg:
            blind_mode_skip_static_stages = bool(fast_cfg.get("blind_mode_skip_static_stages"))
        if "blind_mode_skip_mcp_health_check" in fast_cfg:
            blind_mode_skip_mcp_health_check = bool(fast_cfg.get("blind_mode_skip_mcp_health_check"))
        if "blind_mode_prefer_protocol_semantic_probe" in fast_cfg:
            blind_mode_prefer_protocol_semantic_probe = bool(
                fast_cfg.get("blind_mode_prefer_protocol_semantic_probe")
            )
        if "blind_mode_default_strategy_hint" in fast_cfg:
            blind_mode_default_strategy_hint = (
                _normalize_strategy_hint(fast_cfg.get("blind_mode_default_strategy_hint"))
                or blind_mode_default_strategy_hint
            )
        if "blind_mode_route_switch_lock" in fast_cfg:
            blind_mode_route_switch_lock = bool(fast_cfg.get("blind_mode_route_switch_lock"))
        if "timeout_no_evidence_gate_enabled" in fast_cfg:
            timeout_gate_enabled = bool(fast_cfg.get("timeout_no_evidence_gate_enabled"))
        if "timeout_no_evidence_gate_consecutive_loops" in fast_cfg:
            timeout_gate_consecutive_loops = max(
                1,
                int(
                    fast_cfg.get(
                        "timeout_no_evidence_gate_consecutive_loops",
                        timeout_gate_consecutive_loops,
                    )
                    or timeout_gate_consecutive_loops
                ),
            )
        if "timeout_no_evidence_gate_require_no_progress" in fast_cfg:
            timeout_gate_require_no_progress = bool(
                fast_cfg.get("timeout_no_evidence_gate_require_no_progress")
            )
        if "timeout_no_evidence_gate_blind_only" in fast_cfg:
            timeout_gate_blind_only = bool(fast_cfg.get("timeout_no_evidence_gate_blind_only"))
        if "timeout_no_evidence_gate_write_report" in fast_cfg:
            timeout_gate_write_report = bool(fast_cfg.get("timeout_no_evidence_gate_write_report"))
        if "timeout_no_evidence_gate_stop_on_trigger" in fast_cfg:
            timeout_gate_stop_on_trigger = bool(fast_cfg.get("timeout_no_evidence_gate_stop_on_trigger"))
        if "remote_preflight_enabled" in fast_cfg:
            remote_preflight_enabled = bool(fast_cfg.get("remote_preflight_enabled"))
        if "remote_preflight_check_on_start" in fast_cfg:
            remote_preflight_check_on_start = bool(fast_cfg.get("remote_preflight_check_on_start"))
        skip_intermediate_exploit = bool(fast_cfg.get("skip_intermediate_exploit", skip_intermediate_exploit))
        context_mode = str(fast_cfg.get("context_mode", context_mode)).strip().lower() or context_mode
        context_include_hypothesis_ids = bool(fast_cfg.get("context_include_hypothesis_ids", context_include_hypothesis_ids))
        context_include_mutations = bool(fast_cfg.get("context_include_mutations", context_include_mutations))
        context_include_state_digest = bool(fast_cfg.get("context_include_state_digest", context_include_state_digest))
        context_contract_hint_max_chars = int(
            fast_cfg.get("context_contract_hint_max_chars", context_contract_hint_max_chars) or context_contract_hint_max_chars
        )
        stage_cache_enabled = bool(fast_cfg.get("cache_enabled", stage_cache_enabled))
        stage_cache_overwrite = bool(fast_cfg.get("cache_overwrite", stage_cache_overwrite))
        if "cache_exploit_profile" in fast_cfg:
            exploit_profile_cache_enabled = bool(fast_cfg.get("cache_exploit_profile"))
        if "hard_step_enabled" in fast_cfg:
            hard_step_enabled = bool(fast_cfg.get("hard_step_enabled"))
        if "hard_step_enforce_allowed_tools" in fast_cfg:
            hard_step_enforce_allowed_tools = bool(fast_cfg.get("hard_step_enforce_allowed_tools"))
        if "hard_step_default_max_tool_calls" in fast_cfg:
            try:
                hard_step_default_max_tool_calls = max(
                    0, int(fast_cfg.get("hard_step_default_max_tool_calls", hard_step_default_max_tool_calls))
                )
            except Exception:
                pass
        fast_hard_step_stage_max = fast_cfg.get("hard_step_stage_max_tool_calls", {})
        if isinstance(fast_hard_step_stage_max, dict):
            for k, v in fast_hard_step_stage_max.items():
                key = str(k).strip()
                if not key:
                    continue
                try:
                    hard_step_stage_max[key] = max(0, int(v))
                except Exception:
                    continue
        if "hard_step_direct_gdb_probe" in fast_cfg:
            hard_step_direct_gdb_probe = bool(fast_cfg.get("hard_step_direct_gdb_probe"))
        bundle_l0_l2_enabled = bool(fast_cfg.get("bundle_l0_l2", bundle_l0_l2_enabled))
        bundle_include_exploit_stages = bool(
            fast_cfg.get("bundle_include_exploit_stages", bundle_include_exploit_stages)
        )
        max_codex_calls = int(fast_cfg.get("max_codex_calls", max_codex_calls) or max_codex_calls)
        max_prompt_chars = int(fast_cfg.get("max_prompt_chars", max_prompt_chars) or max_prompt_chars)
        max_wall_time_sec = float(fast_cfg.get("max_wall_time_sec", max_wall_time_sec) or max_wall_time_sec)
        codex_model = str(
            fast_cfg.get("codex_model", fast_cfg.get("model", codex_model))
        ).strip()
        stage_model_fast_raw = fast_cfg.get("stage_model", {})
        if isinstance(stage_model_fast_raw, dict):
            for k, v in stage_model_fast_raw.items():
                key = str(k).strip()
                val = str(v).strip()
                if key and val:
                    codex_stage_model[key] = val
        codex_reasoning_effort = str(
            fast_cfg.get("codex_model_reasoning_effort", fast_cfg.get("model_reasoning_effort", codex_reasoning_effort))
        ).strip().lower()
        stage_effort_fast_raw = fast_cfg.get("stage_model_reasoning_effort", {})
        if isinstance(stage_effort_fast_raw, dict):
            for k, v in stage_effort_fast_raw.items():
                key = str(k).strip()
                val = str(v).strip().lower()
                if key and val:
                    codex_stage_reasoning_effort[key] = val
        codex_internal_retry_on_nonzero = bool(
            fast_cfg.get("codex_internal_retry_on_nonzero", codex_internal_retry_on_nonzero)
        )
        fast_exec_args = fast_cfg.get("codex_exec_args", None)
        if isinstance(fast_exec_args, list) and fast_exec_args:
            codex_exec_args = [str(x) for x in fast_exec_args if str(x).strip()]

    streamlined_summary = ""
    if streamlined_enabled:
        mutation_cfg = dict(mutation_cfg)
        mutation_cfg["enabled"] = False
        bundle_l0_l2_enabled = False
        bundle_include_exploit_stages = False
        hard_step_enabled = False
        hard_step_direct_gdb_probe = False
        stage_timeout_circuit_enabled = False
        codex_unhealthy_enabled = False
        timeout_gate_enabled = False
        exploit_precheck_enabled = False
        acceptance_cfg = dict(acceptance_cfg)
        acceptance_cfg["enabled"] = False
        context_contract_hint_max_chars = min(context_contract_hint_max_chars, 120)
        exploit_autofix_source_snippet_chars = min(exploit_autofix_source_snippet_chars, 1800)
        streamlined_summary = (
            "streamlined mode: disable mutation/bundle/hard-step/acceptance/"
            "timeout-handoff/exploit-precheck; keep runtime-align + route-switch + rewrite + verify"
        )
    if streamlined_summary:
        notes.append(streamlined_summary)

    if exploit_autofix_reasoning_effort:
        for _k in ("exploit_l3_autofix", "exploit_l4_autofix"):
            if _k not in codex_stage_reasoning_effort:
                codex_stage_reasoning_effort[_k] = exploit_autofix_reasoning_effort

    if enable_exploit and skip_intermediate_exploit:
        term_stage = terminal_exploit_stage(stage_order)
        term_lv = exploit_stage_level(term_stage)
        if term_lv > 0:
            stage_order = [x for x in stage_order if (exploit_stage_level(x) < 0) or (x == term_stage)]
            terminal_stage = term_stage

    session_blind_mode = bool(blind_mode_enabled and detect_blind_mode(state))
    if session_blind_mode:
        notes.append("blind mode detected: challenge binary_path is empty or explicitly marked blind_mode")
        if enable_exploit and terminal_stage and blind_mode_skip_static_stages:
            stage_order = [terminal_stage]
            notes.append("blind mode stage gate: skip recon/ida/gdb, keep terminal exploit only")
        if enable_exploit and terminal_stage and blind_mode_prefer_protocol_semantic_probe:
            state_for_blind_hint = load_json(args.state)
            exp_hint_obj = state_for_blind_hint.setdefault("session", {}).setdefault("exp", {})
            current_hint = _normalize_strategy_hint(exp_hint_obj.get("strategy_hint", ""))
            if not current_hint:
                exp_hint_obj["strategy_hint"] = blind_mode_default_strategy_hint
                exp_hint_obj["force_regen_once"] = True
                exp_hint_obj["strategy_switch_reason"] = "blind mode default strategy bootstrap"
                exp_hint_obj["strategy_switch_utc"] = utc_now()
                save_json(args.state, state_for_blind_hint)
                notes.append(f"blind mode strategy bootstrap: {blind_mode_default_strategy_hint}")

    quick_strategy_applied = False
    quick_strategy_report_rel = ""
    if enable_exploit and terminal_stage and (not session_blind_mode):
        quick_strategy_applied, quick_strategy_report_rel = apply_direct_system_binsh_shortcut(args.state, sid)
        if quick_strategy_report_rel:
            notes.append(f"quick strategy report: {quick_strategy_report_rel}")
        if quick_strategy_applied:
            stage_order = [terminal_stage]
            notes.append(
                "quick shortcut matched: direct system('/bin/sh')，跳过 L0-L2，直接进入 terminal exploit"
            )

    codex_bin = str(codex_cfg.get("bin", "codex"))
    configured_codex_bin = codex_bin
    enforce_configured_bin = bool(codex_cfg.get("enforce_configured_bin", True))
    allow_env_codex_bin_override = bool(codex_cfg.get("allow_env_codex_bin_override", False))
    if allow_env_codex_bin_override:
        env_codex_bin = os.environ.get("CODEX_BIN", "").strip()
        if env_codex_bin:
            codex_bin = env_codex_bin
            configured_codex_bin = codex_bin

    def _is_exec_available(path_or_cmd: str) -> bool:
        p = str(path_or_cmd).strip()
        if not p:
            return False
        if os.path.sep in p:
            ap = p if os.path.isabs(p) else os.path.abspath(os.path.join(ROOT_DIR, p))
            return os.path.isfile(ap) and os.access(ap, os.X_OK)
        return shutil.which(p) is not None

    codex_runner_invalid = False
    codex_runner_invalid_reason = ""
    if not _is_exec_available(codex_bin):
        if (os.path.sep in str(configured_codex_bin)) and enforce_configured_bin:
            codex_runner_invalid = True
            codex_runner_invalid_reason = (
                f"configured codex runner unavailable: {configured_codex_bin} "
                "(refuse fallback to plain codex to avoid MCP misconfiguration)"
            )
        else:
            fallback_candidates = [
                os.path.expanduser("~/.npm-global/bin/codex"),
                os.path.expanduser("~/.local/bin/codex"),
            ]
            for fb in fallback_candidates:
                if os.path.exists(fb) and os.access(fb, os.X_OK):
                    codex_bin = fb
                    break
    codex_retries = int(codex_cfg.get("retries", 0) or 0)
    timeout_cfg = codex_cfg.get("timeout_sec", {}) if isinstance(codex_cfg.get("timeout_sec", {}), dict) else {}
    default_stage_timeout = int(codex_cfg.get("default_timeout_sec", 90) or 90)
    default_stage_timeout = max(20, default_stage_timeout)
    if fast_mode:
        codex_retries = int(fast_cfg.get("codex_retries", codex_retries) or codex_retries)
        fast_timeout_cfg = fast_cfg.get("timeout_sec", {}) if isinstance(fast_cfg.get("timeout_sec", {}), dict) else {}
        if fast_timeout_cfg:
            timeout_cfg = dict(timeout_cfg)
            for k, v in fast_timeout_cfg.items():
                try:
                    timeout_cfg[str(k)] = int(v)
                except Exception:
                    continue
        if "default_timeout_sec" in fast_cfg:
            try:
                default_stage_timeout = max(20, int(fast_cfg.get("default_timeout_sec", default_stage_timeout)))
            except Exception:
                pass
    adapter = CodexCLIAdapter(
        codex_bin=codex_bin,
        retries=codex_retries,
        retry_on_nonzero=codex_internal_retry_on_nonzero,
        model=codex_model,
        stage_model=codex_stage_model,
        model_reasoning_effort=codex_reasoning_effort,
        stage_model_reasoning_effort=codex_stage_reasoning_effort,
        extra_args=codex_exec_args,
    )

    codex_available = _is_exec_available(codex_bin) and (not codex_runner_invalid)

    kpi_enabled = bool(kpi_cfg.get("enabled", True))
    kpi_paths = kpi_cfg.get("paths", {}) if isinstance(kpi_cfg.get("paths", {}), dict) else {}
    per_session_tpl = str(kpi_paths.get("per_session", "sessions/{session_id}/metrics.json"))
    global_kpi_rel = str(kpi_paths.get("global", "artifacts/reports/kpi_latest.json"))

    per_session_rel = per_session_tpl.replace("{session_id}", sid)
    per_session_abs = os.path.join(ROOT_DIR, per_session_rel)
    global_kpi_abs = os.path.join(ROOT_DIR, global_kpi_rel)

    metrics = SessionMetrics.load_or_new(per_session_abs, sid)
    if conservative_self_stop_threshold > 0 and metrics.self_stop_blocked >= conservative_self_stop_threshold:
        recovery_cfg = dict(recovery_cfg)
        recovery_cfg["default_max_retries"] = 0
        recovery_cfg["stage_max_retries"] = {k: 0 for k in stage_order}
        bundle_l0_l2_enabled = False
    if conservative_autofix_threshold > 0 and metrics.autofix_rounds_total >= conservative_autofix_threshold:
        exploit_autofix_enabled = False
    hypo_max_active = int(decision_cfg.get("max_active_hypotheses", budget_hyp.get("max_active", 3)) or 3)
    hypo_drop_threshold = int(
        decision_cfg.get(
            "hypothesis_no_progress_drop_threshold",
            drop_rule.get("max_consecutive_no_progress", 2),
        )
        or 2
    )
    hypo_engine = HypothesisEngine(max_active=hypo_max_active, no_progress_drop_threshold=hypo_drop_threshold)

    stage_results: List[Dict[str, Any]] = []
    no_progress_loops = 0
    stop_requested = False
    fuse_triggered = False
    fuse_reason = ""
    run_started_monotonic = time.monotonic()
    binary_sha256 = challenge_binary_sha256(load_json(args.state))
    prev_session_mcp_env = configure_session_mcp_env(sid)
    prev_autorun = os.environ.get("DIRGE_AUTORUN", None)
    prev_block_self_stop = os.environ.get("DIRGE_BLOCK_SELF_STOP", None)

    loop_start = 1 if args.fresh_loops else next_loop_index(sid)
    base_max_loops = max_loops
    exploit_rewrite_extra_loops = (
        exploit_rewrite_max_extra_loops if (exploit_rewrite_enabled and enable_exploit and bool(terminal_stage)) else 0
    )
    loop_end = loop_start + base_max_loops + exploit_rewrite_extra_loops
    if exploit_rewrite_enabled and exploit_rewrite_until_success and enable_exploit and bool(terminal_stage):
        loop_end = max(loop_end, loop_start + EXPLOIT_REWRITE_UNTIL_SUCCESS_LOOP_CAP)
    exploit_rewrite_started_monotonic = 0.0
    exploit_rewrite_same_error_streak = 0
    exploit_rewrite_last_error = ""
    exploit_rewrite_last_verify_report = ""
    exploit_rewrite_last_exp_path = ""
    exploit_rewrite_stop_reason = ""
    exploit_rewrite_report_rel = ""
    l0_timeout_no_terminal_streak = 0
    terminal_unsolved_streak = 0
    terminal_non_actionable_verify_streak = 0
    weak_closure_precheck_streak = 0
    strategy_route_switch_count = 0
    last_new_evidence_monotonic = time.monotonic()
    hint_gate_last_trigger_loop = 0
    timeout_no_evidence_streak = 0
    stage_timeout_failure_streak: Dict[str, int] = {s: 0 for s in stage_timeout_circuit_stages}
    stage_timeout_skip_remaining: Dict[str, int] = {s: 0 for s in stage_timeout_circuit_stages}
    codex_unhealthy_failure_streak: Dict[str, int] = {s: 0 for s in codex_unhealthy_stages}
    codex_unhealthy_skip_remaining: Dict[str, int] = {s: 0 for s in codex_unhealthy_stages}

    try:
        os.environ["DIRGE_AUTORUN"] = "1"
        os.environ["DIRGE_BLOCK_SELF_STOP"] = "1" if block_self_stop else "0"

        if fast_mode:
            notes.append("fast profile 已启用")
        if unified_enabled:
            notes.append("unified_solve 已启用：固定顺序单轮推进到终点 exploit")
        if stage_cache_enabled:
            notes.append("stage_cache 已启用（按 binary sha256）")
        if exploit_profile_cache_enabled:
            notes.append("exploit_profile cache 已启用（按 binary sha256）")
        if bundle_l0_l2_enabled:
            if bundle_include_exploit_stages:
                notes.append("L0->L4 单次编排已启用")
            else:
                notes.append("L0/L1/L2 单次编排已启用")
        if max_codex_calls > 0 or max_prompt_chars > 0 or max_wall_time_sec > 0:
            notes.append(
                f"cost_fuse 生效: codex_calls<={max_codex_calls or 'inf'}, "
                f"prompt_chars<={max_prompt_chars or 'inf'}, wall<={int(max_wall_time_sec) if max_wall_time_sec > 0 else 'inf'}s"
            )
        if max_autofix_rounds > 0:
            notes.append(f"cost_fuse 生效: autofix_rounds_total<={max_autofix_rounds}")
        notes.append(
            f"codex runner: retries={max(0, int(codex_retries))}, "
            f"internal_retry_on_nonzero={bool(codex_internal_retry_on_nonzero)}, "
            f"model={(codex_model or 'default')}, "
            f"reasoning_effort={(codex_reasoning_effort or 'default')}"
        )
        notes.append(f"codex bin: {codex_bin}")
        gh_proj = str(os.environ.get("GHIDRA_MCP_PROJECT_PATH", "")).strip()
        if gh_proj:
            notes.append(f"ghidra project: {gh_proj}")
        notes.append(f"self-stop guard: {'on' if block_self_stop else 'off'}")
        if ida_fail_open_enabled:
            cats = ",".join(sorted(ida_fail_open_categories)) if ida_fail_open_categories else "none"
            notes.append(f"ida fail-open: on ({cats})")
        else:
            notes.append("ida fail-open: off")
        notes.append(
            f"mcp stage gate: {'on' if mcp_stage_gate_enabled else 'off'}"
            + (f" (fail_fast={'on' if mcp_stage_gate_fail_fast else 'off'})" if mcp_stage_gate_enabled else "")
        )
        notes.append(
            "mcp functional probe: "
            + (
                f"before_run={'on' if bool(mcp_health_cfg.get('functional_probe_before_run', True)) else 'off'}, "
                f"stage_gate={'on' if bool(mcp_health_cfg.get('functional_probe_on_stage_gate', False)) else 'off'}"
            )
        )
        notes.append(f"ida pre-stage self-heal: {'on' if ida_pre_stage_self_heal else 'off'}")
        notes.append(
            f"hard-step guard: {'on' if hard_step_enabled else 'off'}"
            + (
                f" (enforce_allowed={'on' if hard_step_enforce_allowed_tools else 'off'}, "
                f"default_max_tool_calls={hard_step_default_max_tool_calls or 'auto'})"
                if hard_step_enabled
                else ""
            )
        )
        if hard_step_enabled:
            notes.append(f"hard-step direct gdb probe: {'on' if hard_step_direct_gdb_probe else 'off'}")
        if conservative_self_stop_threshold > 0 and metrics.self_stop_blocked >= conservative_self_stop_threshold:
            notes.append(
                f"conservative mode: self_stop_blocked={metrics.self_stop_blocked} >= {conservative_self_stop_threshold}"
            )
        if conservative_autofix_threshold > 0 and metrics.autofix_rounds_total >= conservative_autofix_threshold:
            notes.append(
                f"conservative mode: autofix_rounds_total={metrics.autofix_rounds_total} >= {conservative_autofix_threshold}"
            )
        if enable_exploit:
            notes.append(
                f"exploit_verify: run={bool(exp_verify_cfg.get('run', False))}, "
                f"strict={bool(exp_verify_cfg.get('strict', False))}, "
                f"verify_mode={exp_verify_mode}, quick_then_full={exp_verify_quick_then_full}, "
                f"timeout={float(exp_verify_cfg.get('run_timeout_sec', 0) or 0):g}s"
            )
            notes.append(
                f"exploit_autofix: enabled={exploit_autofix_enabled}, "
                f"run_codex_fix={exploit_autofix_run_codex_fix}, "
                f"until_success={exploit_autofix_until_success}, "
                f"force_until_success={exploit_autofix_force_until_success}, "
                f"max_attempts={exploit_autofix_max_attempts}, require_success={exploit_autofix_require_success}, "
                f"timeout={exploit_autofix_codex_timeout_sec}s+{exploit_autofix_timeout_backoff_sec}s, "
                f"max_timeout={exploit_autofix_max_timeout_sec}s, stop_after_timeout_streak={exploit_autofix_stop_on_consecutive_timeout}, "
                f"disable_mcp={exploit_autofix_disable_mcp}, reasoning={exploit_autofix_reasoning_effort or 'default'}, "
                f"source_snippet_chars={exploit_autofix_source_snippet_chars}"
            )
            notes.append(
                f"exploit_rewrite: enabled={exploit_rewrite_enabled}, "
                f"until_success={exploit_rewrite_until_success}, "
                f"base_loops={base_max_loops}, extra_loops={exploit_rewrite_extra_loops}, "
                f"max_wall={exploit_rewrite_max_wall_sec:g}s, same_error_streak<={exploit_rewrite_stop_on_same_error_streak or 'inf'}, "
                f"non_actionable_verify_streak<={exploit_rewrite_stop_on_non_actionable_verify_streak or 'inf'}, "
                f"request_hint_after_wall={exploit_rewrite_request_hint_after_wall_sec or 'off'}s, "
                f"stop_on_request_hint={exploit_rewrite_stop_on_request_hint}, "
                f"reuse_without_ida={exploit_rewrite_reuse_without_ida}, "
                f"force_terminal_after_l0_timeout_loops={exploit_rewrite_force_terminal_after_l0_timeout_loops}, "
                f"force_stage_codex_after_unsolved_loops={exploit_rewrite_force_stage_codex_after_unsolved_loops}, "
                f"skip_force_stage_codex_on_timeout_error={exploit_rewrite_skip_force_stage_codex_on_timeout_error}, "
                f"reuse_existing_exp={exploit_stage_reuse_existing_exp}"
            )
        if auto_runtime_env:
            notes.append(
                "runtime alignment auto: "
                + f"loader={os.path.basename(str(auto_runtime_env.get('PWN_LOADER', '')))}, "
                + f"libc={os.path.basename(str(auto_runtime_env.get('PWN_LIBC_PATH', '')))}"
            )
            if str(auto_runtime_env.get("PWN_LIBC_PROFILE", "")).strip():
                notes.append(f"runtime libc profile hint: {str(auto_runtime_env.get('PWN_LIBC_PROFILE', '')).strip()}")
        if runtime_guard_rel:
            notes.append(f"runtime ABI guard: {runtime_guard_rel}")
        if bool(runtime_guard.get("selected_mismatch", False)):
            notes.append("runtime ABI guard blocked mismatched loader/libc injection")
        if runtime_profile_rel:
            notes.append(f"runtime profile saved: {runtime_profile_rel}")
        if stage_timeout_circuit_enabled:
            notes.append(
                "stage timeout circuit: on "
                + f"(stages={','.join(sorted(stage_timeout_circuit_stages)) or 'none'}, "
                + f"failures={','.join(sorted(stage_timeout_circuit_failure_categories)) or 'none'}, "
                + f"trigger={stage_timeout_circuit_consecutive_failures}, cooldown_loops={stage_timeout_circuit_cooldown_loops}, "
                + f"skip_only_if_terminal={stage_timeout_circuit_skip_only_if_terminal_in_plan}, "
                + f"require_exploit_enabled={stage_timeout_circuit_require_exploit_enabled})"
            )
        else:
            notes.append("stage timeout circuit: off")
        if codex_unhealthy_enabled:
            notes.append(
                "codex unhealthy cooldown: on "
                + f"(stages={','.join(sorted(codex_unhealthy_stages)) or 'none'}, "
                + f"failures={','.join(sorted(codex_unhealthy_failure_categories)) or 'none'}, "
                + f"trigger={codex_unhealthy_consecutive_failures}, cooldown_loops={codex_unhealthy_cooldown_loops}, "
                + f"skip_only_if_terminal={codex_unhealthy_skip_only_if_terminal_in_plan}, "
                + f"require_exploit_enabled={codex_unhealthy_require_exploit_enabled})"
            )
        else:
            notes.append("codex unhealthy cooldown: off")
        notes.append(
            f"exploit precheck: {'on' if exploit_precheck_enabled else 'off'}"
            + (
                f" (weak={','.join(sorted(exploit_precheck_weak_strategies)) or 'none'}, "
                f"terminal_only={exploit_precheck_terminal_stage_only}, "
                f"min_unsolved_loops={exploit_precheck_min_unsolved_loops}, "
                f"force_min_rewrite_after_weak_streak={exploit_precheck_force_minimal_rewrite_after_weak_streak})"
                if exploit_precheck_enabled
                else ""
            )
        )
        notes.append(
            "strategy route switch: "
            + (
                f"on (no_progress>={strategy_route_switch_no_progress_loops}, "
                f"terminal_unsolved>={strategy_route_switch_terminal_unsolved_loops}, "
                f"weak_only={strategy_route_switch_weak_only}, "
                f"reset_no_progress={strategy_route_switch_reset_no_progress}, "
                f"request_hint_after={strategy_route_switch_request_hint_after or 'off'})"
                if strategy_route_switch_enabled
                else "off"
            )
        )
        notes.append(
            "hint gate: "
            + (
                f"on (no_progress>={hint_gate_no_progress_loops or 'off'}, "
                f"no_new_evidence>={int(hint_gate_no_new_evidence_sec // 60) if hint_gate_no_new_evidence_sec > 0 else 'off'}m, "
                f"stop_on_trigger={hint_gate_stop_on_trigger})"
                if hint_gate_enabled
                else "off"
            )
        )
        notes.append(
            "blind mode policy: "
            + (
                f"on (skip_static={blind_mode_skip_static_stages}, "
                f"skip_mcp_health={blind_mode_skip_mcp_health_check}, "
                f"prefer_protocol_probe={blind_mode_prefer_protocol_semantic_probe}, "
                f"default_strategy={blind_mode_default_strategy_hint}, "
                f"route_lock={blind_mode_route_switch_lock})"
                if blind_mode_enabled
                else "off"
            )
        )
        notes.append(
            "timeout/no-evidence gate: "
            + (
                f"on (threshold={timeout_gate_consecutive_loops}, "
                f"require_no_progress={timeout_gate_require_no_progress}, "
                f"blind_only={timeout_gate_blind_only}, "
                f"stop_on_trigger={timeout_gate_stop_on_trigger})"
                if timeout_gate_enabled
                else "off"
            )
        )
        notes.append(
            "remote preflight gate: "
            + (
                "on(startup)"
                if (remote_preflight_enabled and remote_preflight_check_on_start)
                else ("on(lazy)" if remote_preflight_enabled else "off")
            )
        )
        if remote_preflight_enabled and remote_preflight_check_on_start:
            gate_ok, gate_report_rel, gate_detail = run_remote_target_preflight(
                state_path=args.state,
                session_id=sid,
                cfg=remote_preflight_cfg,
                notes=notes,
            )
            if gate_report_rel:
                notes.append(f"remote preflight report: {gate_report_rel}")
            if gate_detail and gate_ok:
                notes.append(f"remote preflight note: {gate_detail}")
            if not gate_ok:
                state_remote_gate = load_json(args.state)
                state_remote_gate.setdefault("session", {})["status"] = "remote_target_unavailable"
                state_remote_gate["session"]["last_error"] = f"remote preflight blocked: {gate_detail or 'unreachable'}"
                save_json(args.state, state_remote_gate)
                sync_meta_from_state(sid, state_remote_gate)
                return 6
        hard_preflight_ok, hard_preflight_report, hard_preflight_detail = run_mcp_hard_preflight(
            state_path=args.state,
            session_id=sid,
            health_cfg=mcp_health_cfg,
            codex_bin=codex_bin,
            notes=notes,
        )
        if hard_preflight_report:
            notes.append(f"mcp hard preflight report: {hard_preflight_report}")
        if hard_preflight_detail and hard_preflight_ok:
            notes.append(f"mcp hard preflight note: {hard_preflight_detail}")
        if not hard_preflight_ok:
            state_hard_gate = load_json(args.state)
            state_hard_gate.setdefault("session", {})["status"] = "mcp_health_failed"
            state_hard_gate["session"]["last_error"] = f"mcp hard preflight blocked: {hard_preflight_detail or 'invalid env'}"
            save_json(args.state, state_hard_gate)
            sync_meta_from_state(sid, state_hard_gate)
            return 5
        ident_pre_rel = write_binary_identity_report(
            state_path=args.state,
            session_id=sid,
            stage_tag="preflight",
            note="before mcp health check",
        )
        notes.append(f"binary identity checked: {ident_pre_rel}")
        skip_mcp_bootstrap_for_blind = bool(
            session_blind_mode and blind_mode_enabled and blind_mode_skip_mcp_health_check
        )
        if quick_strategy_applied:
            notes.append("quick shortcut active: skip MCP startup self-heal/health gate")
        elif skip_mcp_bootstrap_for_blind:
            notes.append("blind mode active: skip MCP startup self-heal/health gate")
        else:
            if bool(mcp_health_cfg.get("self_heal_on_start", True)):
                run_mcp_self_heal(
                    state_path=args.state,
                    session_id=sid,
                    loop_idx=0,
                    stage="preflight",
                    reason="startup preflight",
                    health_cfg=mcp_health_cfg,
                    codex_bin=codex_bin,
                    notes=notes,
                )
            health_ok = run_mcp_health_check(
                state_path=args.state,
                session_id=sid,
                health_cfg=mcp_health_cfg,
                codex_bin=codex_bin,
                notes=notes,
            )
            if not health_ok:
                sync_meta_from_state(sid, load_json(args.state))
                return 5

        if stage_cache_enabled and exploit_profile_cache_enabled and binary_sha256:
            state_for_xcache = load_json(args.state)
            x_hit, x_rel = apply_exploit_profile_cache(
                state_for_xcache,
                binary_sha256=binary_sha256,
                overwrite=exploit_profile_cache_overwrite,
            )
            if x_hit:
                state_for_xcache.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                    "cache_exploit_profile"
                ] = x_rel
                save_json(args.state, state_for_xcache)
                notes.append(f"exploit_profile cache hit: {x_rel}")

        requires_codex_runtime = any(exploit_stage_level(st) < 0 for st in stage_order) or (
            enable_exploit and exploit_run_codex
        )
        if quick_strategy_applied:
            requires_codex_runtime = False

        if (not codex_available) and requires_codex_runtime:
            msg = codex_runner_invalid_reason or f"codex command not found: {codex_bin}"
            if args.allow_codex_missing:
                notes.append(msg)
                restrict_to_l3 = bool(decision_cfg.get("restrict_to_l3_on_codex_missing", True))
                if restrict_to_l3:
                    fallback_stage = terminal_stage or "exploit_l3"
                    stage_order = [x for x in stage_order if x == fallback_stage]
                else:
                    notes.append("codex 缺失，但保持完整 stage plan（失败后继续由策略层处理）")
                state = load_json(args.state)
                state.setdefault("session", {})["status"] = "codex_unavailable"
                state["session"]["last_error"] = msg
                save_json(args.state, state)
            else:
                print(f"[run_session] {msg}", file=sys.stderr)
                return 3
        elif not codex_available:
            notes.append("codex 不可用，但当前 stage plan 不依赖 codex，继续执行本地 exploit 流程")

        for loop_idx in range(loop_start, loop_end):
            if max_wall_time_sec > 0:
                elapsed = time.monotonic() - run_started_monotonic
                if elapsed >= max_wall_time_sec:
                    fuse_triggered = True
                    fuse_reason = f"cost fuse hit: wall_time {elapsed:.1f}s >= {max_wall_time_sec:.1f}s"
                    notes.append(fuse_reason)
                    break

            stop_doc = read_stop_request(ROOT_DIR, sid)
            if stop_doc:
                stop_requested = True
                metrics.stop_requests += 1
                reason = str(stop_doc.get("reason", "")).strip() or "stop requested"
                notes.append(f"收到停止请求，终止自动推进: {reason}")
                state_stopped = load_json(args.state)
                state_stopped.setdefault("session", {})["status"] = "stopped"
                state_stopped["session"]["last_error"] = reason
                save_json(args.state, state_stopped)
                sync_meta_from_state(sid, state_stopped)
                break

            metrics.loops_total += 1

            before_loop_state = load_json(args.state)
            hypo_engine.apply_to_state(before_loop_state)
            cap_report_pre_rel = ""
            if bool(cap_cfg.get("enabled", True)):
                cap_inf_pre = infer_capabilities(before_loop_state, cap_cfg)
                if cap_inf_pre.changed:
                    metrics.capability_updates += 1
                cap_report_pre_rel = write_capability_report(
                    root_dir=ROOT_DIR,
                    session_id=sid,
                    loop_idx=loop_idx,
                    inf=cap_inf_pre,
                )
                before_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                    "capabilities_report"
                ] = cap_report_pre_rel
            pre_obj = evaluate_objectives(before_loop_state, objective_cfg, enable_exploit)
            apply_objective_state(before_loop_state, pre_obj.to_dict())
            save_json(args.state, before_loop_state)
            before_evid = len(before_loop_state.get("dynamic_evidence", {}).get("evidence", []) or [])
            before_hypos = len(before_loop_state.get("static_analysis", {}).get("hypotheses", []) or [])
            active_hids = hypo_engine.active_ids(before_loop_state)
            blind_mode_loop = bool(blind_mode_enabled and detect_blind_mode(before_loop_state))
            repl_cmd_exec_hint_loop = detect_repl_cmd_exec_hint(before_loop_state)
            nxoff_libc_free_hint_loop = detect_nxoff_libc_free_hint(before_loop_state)
            lua_runtime_hint_loop = detect_lua_runtime_exec_hint(before_loop_state)

            if (
                blind_mode_loop
                and enable_exploit
                and terminal_stage
                and blind_mode_prefer_protocol_semantic_probe
            ):
                exp_loop = before_loop_state.setdefault("session", {}).setdefault("exp", {})
                cur_hint_loop = _normalize_strategy_hint(exp_loop.get("strategy_hint", ""))
                if (
                    (not cur_hint_loop)
                    or (cur_hint_loop in {"ret2win", "ret2libc", "ret2shellcode", "direct_execve_shell", "rip_control_probe"})
                ):
                    forced_hint_loop = "js_shell_cmd_exec" if (lua_runtime_hint_loop or repl_cmd_exec_hint_loop) else blind_mode_default_strategy_hint
                    exp_loop["strategy_hint"] = forced_hint_loop
                    exp_loop["force_regen_once"] = True
                    exp_loop["strategy_switch_reason"] = "blind mode protocol/semantic preference"
                    exp_loop["strategy_switch_utc"] = utc_now()
                    save_json(args.state, before_loop_state)
                    loop_note = f"blind mode strategy_hint override -> {forced_hint_loop}"
                    notes.append(loop_note)

            if objective_enabled and objective_stop_on_achieved and pre_obj.target_achieved:
                if force_terminal_stage:
                    notes.append(f"目标已满足，但按策略强制推进至 {terminal_stage}")
                else:
                    notes.append("目标已满足，停止自动推进")
                    break

            loop_base_order = stage_order
            if objective_enabled and objective_stop_on_achieved and pre_obj.target_achieved and force_terminal_stage and terminal_stage:
                loop_base_order = [terminal_stage]
            if objective_enabled and objective_prioritize_missing and pre_obj.missing_stages:
                pri = [x for x in pre_obj.missing_stages if x in stage_order]
                if pri:
                    loop_base_order = pri + [x for x in stage_order if x not in pri]

            if unified_enabled:
                loop_stage_order = [str(x) for x in stage_order]
                loop_notes = ["unified_solve: fixed stage order"]
            else:
                loop_decision = choose_stage_plan(
                    base_stage_order=loop_base_order,
                    state=before_loop_state,
                    no_progress_loops=no_progress_loops,
                    decision_cfg=decision_cfg,
                    enable_exploit=enable_exploit,
                )
                loop_stage_order = loop_decision.stage_order
                loop_notes = list(loop_decision.notes)

            if blind_mode_loop and enable_exploit and terminal_stage and blind_mode_skip_static_stages:
                loop_stage_order = [terminal_stage]
                loop_notes.append("blind mode: terminal-only loop (skip recon/ida/gdb)")
            elif repl_cmd_exec_hint_loop and enable_exploit and terminal_stage:
                repl_plan: List[str] = []
                if (not blind_mode_loop) and ("gdb_evidence" in stage_order):
                    repl_plan.append("gdb_evidence")
                repl_plan.append(terminal_stage)
                loop_stage_order = list(dict.fromkeys([x for x in repl_plan if str(x).strip()]))
                if blind_mode_loop:
                    loop_notes.append("repl/cmd-exec hint (blind): prioritize terminal exploit, skip recon/ida/gdb")
                else:
                    loop_notes.append("repl/cmd-exec hint: prioritize gdb_evidence + terminal exploit, skip recon/ida")
            elif nxoff_libc_free_hint_loop and enable_exploit and terminal_stage:
                nxoff_plan: List[str] = []
                if (not blind_mode_loop) and ("gdb_evidence" in stage_order):
                    nxoff_plan.append("gdb_evidence")
                nxoff_plan.append(terminal_stage)
                loop_stage_order = list(dict.fromkeys([x for x in nxoff_plan if str(x).strip()]))
                if blind_mode_loop:
                    loop_notes.append("nx-off hint (blind): prioritize terminal exploit, skip recon/ida/gdb")
                else:
                    loop_notes.append("nx-off libc-free hint: prioritize gdb_evidence + terminal exploit, skip recon/ida")

            # 当 L0-L2 已完整可复用时，后续轮次优先仅推进终点 exploit，避免重复跑静态/动态证据阶段。
            if enable_exploit and terminal_stage and loop_idx > loop_start and l0_l2_ready(
                before_loop_state,
                allow_without_ida=exploit_rewrite_reuse_without_ida,
            ):
                loop_stage_order = [terminal_stage]
                if exploit_rewrite_reuse_without_ida and (not cache_patch_is_valid("ida_slice", before_loop_state)):
                    loop_notes.append("reuse L0+L2 evidence (ida fail-open): exploit-only loop")
                else:
                    loop_notes.append("reuse L0-L2 evidence: exploit-only loop")
            if (
                exploit_rewrite_enabled
                and enable_exploit
                and terminal_stage
                and exploit_rewrite_force_terminal_after_l0_timeout_loops > 0
                and l0_timeout_no_terminal_streak >= exploit_rewrite_force_terminal_after_l0_timeout_loops
            ):
                loop_stage_order = [terminal_stage]
                loop_notes.append(
                    "L0 timeout/mcp failures persisted; force terminal-only rewrite loop"
                )
            if force_terminal_stage:
                loop_stage_order = ensure_terminal_stage_last(loop_stage_order, terminal_stage)
            if objective_enabled and objective_prioritize_missing and pre_obj.missing_stages:
                loop_notes.append(f"objective 缺口优先: {','.join(pre_obj.missing_stages)}")

            if stage_timeout_circuit_enabled and enable_exploit and terminal_stage:
                static_hard_skipped: List[str] = []
                gdb_success = int(metrics.stage_success.get("gdb_evidence", 0) or 0)
                for st in ("recon", "ida_slice"):
                    attempts_now = int(metrics.stage_attempts.get(st, 0) or 0)
                    success_now = int(metrics.stage_success.get(st, 0) or 0)
                    failures_now = int(metrics.stage_failures.get(st, 0) or 0)
                    if attempts_now < 2:
                        continue
                    if success_now > 0:
                        continue
                    if failures_now < attempts_now:
                        continue
                    if (gdb_success <= 0) and (not repl_cmd_exec_hint_loop) and (not nxoff_libc_free_hint_loop):
                        continue
                    prev_remain = int(stage_timeout_skip_remaining.get(st, 0) or 0)
                    hard_cooldown = max(prev_remain, loop_end - loop_idx + 1)
                    stage_timeout_skip_remaining[st] = hard_cooldown
                    static_hard_skipped.append(
                        f"{st}(attempts={attempts_now},success=0,cooldown={hard_cooldown})"
                    )
                if static_hard_skipped:
                    loop_notes.append("static hard-skip armed: " + ", ".join(static_hard_skipped))

            force_stage_codex_this_loop = bool(exploit_run_codex)
            if (
                exploit_rewrite_enabled
                and enable_exploit
                and terminal_stage
                and exploit_rewrite_force_stage_codex_after_unsolved_loops > 0
                and terminal_unsolved_streak >= exploit_rewrite_force_stage_codex_after_unsolved_loops
            ):
                timeout_like_last_error = _is_timeout_like_error(exploit_rewrite_last_error)
                if exploit_rewrite_skip_force_stage_codex_on_timeout_error and timeout_like_last_error:
                    loop_notes.append(
                        "terminal unsolved streak reached, but last error is timeout-like; keep terminal local loop without forcing codex stage"
                    )
                else:
                    force_stage_codex_this_loop = True
                    loop_notes.append(
                        f"terminal unsolved streak={terminal_unsolved_streak}; enable terminal codex stage"
                    )

            if stage_timeout_circuit_enabled:
                allow_timeout_skip = True
                if stage_timeout_circuit_require_exploit_enabled and (not enable_exploit):
                    allow_timeout_skip = False
                if stage_timeout_circuit_skip_only_if_terminal_in_plan:
                    allow_timeout_skip = bool(terminal_stage and (terminal_stage in loop_stage_order))
                if allow_timeout_skip:
                    filtered_order: List[str] = []
                    skipped_now: List[str] = []
                    for st in loop_stage_order:
                        if st not in stage_timeout_circuit_stages:
                            filtered_order.append(st)
                            continue
                        remain = int(stage_timeout_skip_remaining.get(st, 0) or 0)
                        if remain <= 0:
                            filtered_order.append(st)
                            continue
                        remain_next = max(0, remain - 1)
                        stage_timeout_skip_remaining[st] = remain_next
                        metrics.timeout_circuit_skips += 1
                        skipped_now.append(f"{st}(remaining={remain_next})")
                    if skipped_now:
                        loop_notes.append("timeout circuit skip: " + ", ".join(skipped_now))
                    if filtered_order:
                        loop_stage_order = filtered_order
                    elif terminal_stage and enable_exploit:
                        loop_stage_order = [terminal_stage]
                        loop_notes.append("timeout circuit skipped all non-terminal stages; keep terminal only")
            if codex_unhealthy_enabled:
                allow_codex_skip = True
                if codex_unhealthy_require_exploit_enabled and (not enable_exploit):
                    allow_codex_skip = False
                if codex_unhealthy_skip_only_if_terminal_in_plan:
                    allow_codex_skip = bool(terminal_stage and (terminal_stage in loop_stage_order))
                if allow_codex_skip:
                    filtered_order = []
                    skipped_now = []
                    for st in loop_stage_order:
                        if st not in codex_unhealthy_stages:
                            filtered_order.append(st)
                            continue
                        remain = int(codex_unhealthy_skip_remaining.get(st, 0) or 0)
                        if remain <= 0:
                            filtered_order.append(st)
                            continue
                        remain_next = max(0, remain - 1)
                        codex_unhealthy_skip_remaining[st] = remain_next
                        skipped_now.append(f"{st}(remaining={remain_next})")
                    if skipped_now:
                        loop_notes.append("codex unhealthy cooldown skip: " + ", ".join(skipped_now))
                    if filtered_order:
                        loop_stage_order = filtered_order
                    elif terminal_stage and enable_exploit:
                        loop_stage_order = [terminal_stage]
                        loop_notes.append("codex unhealthy cooldown skipped all non-terminal stages; keep terminal only")

            bundle_active, bundle_trigger_stage, bundle_stages = detect_bundle_plan(
                loop_stage_order,
                enabled=bundle_l0_l2_enabled,
                include_exploit_stages=bundle_include_exploit_stages,
                require_consecutive=bundle_require_consecutive,
            )
            if bundle_active:
                label = "bundle_l0_l4" if bundle_include_exploit_stages else "bundle_l0_l2"
                loop_notes.append(f"{label} active: trigger={bundle_trigger_stage}")

            decision_report_rel = write_loop_decision_report(
                session_id=sid,
                loop_idx=loop_idx,
                plan=loop_stage_order,
                notes=loop_notes,
                active_hypothesis_ids=active_hids,
                mutation_manifest="",
            )
            before_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "decision_report"
            ] = decision_report_rel
            before_loop_state.setdefault("summary", {})["next_actions"] = loop_stage_order
            save_json(args.state, before_loop_state)

            loop_executed_stages: List[str] = []
            terminal_attempted_this_loop = False
            bundle_completed = False
            terminal_local_verified_this_loop = False
            terminal_last_error_this_loop = ""
            terminal_verify_report_this_loop = ""
            terminal_exp_path_this_loop = ""
            loop_l0_timeout_like_failure = False
            loop_rc124_failures = 0
            skip_static_stages_this_loop: Set[str] = set()
            before_exp_hash = ""
            after_exp_hash = ""
            if enable_exploit and terminal_stage:
                exp_rel_before = str(before_loop_state.get("session", {}).get("exp", {}).get("path", "")).strip()
                if exp_rel_before:
                    exp_abs_before = (
                        exp_rel_before
                        if os.path.isabs(exp_rel_before)
                        else os.path.abspath(os.path.join(ROOT_DIR, exp_rel_before))
                    )
                    if os.path.isfile(exp_abs_before):
                        try:
                            before_exp_hash = file_sha256(exp_abs_before)
                        except Exception:
                            before_exp_hash = ""

            for stage in loop_stage_order:
                if stage in skip_static_stages_this_loop:
                    loop_notes.append(f"{stage} skipped in-loop after prior static-stage timeout/mcp failure")
                    continue
                if max_wall_time_sec > 0:
                    elapsed_stage_gate = time.monotonic() - run_started_monotonic
                    if elapsed_stage_gate >= max_wall_time_sec:
                        fuse_triggered = True
                        fuse_reason = f"cost fuse hit: wall_time {elapsed_stage_gate:.1f}s >= {max_wall_time_sec:.1f}s"
                        notes.append(fuse_reason)
                        break

                stop_doc = read_stop_request(ROOT_DIR, sid)
                if stop_doc:
                    stop_requested = True
                    metrics.stop_requests += 1
                    reason = str(stop_doc.get("reason", "")).strip() or "stop requested"
                    notes.append(f"收到停止请求，终止当前轮次: {reason}")
                    state_stopped = load_json(args.state)
                    state_stopped.setdefault("session", {})["status"] = "stopped"
                    state_stopped["session"]["last_error"] = reason
                    save_json(args.state, state_stopped)
                    sync_meta_from_state(sid, state_stopped)
                    break

                loop_executed_stages.append(stage)
                stage_spec = get_stage_spec(stage_runner_cfg, stage)
                if exploit_stage_level(stage) >= 0 and (not bool(exp_verify_cfg.get("enabled", True))):
                    stage_spec["required_artifact_keys"] = [
                        k for k in stage_spec.get("required_artifact_keys", []) if k != "exp_verify_report"
                    ]
                stage_contract_hint = compact_hint_text(
                    stage_prompt_contract(stage_spec),
                    context_contract_hint_max_chars,
                )
                log_rel = f"artifacts/logs/run_session_{sid}_{loop_idx:02d}_{stage}.log"
                log_abs = os.path.join(ROOT_DIR, log_rel)
                stage_started_utc = utc_now()
                stage_started_monotonic = time.monotonic()
                run_bundle_now = bool(bundle_active and (stage == bundle_trigger_stage) and (not bundle_completed))
                skip_codex_due_bundle = bool(bundle_active and bundle_completed and (stage in bundle_stages) and (stage != bundle_trigger_stage))
                if run_bundle_now and bundle_stages:
                    hints = [stage_contract_hint]
                    for b_stage in bundle_stages:
                        if b_stage == stage:
                            continue
                        if exploit_stage_level(b_stage) >= 0:
                            # exploit 阶段由本地 exp plugin + verify 执行，不并入 MCP 提示约束。
                            continue
                        b_spec = get_stage_spec(stage_runner_cfg, b_stage)
                        hints.append(compact_hint_text(stage_prompt_contract(b_spec), context_contract_hint_max_chars))
                    stage_contract_hint = " ".join([x for x in hints if str(x).strip()])

                before = load_json(args.state)
                before_rel = write_tx_snapshot(sid, loop_idx, stage, "before", before)
                session = before.setdefault("session", {})
                session["status"] = f"running:{stage}"
                save_json(args.state, before)
                sync_meta_from_state(sid, before)

                metrics.bump_stage_attempt(stage)

                ok = True
                rc = 0
                err = ""
                contract_errors: List[str] = []
                failure_report_rel = ""
                mutation_manifest_rel = ""
                mutation_items: List[Dict[str, Any]] = []
                failure_category = ""
                failure_recoverable = False
                attempt_records: List[Dict[str, Any]] = []
                attempt_no = 1
                stage_spec_errors: List[str] = []
                exp_verify_ok = True
                exp_verify_report = ""
                exp_autofix_attempts = 0
                exp_autofix_last_error = ""
                stage_cache_hit = False
                stage_cache_rel = ""
                cache_saved_rel = ""
                cache_fallback_used = False
                direct_stage_done = False
                mcp_forced_retry_used = False

                if stage == "gdb_evidence" and (not skip_codex_due_bundle):
                    state_for_mut = load_json(args.state)
                    mutation_manifest_rel, mutation_items = prepare_mutation_inputs(
                        state=state_for_mut,
                        session_id=sid,
                        loop_idx=loop_idx,
                        mutation_cfg=mutation_cfg,
                    )
                    if mutation_manifest_rel:
                        save_json(args.state, state_for_mut)
                        metrics.mutations_generated += len(mutation_items)
                        append_file(
                            log_abs,
                            f"[run_session] generated mutation inputs: {len(mutation_items)} manifest={mutation_manifest_rel}\n",
                        )
                        decision_report_rel = write_loop_decision_report(
                            session_id=sid,
                            loop_idx=loop_idx,
                            plan=loop_stage_order,
                            notes=loop_notes,
                            active_hypothesis_ids=active_hids,
                            mutation_manifest=mutation_manifest_rel,
                        )

                while True:
                    ok = True
                    rc = 0
                    err = ""
                    contract_errors = []
                    validate_failed = False
                    verifier_failed = False

                    append_file(log_abs, f"[run_session] attempt={attempt_no}\n")

                    if max_wall_time_sec > 0:
                        elapsed_retry_gate = time.monotonic() - run_started_monotonic
                        if elapsed_retry_gate >= max_wall_time_sec:
                            ok = False
                            rc = 68
                            err = f"cost fuse hit: wall_time {elapsed_retry_gate:.1f}s >= {max_wall_time_sec:.1f}s"
                            fuse_triggered = True
                            fuse_reason = err
                            append_file(log_abs, f"[run_session] {err}\n")

                    if (
                        ok
                        and attempt_no == 1
                        and stage_cache_enabled
                        and (stage in stage_cache_stages_set)
                        and (exploit_stage_level(stage) < 0)
                        and (not run_bundle_now)
                    ):
                        state_for_cache = load_json(args.state)
                        stage_cache_hit, stage_cache_rel = apply_stage_cache(
                            stage=stage,
                            state=state_for_cache,
                            binary_sha256=binary_sha256,
                            overwrite=stage_cache_overwrite,
                        )
                        if stage_cache_hit:
                            make_cache_hit_artifacts(state_for_cache, sid, loop_idx, stage, stage_cache_rel)
                            state_for_cache.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                                f"cache_hit_{stage}"
                            ] = stage_cache_rel
                            save_json(args.state, state_for_cache)
                            append_file(log_abs, f"[run_session] cache hit: stage={stage} cache={stage_cache_rel}\n")
                        else:
                            # Fast-path: if current state already has valid stage outputs, skip recon/ida reruns.
                            reuse_reason = stage_state_reuse_reason(stage, state_for_cache, sid)
                            if reuse_reason:
                                stage_cache_hit = True
                                stage_cache_rel = reuse_reason
                                make_cache_hit_artifacts(state_for_cache, sid, loop_idx, stage, stage_cache_rel)
                                state_for_cache.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                                    f"cache_hit_{stage}"
                                ] = stage_cache_rel
                                save_json(args.state, state_for_cache)
                                append_file(
                                    log_abs,
                                    f"[run_session] state reuse hit: stage={stage} source={stage_cache_rel}\n",
                                )

                    stage_needs_mcp = bool(
                        (exploit_stage_level(stage) < 0) and (not stage_cache_hit) and (not skip_codex_due_bundle)
                    )
                    if (
                        ok
                        and ida_pre_stage_self_heal
                        and stage_needs_mcp
                        and stage == "ida_slice"
                        and attempt_no == 1
                        and codex_available
                    ):
                        pre_heal_rel = run_mcp_self_heal(
                            state_path=args.state,
                            session_id=sid,
                            loop_idx=loop_idx,
                            stage="ida_slice_pre",
                            reason="ida pre-stage lock cleanup",
                            health_cfg=mcp_health_cfg,
                            codex_bin=codex_bin,
                            notes=None,
                        )
                        if pre_heal_rel:
                            append_file(log_abs, f"[run_session] ida pre-stage self-heal -> {pre_heal_rel}\n")
                    if (
                        ok
                        and mcp_stage_gate_enabled
                        and stage_needs_mcp
                        and (stage in mcp_stage_gate_stage_set)
                        and codex_available
                    ):
                        gate_ok, gate_report_rel, gate_detail = run_stage_mcp_gate(
                            state_path=args.state,
                            session_id=sid,
                            loop_idx=loop_idx,
                            stage=stage,
                            health_cfg=mcp_health_cfg,
                            codex_bin=codex_bin,
                        )
                        append_file(
                            log_abs,
                            f"[run_session] mcp_gate stage={stage} ok={gate_ok} report={gate_report_rel}"
                            + (f" detail={gate_detail}" if gate_detail else "")
                            + "\n",
                        )
                        if (not gate_ok) and mcp_stage_gate_fail_fast:
                            ok = False
                            rc = 69
                            err = (
                                f"mcp unavailable before stage {stage}: "
                                f"{gate_detail or 'required servers not listed'}"
                            )

                    if ok and run_validate:
                        rc = run_script(
                            [
                                sys.executable,
                                os.path.join(ROOT_DIR, "scripts", "validate_state.py"),
                                "--state",
                                args.state,
                                "--schema",
                                args.schema,
                            ],
                            log_abs,
                        )
                        if rc != 0:
                            ok = False
                            err = "validate_state failed"
                            validate_failed = True
                            metrics.validate_state_failures += 1

                    if (
                        ok
                        and (stage == "gdb_evidence")
                        and hard_step_enabled
                        and hard_step_direct_gdb_probe
                        and (not repl_cmd_exec_hint_loop)
                        and (not stage_cache_hit)
                        and (not skip_codex_due_bundle)
                    ):
                        direct_cmd = [
                            sys.executable,
                            os.path.join(ROOT_DIR, "scripts", "gdb_direct_probe.py"),
                            "--state",
                            args.state,
                            "--session-id",
                            sid,
                            "--loop",
                            str(loop_idx),
                            "--timeout-sec",
                            str(min(20, int(timeout_cfg.get(stage, default_stage_timeout) or default_stage_timeout))),
                        ]
                        rc_direct = run_script(direct_cmd, log_abs)
                        if rc_direct == 0:
                            direct_stage_done = True
                            append_file(log_abs, "[run_session] gdb direct probe completed\n")
                        else:
                            append_file(
                                log_abs,
                                f"[run_session] gdb direct probe failed rc={rc_direct}; fallback to codex\n",
                            )

                    if ok and exploit_stage_level(stage) >= 0:
                        plugin_outcome = _run_exploit_plugin_stage_impl(
                            state_path=args.state,
                            session_id=sid,
                            loop_idx=loop_idx,
                            metrics=metrics,
                            exploit_stage_reuse_existing_exp=exploit_stage_reuse_existing_exp,
                            exploit_rewrite_enabled=exploit_rewrite_enabled,
                            load_json_fn=load_json,
                            save_json_fn=save_json,
                            append_file_fn=append_file,
                            log_abs=log_abs,
                            manual_exp_regen_locked_fn=_manual_exp_regen_locked,
                            run_exp_plugin_fn=run_exp_plugin,
                            ensure_exploit_artifact_links_fn=ensure_exploit_artifact_links,
                        )
                        ok = plugin_outcome.ok
                        err = plugin_outcome.err
                        if not ok:
                            rc = 1

                    should_run_codex = (exploit_stage_level(stage) < 0) or force_stage_codex_this_loop
                    if stage_cache_hit or skip_codex_due_bundle:
                        should_run_codex = False
                    if direct_stage_done:
                        should_run_codex = False
                    if ok and codex_available and should_run_codex:
                        state_now = load_json(args.state)
                        active_hids_now = hypo_engine.active_ids(state_now) if context_include_hypothesis_ids else []
                        codex_outcome = _run_stage_codex_impl(
                            state_path=args.state,
                            state_now=state_now,
                            session_id=sid,
                            loop_idx=loop_idx,
                            stage=stage,
                            log_abs=log_abs,
                            log_rel=log_rel,
                            allow_remote_exp=allow_remote_exp,
                            run_bundle_now=run_bundle_now,
                            bundle_include_exploit_stages=bundle_include_exploit_stages,
                            repl_cmd_exec_hint_loop=repl_cmd_exec_hint_loop,
                            nxoff_libc_free_hint_loop=nxoff_libc_free_hint_loop,
                            context_include_state_digest=context_include_state_digest,
                            context_mode=context_mode,
                            context_include_hypothesis_ids=context_include_hypothesis_ids,
                            context_include_mutations=context_include_mutations,
                            active_hids_now=active_hids_now,
                            mutation_manifest_rel=mutation_manifest_rel,
                            mutation_items=mutation_items,
                            stage_contract_hint=stage_contract_hint,
                            timeout_cfg=timeout_cfg,
                            default_stage_timeout=default_stage_timeout,
                            max_codex_calls=max_codex_calls,
                            max_prompt_chars=max_prompt_chars,
                            exploit_stage_codex_disable_mcp=exploit_stage_codex_disable_mcp,
                            hard_step_enabled=hard_step_enabled and (exploit_stage_level(stage) < 0),
                            hard_step_blocked_tools=list(hard_step_blocked_tools),
                            hard_step_stage_block_extra=list(hard_step_stage_block_extra.get(stage, [])),
                            hard_step_enforce_allowed_tools=hard_step_enforce_allowed_tools,
                            stage_tools_raw=stage_spec.get("mcp_tools", []),
                            hard_step_stage_allow_extra=list(hard_step_stage_allow_extra.get(stage, [])),
                            hard_step_stage_max=int(hard_step_stage_max.get(stage, hard_step_default_max_tool_calls) or 0),
                            hard_step_default_max_tool_calls=hard_step_default_max_tool_calls,
                            metrics=metrics,
                            adapter=adapter,
                            stage_request_cls=StageRequest,
                            root_dir=ROOT_DIR,
                            build_stage_prompt_fn=build_stage_prompt,
                            state_digest_fn=state_digest,
                            exploit_stage_level_fn=exploit_stage_level,
                            try_recover_recon_from_log_fn=try_recover_recon_from_log,
                            try_recover_ida_from_log_fn=try_recover_ida_from_log,
                            detect_stage_log_signature_fn=detect_stage_log_signature,
                            append_file_fn=append_file,
                        )
                        ok = codex_outcome.ok
                        rc = codex_outcome.rc
                        err = codex_outcome.err
                        if codex_outcome.fuse_triggered:
                            fuse_triggered = True
                            fuse_reason = codex_outcome.fuse_reason
                        if codex_outcome.bundle_completed:
                            bundle_completed = True
                    elif ok and codex_available and (not should_run_codex):
                        if stage_cache_hit:
                            append_file(log_abs, f"[run_session] skip codex for {stage}: cache hit {stage_cache_rel}\n")
                        elif skip_codex_due_bundle:
                            append_file(log_abs, f"[run_session] skip codex for {stage}: bundled by {bundle_trigger_stage}\n")
                        else:
                            append_file(log_abs, f"[run_session] skip codex for {stage} by automation.exploit_stage.run_codex=false\n")
                    elif ok and not codex_available and exploit_stage_level(stage) < 0:
                        ok = False
                        rc = 127
                        err = f"codex missing, skipped stage {stage}"
                        append_file(log_abs, err + "\n")
                    elif ok and not codex_available and exploit_stage_level(stage) >= 0:
                        append_file(log_abs, f"[run_session] codex missing, {stage} runs with local exp plugin only\n")

                    after = load_json(args.state)
                    if ok:
                        ensure_counter_progress(before, after, stage)
                        if stage == "ida_slice":
                            hypo_engine.apply_to_state(after)
                            metrics.hypotheses_added = len(after.get("static_analysis", {}).get("hypotheses", []) or [])
                        if stage == "gdb_evidence":
                            cluster_path, clusters = write_clusters(after, sid)
                            append_file(log_abs, f"[run_session] crash clusters -> {cluster_path}\n")
                            off_hint = _apply_gdb_offset_hint(after)
                            if off_hint > 0:
                                append_file(log_abs, f"[run_session] gdb offset_to_rip hint -> {off_hint}\n")
                            metrics.evidence_added = len(after.get("dynamic_evidence", {}).get("evidence", []) or [])
                            metrics.crash_clusters = len(clusters)
                        if exploit_stage_level(stage) >= 0:
                            precheck_outcome = _run_terminal_exploit_precheck_impl(
                                after_state=after,
                                state_path=args.state,
                                session_id=sid,
                                loop_idx=loop_idx,
                                stage=stage,
                                terminal_stage=terminal_stage,
                                terminal_unsolved_streak=terminal_unsolved_streak,
                                exploit_precheck_enabled=exploit_precheck_enabled,
                                exploit_precheck_terminal_stage_only=exploit_precheck_terminal_stage_only,
                                exploit_precheck_min_unsolved_loops=exploit_precheck_min_unsolved_loops,
                                exploit_precheck_weak_strategies=set(exploit_precheck_weak_strategies),
                                exploit_run_codex=exploit_run_codex,
                                exploit_precheck_force_minimal_rewrite_after_weak_streak=exploit_precheck_force_minimal_rewrite_after_weak_streak,
                                weak_closure_precheck_streak=weak_closure_precheck_streak,
                                metrics=metrics,
                                log_abs=log_abs,
                                save_json_fn=save_json,
                                load_json_fn=load_json,
                                append_file_fn=append_file,
                                evaluate_terminal_exploit_precheck_fn=evaluate_terminal_exploit_precheck,
                                choose_forced_minimal_strategy_hint_fn=choose_forced_minimal_strategy_hint,
                                manual_exp_regen_locked_fn=_manual_exp_regen_locked,
                                run_exp_plugin_fn=run_exp_plugin,
                                write_exploit_precheck_report_fn=write_exploit_precheck_report,
                            )
                            after = precheck_outcome.after_state
                            precheck_reason = precheck_outcome.precheck_reason
                            precheck_detail = precheck_outcome.precheck_detail
                            precheck_report_rel = precheck_outcome.precheck_report_rel
                            weak_closure_precheck_streak = precheck_outcome.weak_closure_precheck_streak
                            if precheck_reason:
                                exp_verify_ok = False
                                exp_verify_report = precheck_report_rel
                                exp_verify_err = f"non-fixable verify error ({precheck_reason})"
                            else:
                                exp_verify_ok, exp_verify_report, exp_verify_err = run_exp_verify(
                                    state_path=args.state,
                                    session_id=sid,
                                    loop_idx=loop_idx,
                                    verify_cfg=exp_verify_cfg,
                                    log_path=log_abs,
                                )
                            after = sync_exp_verify_artifacts(
                                state_path=args.state,
                                session_id=sid,
                                loop_idx=loop_idx,
                                exp_verify_report=exp_verify_report,
                            )
                            local_verified = bool(after.get("session", {}).get("exp", {}).get("local_verify_passed", False))
                            if local_verified:
                                metrics.exploit_success += 1
                                if stage_cache_enabled and exploit_profile_cache_enabled and binary_sha256:
                                    rel_prof = save_exploit_profile_cache(after, binary_sha256)
                                    if rel_prof:
                                        after.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                                            "cache_exploit_profile"
                                        ] = rel_prof

                            autofix_outcome = _run_exploit_autofix_impl(
                                state_path=args.state,
                                session_id=sid,
                                loop_idx=loop_idx,
                                stage=stage,
                                after_state=after,
                                local_verified=local_verified,
                                precheck_reason=precheck_reason,
                                exp_verify_ok=exp_verify_ok,
                                exp_verify_report=exp_verify_report,
                                exp_verify_err=exp_verify_err,
                                exp_autofix_attempts=exp_autofix_attempts,
                                exp_autofix_last_error=exp_autofix_last_error,
                                exploit_autofix_enabled=exploit_autofix_enabled,
                                exploit_autofix_force_until_success=exploit_autofix_force_until_success,
                                exploit_autofix_until_success=exploit_autofix_until_success,
                                exploit_autofix_max_attempts=exploit_autofix_max_attempts,
                                exploit_autofix_run_codex_fix=exploit_autofix_run_codex_fix,
                                exploit_autofix_codex_timeout_sec=exploit_autofix_codex_timeout_sec,
                                exploit_autofix_timeout_backoff_sec=exploit_autofix_timeout_backoff_sec,
                                exploit_autofix_max_timeout_sec=exploit_autofix_max_timeout_sec,
                                exploit_autofix_stop_on_consecutive_timeout=exploit_autofix_stop_on_consecutive_timeout,
                                exploit_autofix_max_error_chars=exploit_autofix_max_error_chars,
                                exploit_autofix_source_snippet_chars=exploit_autofix_source_snippet_chars,
                                exploit_autofix_disable_mcp=exploit_autofix_disable_mcp,
                                exploit_profile_cache_enabled=exploit_profile_cache_enabled,
                                stage_cache_enabled=stage_cache_enabled,
                                binary_sha256=binary_sha256,
                                stage_timeout_default=int(timeout_cfg.get(stage, 60) or 60),
                                max_autofix_rounds=max_autofix_rounds,
                                max_codex_calls=max_codex_calls,
                                max_prompt_chars=max_prompt_chars,
                                codex_available=codex_available,
                                metrics=metrics,
                                adapter=adapter,
                                stage_request_cls=StageRequest,
                                load_json_fn=load_json,
                                save_json_fn=save_json,
                                append_file_fn=append_file,
                                read_verify_report_detail_fn=_read_verify_report_detail,
                                classify_verify_autofix_block_reason_fn=classify_verify_autofix_block_reason,
                                read_exp_source_snippet_fn=_read_exp_source_snippet,
                                build_exploit_autofix_prompt_fn=build_exploit_autofix_prompt,
                                run_exp_verify_fn=lambda **kwargs: run_exp_verify(
                                    state_path=kwargs["state_path"],
                                    session_id=kwargs["session_id"],
                                    loop_idx=kwargs["loop_idx"],
                                    verify_cfg=exp_verify_cfg,
                                    log_path=kwargs["log_path"],
                                ),
                                sync_exp_verify_artifacts_fn=sync_exp_verify_artifacts,
                                save_exploit_profile_cache_fn=save_exploit_profile_cache,
                                log_abs=log_abs,
                                bin_path=str(after.get("challenge", {}).get("binary_path", "")).strip(),
                                root_dir=ROOT_DIR,
                            )
                            after = autofix_outcome.after_state
                            local_verified = autofix_outcome.local_verified
                            exp_verify_ok = autofix_outcome.exp_verify_ok
                            exp_verify_report = autofix_outcome.exp_verify_report
                            exp_verify_err = autofix_outcome.exp_verify_err
                            exp_autofix_attempts = autofix_outcome.exp_autofix_attempts
                            exp_autofix_last_error = autofix_outcome.exp_autofix_last_error
                            if autofix_outcome.fuse_triggered:
                                fuse_triggered = True
                                fuse_reason = autofix_outcome.fuse_reason
                            must_pass_verify = bool(exp_verify_cfg.get("strict", False))
                            if exploit_autofix_enabled and exploit_autofix_require_success:
                                must_pass_verify = True
                            if (not local_verified) and must_pass_verify:
                                ok = False
                                rc = rc or 67
                                tail = exp_autofix_last_error or exp_verify_err
                                err = f"local exp verify failed: {tail}"
                                append_file(log_abs, f"[run_session] {err}\n")
                            exp_verify_ok = local_verified
                            if stage == terminal_stage:
                                terminal_local_verified_this_loop = bool(local_verified)
                                terminal_last_error_this_loop = str(
                                    exp_autofix_last_error or exp_verify_err or err
                                ).strip()
                                terminal_verify_report_this_loop = str(exp_verify_report or "").strip()
                                terminal_exp_path_this_loop = str(
                                    after.get("session", {}).get("exp", {}).get("path", "")
                                ).strip()

                        stage_post_validation = _run_stage_post_validation_impl(
                            state_path=args.state,
                            session_id=sid,
                            loop_idx=loop_idx,
                            stage=stage,
                            log_rel=log_rel,
                            log_abs=log_abs,
                            after_state=after,
                            ok=ok,
                            rc=rc,
                            err=err,
                            run_bundle_now=run_bundle_now,
                            bundle_stages=list(bundle_stages),
                            stage_cache_enabled=stage_cache_enabled,
                            binary_sha256=binary_sha256,
                            stage_cache_stages_set=set(stage_cache_stages_set),
                            run_verifier=run_verifier,
                            schema_path=args.schema,
                            budget_path=args.budget,
                            contracts=contracts,
                            root_dir=ROOT_DIR,
                            python_executable=sys.executable,
                            load_json_fn=load_json,
                            save_json_fn=save_json,
                            append_file_fn=append_file,
                            normalize_latest_artifact_keys_fn=normalize_latest_artifact_keys,
                            write_symbol_map_artifact_fn=write_symbol_map_artifact,
                            validate_stage_contract_fn=validate_stage_contract,
                            exploit_stage_level_fn=exploit_stage_level,
                            save_stage_cache_fn=save_stage_cache,
                            run_script_fn=run_script,
                        )
                        after = stage_post_validation.after_state
                        ok = stage_post_validation.ok
                        rc = stage_post_validation.rc
                        err = stage_post_validation.err
                        contract_errors = stage_post_validation.contract_errors
                        cache_saved_rel = stage_post_validation.cache_saved_rel
                        verifier_failed = stage_post_validation.verifier_failed
                        if verifier_failed:
                            metrics.verifier_failures += 1

                    if _should_use_cache_fallback_impl(
                        ok=ok,
                        stage_cache_hit=stage_cache_hit,
                        cache_fallback_used=cache_fallback_used,
                    ):
                        cache_fallback_used = True
                        append_file(log_abs, "[run_session] cache hit 验证失败，回退到实时 MCP 路径重试\n")
                        stage_cache_hit = False
                        stage_cache_rel = ""
                        save_json(args.state, before)
                        attempt_no += 1
                        continue

                    attempt_finalize = _finalize_attempt_impl(
                        ok=ok,
                        rc=rc,
                        err=err,
                        contract_errors=contract_errors,
                        validate_failed=validate_failed,
                        verifier_failed=verifier_failed,
                        fuse_triggered=fuse_triggered,
                        stage=stage,
                        attempt_no=attempt_no,
                        attempt_records=attempt_records,
                        mcp_forced_retry_used=mcp_forced_retry_used,
                        codex_available=codex_available,
                        recovery_cfg=recovery_cfg,
                        state_path=args.state,
                        session_id=sid,
                        loop_idx=loop_idx,
                        health_cfg=mcp_health_cfg,
                        codex_bin=codex_bin,
                        log_abs=log_abs,
                        metrics=metrics,
                        classify_failure_fn=classify_failure,
                        utc_now_fn=utc_now,
                        evaluate_attempt_retry_policy_fn=_evaluate_attempt_retry_policy_impl,
                        should_retry_fn=should_retry,
                        next_backoff_seconds_fn=next_backoff_seconds,
                        run_mcp_self_heal_fn=run_mcp_self_heal,
                        append_file_fn=append_file,
                        sleep_fn=time.sleep,
                    )
                    failure_category = attempt_finalize.failure_category
                    failure_recoverable = attempt_finalize.failure_recoverable
                    mcp_forced_retry_used = attempt_finalize.mcp_forced_retry_used
                    if attempt_finalize.should_continue:
                        attempt_no = attempt_finalize.next_attempt_no
                        continue
                    if attempt_finalize.should_break:
                        break

                stage_spec_outcome = _apply_stage_spec_check_impl(
                    ok=ok,
                    rc=rc,
                    err=err,
                    stage=stage,
                    state_path=args.state,
                    session_id=sid,
                    loop_idx=loop_idx,
                    stage_log_rel=log_rel,
                    log_abs=log_abs,
                    is_exploit_stage=bool(exploit_stage_level(stage) >= 0),
                    exp_verify_report=exp_verify_report,
                    failure_category=failure_category,
                    failure_recoverable=failure_recoverable,
                    load_json_fn=load_json,
                    append_file_fn=append_file,
                    normalize_latest_artifact_keys_fn=normalize_latest_artifact_keys,
                    ensure_exploit_artifact_links_fn=ensure_exploit_artifact_links,
                    validate_stage_runner_spec_fn=validate_stage_runner_spec,
                    stage_spec=stage_spec,
                )
                ok = stage_spec_outcome.ok
                rc = stage_spec_outcome.rc
                err = stage_spec_outcome.err
                stage_spec_errors = stage_spec_outcome.stage_spec_errors
                failure_category = stage_spec_outcome.failure_category
                failure_recoverable = stage_spec_outcome.failure_recoverable

                stage_state_outcome = _apply_stage_result_state_impl(
                    state_path=args.state,
                    stage=stage,
                    ok=ok,
                    rc=rc,
                    err=err,
                    contract_errors=contract_errors,
                    failure_category=failure_category,
                    metrics=metrics,
                    loop_rc124_failures=loop_rc124_failures,
                    load_json_fn=load_json,
                    save_json_fn=save_json,
                    sync_meta_fn=sync_meta_from_state,
                    session_id=sid,
                )
                loop_rc124_failures = stage_state_outcome.loop_rc124_failures

                stage_finalize = _finalize_stage_post_run_impl(
                    state_path=args.state,
                    session_id=sid,
                    loop_idx=loop_idx,
                    stage=stage,
                    log_rel=log_rel,
                    ok=ok,
                    rc=rc,
                    err=err,
                    contract_errors=contract_errors,
                    attempt_records=attempt_records,
                    stage_spec_errors=stage_spec_errors,
                    failure_category=failure_category,
                    failure_recoverable=failure_recoverable,
                    before_snapshot_rel=before_rel,
                    stage_started_utc=stage_started_utc,
                    stage_started_monotonic=stage_started_monotonic,
                    is_exploit_stage=bool(exploit_stage_level(stage) >= 0),
                    exp_verify_ok=exp_verify_ok,
                    exp_verify_report=exp_verify_report,
                    exp_autofix_attempts=exp_autofix_attempts,
                    exp_autofix_last_error=exp_autofix_last_error,
                    stage_cache_hit=stage_cache_hit,
                    stage_cache_ref=stage_cache_rel,
                    stage_cache_saved=cache_saved_rel,
                    bundled=bool(run_bundle_now or skip_codex_due_bundle),
                    kpi_enabled=kpi_enabled,
                    metrics=metrics,
                    per_session_abs=per_session_abs,
                    global_kpi_abs=global_kpi_abs,
                    decision_report_rel=decision_report_rel,
                    mutation_manifest_rel=mutation_manifest_rel,
                    load_json_fn=load_json,
                    save_json_fn=save_json,
                    utc_now_fn=utc_now,
                    monotonic_now_fn=time.monotonic,
                    build_failure_context_fn=build_failure_context,
                    build_stage_tx_meta_doc_fn=_build_stage_tx_meta_doc_impl,
                    write_tx_snapshot_fn=write_tx_snapshot,
                    write_tx_meta_fn=write_tx_meta,
                    root_dir=ROOT_DIR,
                    stage_spec=stage_spec,
                    write_stage_receipt_fn=write_stage_receipt,
                    register_stage_receipt_fn=register_stage_receipt,
                    write_failure_report_fn=write_failure_report,
                    update_stage_timing_state_fn=update_stage_timing_state,
                    write_realtime_kpi_snapshot_fn=write_realtime_kpi_snapshot,
                    build_stage_result_record_fn=_build_stage_result_record_impl,
                )
                stage_results.append(stage_finalize.stage_result)
                post_stage_flow = _apply_post_stage_flow_impl(
                    ok=ok,
                    stage=stage,
                    err=err,
                    log_rel=log_rel,
                    log_abs=log_abs,
                    state_path=args.state,
                    session_id=sid,
                    loop_idx=loop_idx,
                    loop_end=loop_end,
                    terminal_stage=terminal_stage,
                    loop_stage_order=list(loop_stage_order),
                    stop_on_stage_failure=stop_on_stage_failure,
                    fuse_triggered=fuse_triggered,
                    force_terminal_stage=force_terminal_stage,
                    exploit_rewrite_enabled=exploit_rewrite_enabled,
                    enable_exploit=enable_exploit,
                    failure_category=failure_category,
                    loop_l0_timeout_like_failure=loop_l0_timeout_like_failure,
                    skip_static_stages_this_loop=skip_static_stages_this_loop,
                    notes=notes,
                    metrics=metrics,
                    stage_timeout_circuit_enabled=stage_timeout_circuit_enabled,
                    stage_timeout_circuit_stages=set(stage_timeout_circuit_stages),
                    stage_timeout_circuit_failure_categories=set(stage_timeout_circuit_failure_categories),
                    stage_timeout_failure_streak=stage_timeout_failure_streak,
                    stage_timeout_skip_remaining=stage_timeout_skip_remaining,
                    stage_timeout_circuit_consecutive_failures=stage_timeout_circuit_consecutive_failures,
                    stage_timeout_circuit_cooldown_loops=stage_timeout_circuit_cooldown_loops,
                    codex_unhealthy_enabled=codex_unhealthy_enabled,
                    codex_unhealthy_stages=set(codex_unhealthy_stages),
                    codex_unhealthy_failure_categories=set(codex_unhealthy_failure_categories),
                    codex_unhealthy_failure_streak=codex_unhealthy_failure_streak,
                    codex_unhealthy_skip_remaining=codex_unhealthy_skip_remaining,
                    codex_unhealthy_consecutive_failures=codex_unhealthy_consecutive_failures,
                    codex_unhealthy_cooldown_loops=codex_unhealthy_cooldown_loops,
                    ida_fail_open_enabled=ida_fail_open_enabled,
                    ida_fail_open_categories=set(ida_fail_open_categories),
                    ida_fail_open_write_blocker=ida_fail_open_write_blocker,
                    auto_continue_mcp_failure_set=set(auto_continue_mcp_failure_set),
                    append_file_fn=append_file,
                    write_ida_dual_evidence_bundle_fn=write_ida_dual_evidence_bundle,
                    write_ida_blocker_report_fn=write_ida_blocker_report,
                )
                loop_l0_timeout_like_failure = post_stage_flow.loop_l0_timeout_like_failure
                terminal_attempted_this_loop = bool(
                    terminal_attempted_this_loop or post_stage_flow.terminal_attempted_this_loop
                )
                if post_stage_flow.should_continue:
                    continue
                if post_stage_flow.should_break:
                    break

            after_loop_state = load_json(args.state)
            if fuse_triggered:
                after_loop_state.setdefault("session", {})["status"] = "fused"
                if fuse_reason:
                    after_loop_state["session"]["last_error"] = fuse_reason
                save_json(args.state, after_loop_state)
                sync_meta_from_state(sid, after_loop_state)
                break

            if bool(cap_cfg.get("enabled", True)):
                cap_inf_post = infer_capabilities(after_loop_state, cap_cfg)
                if cap_inf_post.changed:
                    metrics.capability_updates += 1
                cap_report_post_rel = write_capability_report(
                    root_dir=ROOT_DIR,
                    session_id=sid,
                    loop_idx=loop_idx,
                    inf=cap_inf_post,
                )
                after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                    "capabilities_report"
                ] = cap_report_post_rel
            post_obj = evaluate_objectives(after_loop_state, objective_cfg, enable_exploit)
            objective_report_rel = write_objective_report(
                root_dir=ROOT_DIR,
                session_id=sid,
                loop_idx=loop_idx,
                pre_eval=pre_obj,
                post_eval=post_obj,
                planned_stages=loop_stage_order,
                executed_stages=loop_executed_stages,
            )

            after_loop_state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                "objective_report"
            ] = objective_report_rel
            apply_objective_state(after_loop_state, post_obj.to_dict(), objective_report_rel)

            if stop_requested:
                save_json(args.state, after_loop_state)
                sync_meta_from_state(sid, after_loop_state)
                break

            after_evid = len(after_loop_state.get("dynamic_evidence", {}).get("evidence", []) or [])
            after_hypos = len(after_loop_state.get("static_analysis", {}).get("hypotheses", []) or [])
            loop_exp_hash_changed = False
            if enable_exploit and terminal_stage:
                exp_rel_after = str(after_loop_state.get("session", {}).get("exp", {}).get("path", "")).strip()
                if exp_rel_after:
                    exp_abs_after = (
                        exp_rel_after
                        if os.path.isabs(exp_rel_after)
                        else os.path.abspath(os.path.join(ROOT_DIR, exp_rel_after))
                    )
                    if os.path.isfile(exp_abs_after):
                        try:
                            after_exp_hash = file_sha256(exp_abs_after)
                        except Exception:
                            after_exp_hash = ""
                if before_exp_hash and after_exp_hash and before_exp_hash != after_exp_hash:
                    loop_exp_hash_changed = True
                elif (not before_exp_hash) and after_exp_hash:
                    loop_exp_hash_changed = True

            loop_terminal_unsolved = bool(
                enable_exploit
                and terminal_stage
                and terminal_attempted_this_loop
                and (not terminal_local_verified_this_loop)
            )
            rewrite_force_regen_this_loop = False
            rewrite_force_regen_reason = ""
            rewrite_force_regen_hint = ""
            rewrite_elapsed_sec = 0.0
            if loop_terminal_unsolved:
                if exploit_rewrite_started_monotonic <= 0:
                    exploit_rewrite_started_monotonic = time.monotonic()
                rewrite_elapsed_sec = max(0.0, time.monotonic() - exploit_rewrite_started_monotonic)
                if terminal_last_error_this_loop:
                    same_timeout_like = _is_timeout_like_error(terminal_last_error_this_loop)
                    if terminal_last_error_this_loop == exploit_rewrite_last_error:
                        if same_timeout_like:
                            exploit_rewrite_same_error_streak = 0
                        else:
                            exploit_rewrite_same_error_streak += 1
                    elif same_timeout_like:
                        exploit_rewrite_same_error_streak = 0
                    else:
                        exploit_rewrite_same_error_streak = 1
                exploit_rewrite_last_error = terminal_last_error_this_loop or exploit_rewrite_last_error
                exploit_rewrite_last_verify_report = (
                    terminal_verify_report_this_loop or exploit_rewrite_last_verify_report
                )
                exploit_rewrite_last_exp_path = terminal_exp_path_this_loop or exploit_rewrite_last_exp_path
                (
                    rewrite_force_regen_this_loop,
                    rewrite_force_regen_reason,
                    rewrite_force_regen_hint,
                ) = _should_force_exp_regen_after_unsolved(
                    after_loop_state,
                    verify_report=terminal_verify_report_this_loop,
                    last_error=terminal_last_error_this_loop,
                )
                if rewrite_force_regen_this_loop:
                    exp_now = (
                        after_loop_state.setdefault("session", {}).setdefault("exp", {})
                        if isinstance(after_loop_state.setdefault("session", {}).setdefault("exp", {}), dict)
                        else {}
                    )
                    manual_exp_lock = _manual_exp_regen_locked(exp_cfg=exp_now)
                    if rewrite_force_regen_hint and (
                        str(exp_now.get("strategy_hint", "")).strip().lower() != rewrite_force_regen_hint
                    ):
                        exp_now["strategy_hint"] = rewrite_force_regen_hint
                    if (not manual_exp_lock) and (not bool(exp_now.get("force_regen_once", False))):
                        exp_now["force_regen_once"] = True
                    exp_now["rewrite_force_reason"] = rewrite_force_regen_reason
                    save_json(args.state, after_loop_state)
                    sync_meta_from_state(sid, after_loop_state)
                    notes.append(
                        "terminal exploit unsolved -> force exp rewrite next loop: "
                        + rewrite_force_regen_reason
                        + (
                            f" (strategy_hint={rewrite_force_regen_hint})"
                            if rewrite_force_regen_hint
                            else ""
                        )
                        + (" [manual exp lock active]" if manual_exp_lock else "")
                    )
            elif terminal_attempted_this_loop and terminal_local_verified_this_loop:
                exploit_rewrite_same_error_streak = 0
                exploit_rewrite_last_error = ""

            if loop_terminal_unsolved:
                terminal_unsolved_streak += 1
            elif terminal_attempted_this_loop and terminal_local_verified_this_loop:
                terminal_unsolved_streak = 0

            if loop_terminal_unsolved:
                low_term_err = str(terminal_last_error_this_loop or "").strip().lower()
                codex_timeout_like = (
                    _is_timeout_like_error(low_term_err)
                    and any(x in low_term_err for x in ("codex", "mcp", "transport closed", "channel closed"))
                )
                verify_timeout_like = (
                    ("verify" in low_term_err)
                    and (
                        ("rc=124" in low_term_err)
                        or ("timeout=1" in low_term_err)
                        or ("runtime timed out" in low_term_err)
                        or ("timed out" in low_term_err)
                    )
                )
                budget_non_actionable = (
                    ("cost fuse hit:" in low_term_err)
                    or ("prompt_chars" in low_term_err and "fuse" in low_term_err)
                    or ("codex_calls" in low_term_err and "fuse" in low_term_err)
                )
                non_actionable = (
                    ("non-fixable verify error" in low_term_err)
                    or ("no actionable runtime error" in low_term_err)
                    or codex_timeout_like
                    or verify_timeout_like
                    or budget_non_actionable
                )
                if rewrite_force_regen_this_loop:
                    terminal_non_actionable_verify_streak = 0
                elif non_actionable:
                    terminal_non_actionable_verify_streak += 1
                else:
                    terminal_non_actionable_verify_streak = 0
            elif terminal_attempted_this_loop and terminal_local_verified_this_loop:
                terminal_non_actionable_verify_streak = 0

            if loop_l0_timeout_like_failure:
                # 统计“本轮 L0 超时/瞬断”是否持续发生，即使本轮也尝试了 terminal。
                # 这样才能触发下一轮 terminal-only，避免 recon/ida 在超时场景下重复空转。
                l0_timeout_no_terminal_streak += 1
            else:
                l0_timeout_no_terminal_streak = 0

            loop_progress = (
                (after_evid > before_evid)
                or (after_hypos > before_hypos)
                or loop_exp_hash_changed
                or terminal_local_verified_this_loop
            )
            evidence_progress = bool((after_evid > before_evid) or (after_hypos > before_hypos))
            if evidence_progress:
                last_new_evidence_monotonic = time.monotonic()
            no_new_evidence_sec = max(0.0, time.monotonic() - last_new_evidence_monotonic)
            hypo_engine.update_after_loop(after_loop_state, had_progress=loop_progress)

            loop_decision_outcome = _apply_loop_decision_state_impl(
                after_loop_state=after_loop_state,
                state_path=args.state,
                session_id=sid,
                loop_idx=loop_idx,
                terminal_stage=terminal_stage,
                loop_stage_order=loop_stage_order,
                decision_report_rel=decision_report_rel,
                active_hypothesis_ids=hypo_engine.active_ids(after_loop_state),
                notes=notes,
                metrics=metrics,
                post_obj=post_obj,
                loop_progress=loop_progress,
                no_progress_loops=no_progress_loops,
                loop_terminal_unsolved=loop_terminal_unsolved,
                terminal_unsolved_streak=terminal_unsolved_streak,
                no_new_evidence_sec=no_new_evidence_sec,
                rewrite_elapsed_sec=rewrite_elapsed_sec,
                hint_gate_enabled=hint_gate_enabled,
                hint_gate_no_progress_loops=hint_gate_no_progress_loops,
                hint_gate_no_new_evidence_sec=hint_gate_no_new_evidence_sec,
                exploit_rewrite_request_hint_after_wall_sec=exploit_rewrite_request_hint_after_wall_sec,
                hint_gate_last_trigger_loop=hint_gate_last_trigger_loop,
                hint_gate_write_report=hint_gate_write_report,
                hint_gate_stop_on_trigger=hint_gate_stop_on_trigger,
                exploit_rewrite_stop_on_request_hint=exploit_rewrite_stop_on_request_hint,
                timeout_gate_enabled=timeout_gate_enabled,
                timeout_gate_blind_only=timeout_gate_blind_only,
                timeout_gate_require_no_progress=timeout_gate_require_no_progress,
                timeout_gate_consecutive_loops=timeout_gate_consecutive_loops,
                timeout_gate_write_report=timeout_gate_write_report,
                timeout_gate_stop_on_trigger=timeout_gate_stop_on_trigger,
                timeout_no_evidence_streak=timeout_no_evidence_streak,
                loop_rc124_failures=loop_rc124_failures,
                strategy_route_switch_enabled=strategy_route_switch_enabled,
                strategy_route_switch_no_progress_loops=strategy_route_switch_no_progress_loops,
                strategy_route_switch_terminal_unsolved_loops=strategy_route_switch_terminal_unsolved_loops,
                strategy_route_switch_weak_only=strategy_route_switch_weak_only,
                exploit_precheck_weak_strategies=set(exploit_precheck_weak_strategies),
                strategy_route_switch_cycle=list(strategy_route_switch_cycle),
                blind_mode_enabled=blind_mode_enabled,
                blind_mode_route_switch_lock=blind_mode_route_switch_lock,
                blind_mode_default_strategy_hint=blind_mode_default_strategy_hint,
                strategy_route_switch_count=strategy_route_switch_count,
                strategy_route_switch_reset_no_progress=strategy_route_switch_reset_no_progress,
                strategy_route_switch_request_hint_after=strategy_route_switch_request_hint_after,
                strategy_route_switch_write_report=strategy_route_switch_write_report,
                stage_timeout_circuit_enabled=stage_timeout_circuit_enabled,
                stage_timeout_circuit_stages=set(stage_timeout_circuit_stages),
                stage_timeout_circuit_failure_categories=set(stage_timeout_circuit_failure_categories),
                stage_timeout_circuit_consecutive_failures=stage_timeout_circuit_consecutive_failures,
                stage_timeout_circuit_cooldown_loops=stage_timeout_circuit_cooldown_loops,
                stage_timeout_failure_streak=stage_timeout_failure_streak,
                stage_timeout_skip_remaining=stage_timeout_skip_remaining,
                codex_unhealthy_enabled=codex_unhealthy_enabled,
                codex_unhealthy_stages=set(codex_unhealthy_stages),
                codex_unhealthy_failure_categories=set(codex_unhealthy_failure_categories),
                codex_unhealthy_consecutive_failures=codex_unhealthy_consecutive_failures,
                codex_unhealthy_cooldown_loops=codex_unhealthy_cooldown_loops,
                codex_unhealthy_failure_streak=codex_unhealthy_failure_streak,
                codex_unhealthy_skip_remaining=codex_unhealthy_skip_remaining,
                adaptive_stage_order_enabled=bool(decision_cfg.get("enable_adaptive_stage_order", True)),
                detect_blind_mode_fn=detect_blind_mode,
                detect_lua_runtime_exec_hint_fn=detect_lua_runtime_exec_hint,
                detect_repl_cmd_exec_hint_fn=detect_repl_cmd_exec_hint,
                write_strategy_route_switch_report_fn=write_strategy_route_switch_report,
                write_hint_request_gate_report_fn=write_hint_request_gate_report,
                write_timeout_no_evidence_gate_report_fn=write_timeout_no_evidence_gate_report,
                normalize_strategy_hint_fn=_normalize_strategy_hint,
                normalize_strategy_hint_cycle_fn=_normalize_strategy_hint_cycle,
                pick_next_strategy_hint_fn=_pick_next_strategy_hint,
                save_json_fn=save_json,
                sync_meta_fn=sync_meta_from_state,
                utc_now_fn=utc_now,
            )
            no_progress_loops = loop_decision_outcome.no_progress_loops
            strategy_route_switch_count = loop_decision_outcome.strategy_route_switch_count
            hint_gate_last_trigger_loop = loop_decision_outcome.hint_gate_last_trigger_loop
            timeout_no_evidence_streak = loop_decision_outcome.timeout_no_evidence_streak

            loop_stop_outcome = _evaluate_loop_stop_impl(
                notes=notes,
                after_loop_state=after_loop_state,
                state_path=args.state,
                session_id=sid,
                terminal_stage=terminal_stage,
                terminal_attempted_this_loop=terminal_attempted_this_loop,
                terminal_local_verified_this_loop=terminal_local_verified_this_loop,
                loop_terminal_unsolved=loop_terminal_unsolved,
                exploit_rewrite_enabled=exploit_rewrite_enabled,
                exploit_rewrite_until_success=exploit_rewrite_until_success,
                exploit_rewrite_write_report=exploit_rewrite_write_report,
                stage_results=stage_results,
                base_max_loops=base_max_loops,
                exploit_rewrite_extra_loops=exploit_rewrite_extra_loops,
                rewrite_elapsed_sec=rewrite_elapsed_sec,
                exploit_rewrite_same_error_streak=exploit_rewrite_same_error_streak,
                terminal_non_actionable_verify_streak=terminal_non_actionable_verify_streak,
                exploit_rewrite_last_error=exploit_rewrite_last_error,
                exploit_rewrite_last_verify_report=exploit_rewrite_last_verify_report,
                exploit_rewrite_last_exp_path=exploit_rewrite_last_exp_path,
                metrics=metrics,
                save_json_fn=save_json,
                sync_meta_fn=sync_meta_from_state,
                loop_idx=loop_idx,
                loop_start=loop_start,
                exploit_rewrite_max_wall_sec=exploit_rewrite_max_wall_sec,
                exploit_rewrite_stop_on_same_error_streak=exploit_rewrite_stop_on_same_error_streak,
                exploit_rewrite_stop_on_non_actionable_verify_streak=exploit_rewrite_stop_on_non_actionable_verify_streak,
                is_timeout_like_error_fn=_is_timeout_like_error,
                objective_enabled=objective_enabled,
                objective_stop_on_achieved=objective_stop_on_achieved,
                post_obj=post_obj,
                force_terminal_stage=force_terminal_stage,
                write_exploit_rewrite_report_fn=write_exploit_rewrite_report,
                current_exploit_rewrite_stop_reason=exploit_rewrite_stop_reason,
                stop_after_no_progress=int(decision_cfg.get("stop_after_no_progress_loops", 2) or 2),
                no_progress_loops=no_progress_loops,
                stop_on_stage_failure=stop_on_stage_failure,
                enable_exploit=enable_exploit,
                hint_gate_triggered=loop_decision_outcome.hint_gate_triggered,
                hint_gate_stop_on_trigger=hint_gate_stop_on_trigger,
                rewrite_hint_gate_triggered=loop_decision_outcome.rewrite_hint_gate_triggered,
                exploit_rewrite_stop_on_request_hint=exploit_rewrite_stop_on_request_hint,
                timeout_gate_triggered=loop_decision_outcome.timeout_gate_triggered,
                timeout_gate_stop_on_trigger=timeout_gate_stop_on_trigger,
            )
            exploit_rewrite_stop_reason = loop_stop_outcome.exploit_rewrite_stop_reason
            if loop_stop_outcome.should_break:
                break

        metrics.wall_time_sec = max(0.0, time.monotonic() - run_started_monotonic)
        has_fail = any(not bool(x.get("ok")) for x in stage_results)
        run_finalize = _finalize_run_outputs_impl(
            root_dir=ROOT_DIR,
            state_path=args.state,
            session_id=sid,
            loop_end=loop_end,
            fast_mode=fast_mode,
            enable_exploit=enable_exploit,
            allow_remote_exp=allow_remote_exp,
            exploit_rewrite_enabled=exploit_rewrite_enabled,
            exploit_rewrite_write_report=exploit_rewrite_write_report,
            terminal_stage=terminal_stage,
            base_max_loops=base_max_loops,
            exploit_rewrite_extra_loops=exploit_rewrite_extra_loops,
            exploit_rewrite_started_monotonic=exploit_rewrite_started_monotonic,
            exploit_rewrite_same_error_streak=exploit_rewrite_same_error_streak,
            terminal_non_actionable_verify_streak=terminal_non_actionable_verify_streak,
            exploit_rewrite_last_error=exploit_rewrite_last_error,
            exploit_rewrite_last_verify_report=exploit_rewrite_last_verify_report,
            exploit_rewrite_last_exp_path=exploit_rewrite_last_exp_path,
            exploit_rewrite_stop_reason=exploit_rewrite_stop_reason,
            fuse_triggered=fuse_triggered,
            fuse_reason=fuse_reason,
            stop_requested=stop_requested,
            has_fail=has_fail,
            max_codex_calls=max_codex_calls,
            max_prompt_chars=max_prompt_chars,
            max_wall_time_sec=max_wall_time_sec,
            max_autofix_rounds=max_autofix_rounds,
            acceptance_cfg=acceptance_cfg,
            remote_prompt_cfg=remote_prompt_cfg,
            kpi_enabled=kpi_enabled,
            per_session_abs=per_session_abs,
            global_kpi_abs=global_kpi_abs,
            metrics=metrics,
            stage_results=stage_results,
            notes=notes,
            cap_cfg=cap_cfg,
            objective_cfg=objective_cfg,
            load_json_fn=load_json,
            save_json_fn=save_json,
            infer_capabilities_fn=infer_capabilities,
            evaluate_objectives_fn=evaluate_objectives,
            apply_objective_state_fn=apply_objective_state,
            derive_final_session_status_fn=_derive_final_session_status_impl,
            derive_final_rewrite_reason_fn=_derive_final_rewrite_reason_impl,
            derive_final_exit_decision_fn=_derive_final_exit_decision_impl,
            write_exploit_rewrite_report_fn=write_exploit_rewrite_report,
            write_cost_fuse_report_fn=write_cost_fuse_report,
            write_acceptance_report_fn=write_acceptance_report,
            ensure_exploit_artifact_links_fn=ensure_exploit_artifact_links,
            maybe_prepare_remote_prompt_fn=maybe_prepare_remote_prompt,
            write_timeline_report_fn=write_timeline_report,
            write_timing_report_fn=write_timing_report,
            write_summary_report_fn=write_summary_report,
            merge_external_metric_counters_fn=merge_external_metric_counters,
            refresh_global_kpi_fn=refresh_global_kpi,
            sync_meta_from_state_fn=sync_meta_from_state,
            sync_state_meta_cli_fn=sync_state_meta_cli,
            repo_rel_fn=repo_rel,
            monotonic_now_fn=time.monotonic,
        )
        final_state = run_finalize.final_state
        exit_code = run_finalize.exit_code
        acceptance_report_rel = run_finalize.acceptance_report_rel
        acceptance_passed = run_finalize.acceptance_passed
        timeline_rel = run_finalize.timeline_rel
        timing_rel = run_finalize.timing_rel
        exploit_rewrite_report_rel = run_finalize.exploit_rewrite_report_rel
        report_rel = run_finalize.report_rel
        metrics_rel_out = run_finalize.metrics_rel_out

        final_doc = _build_final_output_doc_impl(
            session_id=sid,
            state_rel=repo_rel(args.state),
            report_rel=report_rel,
            metrics_rel=metrics_rel_out,
            fast_mode=fast_mode,
            fuse_triggered=fuse_triggered,
            fuse_reason=fuse_reason,
            acceptance_report=acceptance_report_rel,
            acceptance_passed=acceptance_passed,
            timeline_report=timeline_rel,
            timing_report=timing_rel,
            exploit_rewrite_report=exploit_rewrite_report_rel,
            exit_code=exit_code,
            stage_results=stage_results,
            notes=notes,
        )
        print(json.dumps(final_doc, ensure_ascii=False, indent=2))
        return exit_code
    finally:
        restore_env(prev_session_mcp_env)
        if prev_autorun is None:
            os.environ.pop("DIRGE_AUTORUN", None)
        else:
            os.environ["DIRGE_AUTORUN"] = prev_autorun
        if prev_block_self_stop is None:
            os.environ.pop("DIRGE_BLOCK_SELF_STOP", None)
        else:
            os.environ["DIRGE_BLOCK_SELF_STOP"] = prev_block_self_stop
        release_run_lock(lock)


if __name__ == "__main__":
    raise SystemExit(main())
