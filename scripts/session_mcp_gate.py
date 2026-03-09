#!/usr/bin/env python3
from __future__ import annotations

from typing import Any, Callable, Dict, List, Tuple


def run_stage_mcp_gate(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    health_required_variants_fn: Callable[[List[str], Dict[str, Any]], List[List[str]]],
    run_health_check_once_fn: Callable[..., Tuple[bool, str]],
    is_analysis_transient_error_fn: Callable[[str], bool],
    write_binary_identity_report_fn: Callable[..., str],
    run_mcp_self_heal_fn: Callable[..., str],
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    sleep_fn: Callable[[float], None],
) -> Tuple[bool, str, str]:
    required = health_cfg.get("required_servers", ["pyghidra-mcp", "gdb"])
    if not isinstance(required, list):
        required = ["pyghidra-mcp", "gdb"]
    required = [str(x).strip() for x in required if str(x).strip()]
    authority = str(health_cfg.get("authority", "codex_registry")).strip() or "codex_registry"
    if authority not in {"project_config", "codex_registry"}:
        authority = "codex_registry"
    timeout_sec = float(health_cfg.get("stage_gate_timeout_sec", 3.0) or 3.0)
    functional_probe = bool(health_cfg.get("functional_probe_on_stage_gate", False))
    probe_timeout_sec = float(health_cfg.get("functional_probe_timeout_sec", max(8.0, timeout_sec)) or max(8.0, timeout_sec))
    probe_nonfatal = bool(health_cfg.get("functional_probe_nonfatal", False))
    retry_once = bool(health_cfg.get("stage_gate_retry_once", True))
    retry_wait_sec = float(health_cfg.get("stage_gate_retry_wait_sec", 0.7) or 0.7)
    retry_backoff = float(health_cfg.get("stage_gate_retry_backoff", 1.7) or 1.7)
    retry_max = health_cfg.get("stage_gate_max_retries", None)
    if retry_max is None:
        retry_max = 1 if retry_once else 0
    try:
        retry_max = max(0, int(retry_max))
    except Exception:
        retry_max = 1 if retry_once else 0
    self_heal_retries = max(0, int(health_cfg.get("stage_gate_self_heal_retries", 1) or 1))
    self_heal_retry_wait_sec = float(
        health_cfg.get("stage_gate_self_heal_retry_wait_sec", retry_wait_sec) or retry_wait_sec
    )
    wait_for_analysis_retry = bool(health_cfg.get("stage_gate_wait_for_analysis_retry", True))
    wait_for_analysis_retries = max(0, int(health_cfg.get("stage_gate_wait_for_analysis_retries", 2) or 2))
    wait_for_analysis_sec = float(health_cfg.get("stage_gate_wait_for_analysis_sec", 2.2) or 2.2)
    enable_alias_fallback = bool(health_cfg.get("enable_alias_fallback", True))
    required_variants = health_required_variants_fn(required, health_cfg) if enable_alias_fallback else [required]

    def _once(attempt: int) -> Tuple[bool, str, str]:
        report_base = f"artifacts/reports/mcp_gate_{session_id}_{loop_idx:02d}_{stage}_{attempt:02d}.json"
        detail = ""
        for i, req_variant in enumerate(required_variants, start=1):
            report_rel = report_base if i == 1 else report_base.replace(".json", f"_v{i:02d}.json")
            ok_try, detail_try = run_health_check_once_fn(
                codex_bin=codex_bin,
                timeout_sec=timeout_sec,
                authority=authority,
                required=req_variant,
                report_rel=report_rel,
                functional_probe=functional_probe,
                probe_timeout_sec=probe_timeout_sec,
                probe_nonfatal=probe_nonfatal,
            )
            if ok_try:
                if req_variant != required:
                    ident_rel = write_binary_identity_report_fn(
                        state_path=state_path,
                        session_id=session_id,
                        stage_tag=f"{stage}_gate_fallback",
                        note=f"required={'/'.join(required)} used={'/'.join(req_variant)}",
                    )
                    return True, report_rel, f"mcp gate fallback: {'/'.join(req_variant)}; binary={ident_rel}"
                return True, report_rel, ""
            if detail_try:
                detail = detail_try
        return False, report_base, detail or "mcp gate check failed"

    attempt_no = 1
    ok, report_rel, detail = _once(attempt_no)

    while (not ok) and (attempt_no <= retry_max):
        wait_sec = retry_wait_sec * (retry_backoff ** max(0, attempt_no - 1))
        if wait_sec > 0:
            sleep_fn(wait_sec)
        attempt_no += 1
        ok2, report_rel2, detail2 = _once(attempt_no)
        if ok2:
            return True, report_rel2, ""
        report_rel = report_rel2
        if detail2:
            detail = detail2

    if (not ok) and wait_for_analysis_retry and is_analysis_transient_error_fn(detail):
        for idx in range(1, wait_for_analysis_retries + 1):
            wait_sec = max(0.2, wait_for_analysis_sec) * (retry_backoff ** max(0, idx - 1))
            if wait_sec > 0:
                sleep_fn(wait_sec)
            attempt_no += 1
            ok_wait, report_wait, detail_wait = _once(attempt_no)
            if ok_wait:
                return True, report_wait, ""
            report_rel = report_wait
            if detail_wait:
                detail = detail_wait

    heal_reports: List[str] = []
    if (not ok) and bool(health_cfg.get("self_heal_on_gate_failure", True)):
        for heal_idx in range(1, self_heal_retries + 1):
            heal_report_rel = run_mcp_self_heal_fn(
                state_path=state_path,
                session_id=session_id,
                loop_idx=loop_idx,
                stage=f"{stage}_gate_h{heal_idx}",
                reason=detail or "mcp gate failure",
                health_cfg=health_cfg,
                codex_bin=codex_bin,
                notes=None,
            )
            if heal_report_rel:
                heal_reports.append(heal_report_rel)
            attempt_no += 1
            ok3, report_rel3, detail3 = _once(attempt_no)
            if ok3:
                return True, report_rel3, ""
            report_rel = report_rel3
            if detail3:
                detail = detail3
            if heal_idx < self_heal_retries and self_heal_retry_wait_sec > 0:
                sleep_fn(self_heal_retry_wait_sec * (retry_backoff ** max(0, heal_idx - 1)))
        if heal_reports:
            heal_hint = ",".join(heal_reports[-2:])
            if detail:
                detail = f"{detail}; self_heal={heal_hint}"
            else:
                detail = f"self_heal={heal_hint}"

    if not ok and (not detail):
        detail = "mcp gate check failed"

    state = load_json_fn(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["mcp_gate_report"] = report_rel
    latest[f"mcp_gate_{stage}"] = report_rel
    save_json_fn(state_path, state)
    return ok, report_rel, detail
