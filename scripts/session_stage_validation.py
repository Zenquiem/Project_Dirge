#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable, Dict, List, Set


@dataclass(frozen=True)
class StagePostValidationOutcome:
    after_state: Dict[str, Any]
    ok: bool
    rc: int
    err: str
    contract_errors: List[str]
    cache_saved_rel: str
    verifier_failed: bool


def run_stage_post_validation(
    *,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    log_rel: str,
    log_abs: str,
    after_state: Dict[str, Any],
    ok: bool,
    rc: int,
    err: str,
    run_bundle_now: bool,
    bundle_stages: List[str],
    stage_cache_enabled: bool,
    binary_sha256: str,
    stage_cache_stages_set: Set[str],
    run_verifier: bool,
    schema_path: str,
    budget_path: str,
    contracts: Any,
    root_dir: str,
    python_executable: str,
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
    append_file_fn: Callable[[str, str], None],
    normalize_latest_artifact_keys_fn: Callable[..., Dict[str, str]],
    write_symbol_map_artifact_fn: Callable[..., str],
    validate_stage_contract_fn: Callable[[Dict[str, Any], str, Any], List[str]],
    exploit_stage_level_fn: Callable[[str], int],
    save_stage_cache_fn: Callable[[str, Dict[str, Any], str], str],
    run_script_fn: Callable[[List[str], str], int],
) -> StagePostValidationOutcome:
    contract_errors: List[str] = []
    cache_saved_rel = ""
    verifier_failed = False
    save_json_fn(state_path, after_state)
    alias_changed = normalize_latest_artifact_keys_fn(
        state_path=state_path,
        session_id=session_id,
        loop_idx=loop_idx,
        stage=stage,
        stage_log_rel=log_rel,
    )
    if alias_changed:
        append_file_fn(
            log_abs,
            "[run_session] normalized artifact keys: "
            + ", ".join(f"{k}={v}" for k, v in sorted(alias_changed.items()))
            + "\n",
        )
    if stage == "ida_slice":
        symbol_map_rel = write_symbol_map_artifact_fn(
            state_path=state_path,
            session_id=session_id,
            loop_idx=loop_idx,
            source_log_rel=log_rel,
        )
        if symbol_map_rel:
            append_file_fn(log_abs, f"[run_session] symbol map -> {symbol_map_rel}\n")
    after = load_json_fn(state_path)

    contract_errors = validate_stage_contract_fn(after, stage, contracts) if contracts else []
    if contract_errors:
        ok = False
        rc = rc or 65
        err = "stage contract validation failed"
        append_file_fn(log_abs, "[run_session] contract errors:\n")
        for ce in contract_errors:
            append_file_fn(log_abs, f" - {ce}\n")

    if ok and stage_cache_enabled and binary_sha256:
        cache_targets = [stage]
        if run_bundle_now and bundle_stages:
            cache_targets = [x for x in bundle_stages]
        for cache_stage in cache_targets:
            if exploit_stage_level_fn(cache_stage) >= 0:
                continue
            if cache_stage not in stage_cache_stages_set:
                continue
            rel = save_stage_cache_fn(cache_stage, after, binary_sha256)
            if rel:
                after.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})[
                    f"cache_{cache_stage}"
                ] = rel
                if cache_stage == stage:
                    cache_saved_rel = rel

    save_json_fn(state_path, after)

    if ok and run_verifier:
        rc_verify = run_script_fn(
            [
                python_executable,
                os.path.join(root_dir, "scripts", "verifier.py"),
                "--state",
                state_path,
                "--schema",
                schema_path,
                "--budget",
                budget_path,
            ],
            log_abs,
        )
        if rc_verify != 0:
            ok = False
            rc = rc_verify
            err = "verifier failed"
            verifier_failed = True

    return StagePostValidationOutcome(
        after_state=load_json_fn(state_path),
        ok=bool(ok),
        rc=int(rc),
        err=str(err or ""),
        contract_errors=contract_errors,
        cache_saved_rel=str(cache_saved_rel or ""),
        verifier_failed=bool(verifier_failed),
    )
