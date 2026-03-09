#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class StageCodexRunOutcome:
    ok: bool
    rc: int
    err: str
    fuse_triggered: bool
    fuse_reason: str
    bundle_completed: bool


def _dedup(seq: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in seq:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def run_stage_codex(
    *,
    state_path: str,
    state_now: Dict[str, Any],
    session_id: str,
    loop_idx: int,
    stage: str,
    log_abs: str,
    log_rel: str,
    allow_remote_exp: bool,
    run_bundle_now: bool,
    bundle_include_exploit_stages: bool,
    repl_cmd_exec_hint_loop: bool,
    nxoff_libc_free_hint_loop: bool,
    context_include_state_digest: bool,
    context_mode: str,
    context_include_hypothesis_ids: bool,
    context_include_mutations: bool,
    active_hids_now: List[str],
    mutation_manifest_rel: str,
    mutation_items: List[Dict[str, Any]],
    stage_contract_hint: str,
    timeout_cfg: Dict[str, Any],
    default_stage_timeout: int,
    max_codex_calls: int,
    max_prompt_chars: int,
    exploit_stage_codex_disable_mcp: bool,
    hard_step_enabled: bool,
    hard_step_blocked_tools: List[str],
    hard_step_stage_block_extra: List[str],
    hard_step_enforce_allowed_tools: bool,
    stage_tools_raw: Any,
    hard_step_stage_allow_extra: List[str],
    hard_step_stage_max: int,
    hard_step_default_max_tool_calls: int,
    metrics: Any,
    adapter: Any,
    stage_request_cls: Any,
    root_dir: str,
    build_stage_prompt_fn: Callable[[str, Dict[str, str], str], str],
    state_digest_fn: Callable[[Dict[str, Any]], str],
    exploit_stage_level_fn: Callable[[str], int],
    try_recover_recon_from_log_fn: Callable[..., tuple[bool, str]],
    try_recover_ida_from_log_fn: Callable[..., tuple[bool, str, str]],
    detect_stage_log_signature_fn: Callable[[str], str],
    append_file_fn: Callable[[str, str], None],
) -> StageCodexRunOutcome:
    bundle_prompt_stage = "bundle_l0_l4" if bundle_include_exploit_stages else "bundle_l0_l2"
    prompt_stage = bundle_prompt_stage if run_bundle_now else stage
    ctx = {
        "session_id": session_id,
        "binary_path": str(state_now.get("challenge", {}).get("binary_path", "")),
        "workdir": str(state_now.get("challenge", {}).get("workdir", ".")),
        "exp_path": str(state_now.get("session", {}).get("exp", {}).get("path", "")),
        "allow_remote_exp": "true" if allow_remote_exp else "false",
        "symbol_map": str(
            state_now.get("artifacts_index", {})
            .get("latest", {})
            .get("paths", {})
            .get("symbol_map", "")
        ).strip(),
        "repl_cmd_exec_hint": ("true" if repl_cmd_exec_hint_loop else "false"),
        "nxoff_libc_free_hint": ("true" if nxoff_libc_free_hint_loop else "false"),
    }
    bin_for_ctx = str(ctx.get("binary_path", "")).strip()
    if bin_for_ctx:
        ctx["binary_path_abs"] = (
            bin_for_ctx if os.path.isabs(bin_for_ctx) else os.path.abspath(os.path.join(root_dir, bin_for_ctx))
        )
    if context_include_state_digest:
        ctx["state_digest"] = state_digest_fn(state_now)
    if context_mode != "minimal":
        if context_include_hypothesis_ids:
            ctx["active_hypothesis_ids"] = ",".join(active_hids_now)
        if context_include_mutations:
            ctx["mutation_manifest"] = mutation_manifest_rel
            ctx["mutation_input_ids"] = ",".join(str(x.get("input_id", "")) for x in mutation_items[:8])

    prompt = build_stage_prompt_fn(prompt_stage, ctx, contract_hint=stage_contract_hint)
    prompt_len = len(prompt)
    ok = True
    rc = 0
    err = ""
    fuse_triggered = False
    fuse_reason = ""
    if max_codex_calls > 0 and metrics.codex_calls >= max_codex_calls:
        ok = False
        rc = 68
        err = f"cost fuse hit: codex_calls {metrics.codex_calls} >= {max_codex_calls}"
        fuse_triggered = True
        fuse_reason = err
    elif max_prompt_chars > 0 and (metrics.prompt_chars_total + prompt_len) > max_prompt_chars:
        ok = False
        rc = 68
        err = f"cost fuse hit: prompt_chars {metrics.prompt_chars_total + prompt_len} > {max_prompt_chars}"
        fuse_triggered = True
        fuse_reason = err
    if not ok:
        append_file_fn(log_abs, f"[run_session] {err}\n")

    bundle_timeout_default = max(
        int(timeout_cfg.get("recon", default_stage_timeout) or default_stage_timeout),
        int(timeout_cfg.get("ida_slice", default_stage_timeout) or default_stage_timeout),
        int(timeout_cfg.get("gdb_evidence", default_stage_timeout) or default_stage_timeout),
    )
    timeout = int(timeout_cfg.get(stage, default_stage_timeout) or default_stage_timeout)
    if run_bundle_now:
        timeout = int(timeout_cfg.get(bundle_prompt_stage, bundle_timeout_default) or bundle_timeout_default)

    req_allowed_tools: List[str] = []
    req_blocked_tools: List[str] = []
    req_max_tool_calls = 0
    req_env: Dict[str, str] = {}
    if exploit_stage_level_fn(stage) >= 0 and exploit_stage_codex_disable_mcp:
        req_env["DIRGE_DISABLE_MCP"] = "1"
    if hard_step_enabled and (exploit_stage_level_fn(stage) < 0):
        req_blocked_tools = list(hard_step_blocked_tools)
        req_blocked_tools.extend(hard_step_stage_block_extra)
        if hard_step_enforce_allowed_tools:
            if isinstance(stage_tools_raw, list):
                req_allowed_tools = [
                    str(x).strip()
                    for x in stage_tools_raw
                    if str(x).strip() and (str(x).strip().lower() != "none")
                ]
            req_allowed_tools.extend(hard_step_stage_allow_extra)
        req_max_tool_calls = int(hard_step_stage_max or 0)
        if req_max_tool_calls <= 0 and req_allowed_tools:
            req_max_tool_calls = max(4, len(req_allowed_tools) + 1)
        req_allowed_tools = _dedup(req_allowed_tools)
        req_blocked_tools = _dedup(req_blocked_tools)

    req = stage_request_cls(
        session_id=session_id,
        stage=stage,
        prompt=prompt,
        timeout_sec=timeout,
        workdir=root_dir,
        output_log=log_abs,
        allowed_tools=req_allowed_tools,
        blocked_tools=req_blocked_tools,
        max_tool_calls=req_max_tool_calls,
        env=req_env,
    )
    bundle_completed = False
    if ok:
        metrics.codex_calls += 1
        metrics.prompt_chars_total += prompt_len
        res = adapter.run_stage(req)
        ok = bool(res.ok)
        rc = int(res.return_code)
        err = str(res.error or "")
        if (not ok) and stage == "recon":
            recovered, recon_report_rel = try_recover_recon_from_log_fn(
                state_path=state_path,
                session_id=session_id,
                loop_idx=loop_idx,
                log_rel=log_rel,
            )
            if recovered:
                ok = True
                rc = 0
                err = ""
                append_file_fn(log_abs, f"[run_session] recon recovered from MCP log -> {recon_report_rel}\n")
        if (not ok) and stage == "ida_slice":
            recovered, ida_json_rel, ida_md_rel = try_recover_ida_from_log_fn(
                state_path=state_path,
                session_id=session_id,
                loop_idx=loop_idx,
                log_rel=log_rel,
            )
            if recovered:
                ok = True
                rc = 0
                err = ""
                append_file_fn(
                    log_abs,
                    "[run_session] ida_slice recovered from MCP log -> "
                    f"{ida_json_rel}, {ida_md_rel}\n",
                )
        if not ok:
            sig = detect_stage_log_signature_fn(log_abs)
            if sig:
                err = (f"{err}; {sig}".strip("; ")).strip()
                append_file_fn(log_abs, f"[run_session] detected failure signature: {sig}\n")
        if ok and run_bundle_now:
            bundle_completed = True

    return StageCodexRunOutcome(
        ok=bool(ok),
        rc=int(rc),
        err=str(err or ""),
        fuse_triggered=bool(fuse_triggered),
        fuse_reason=str(fuse_reason or ""),
        bundle_completed=bool(bundle_completed),
    )
