#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class FailureInfo:
    category: str
    recoverable: bool
    reason: str


def classify_failure(
    return_code: int,
    error: str,
    *,
    contract_errors: List[str] | None = None,
    validate_failed: bool = False,
    verifier_failed: bool = False,
) -> FailureInfo:
    low = (error or "").strip().lower()
    has_contract = bool(contract_errors)

    if has_contract:
        return FailureInfo("contract_violation", False, "stage contract validation failed")
    if validate_failed:
        return FailureInfo("state_invalid", False, "validate_state failed")
    if verifier_failed:
        return FailureInfo("verifier_failed", False, "verifier failed")
    if return_code == 127 and ("codex" in low or "not found" in low):
        return FailureInfo("codex_missing", False, "codex command missing")
    if ("mcp" in low and any(
        k in low
        for k in (
            "unavailable",
            "temporar",
            "broken pipe",
            "reset by peer",
            "eof",
            "no servers",
            "transport closed",
            "stream disconnected",
            "channel closed",
            "handshaking",
            "initialize response",
            "startup",
            "not listed",
            "serde",
            "analysis_complete",
            "analysis pending",
            "analysis still running",
            "closedexception",
            "file is closed",
            "project lock",
        )
    )) or any(
        k in low
        for k in (
            "stream disconnected",
            "channel closed",
            "failed to shutdown rollout recorder",
            "rollout recorder",
            "codex channel closed",
            "serde error",
            "expected value at line 1 column 1",
            "analysis_complete\": false",
            "analysis_complete: false",
            "analysis pending",
            "analysis still running",
            "closedexception",
            "file is closed",
        )
    ):
        return FailureInfo("mcp_transient", True, "mcp transient failure")
    if any(k in low for k in ("ghidra project lock", "lockexception", "unable to lock project", "early abort:")):
        return FailureInfo("mcp_transient", True, "mcp backend lock/transient failure")
    if return_code == 124 or "timeout" in low:
        return FailureInfo("timeout", True, "stage timeout")
    if return_code != 0:
        return FailureInfo("stage_runtime_error", False, "non-zero return code")
    return FailureInfo("unknown", False, "unknown failure")


def should_retry(
    stage: str,
    attempt_no: int,
    info: FailureInfo,
    recovery_cfg: Dict[str, Any],
) -> bool:
    if not bool(recovery_cfg.get("enabled", True)):
        return False
    if not info.recoverable:
        return False

    stage_limits = recovery_cfg.get("stage_max_retries", {})
    if not isinstance(stage_limits, dict):
        stage_limits = {}

    default_max = int(recovery_cfg.get("default_max_retries", 1) or 1)
    max_retries = stage_limits.get(stage, default_max)
    try:
        max_retries = int(max_retries)
    except Exception:
        max_retries = default_max
    max_retries = max(0, max_retries)

    # Optional per-stage per-category cap, e.g.
    # recovery.stage_max_retries_by_category.exploit_l4.timeout = 1
    by_cat_cfg = recovery_cfg.get("stage_max_retries_by_category", {})
    if isinstance(by_cat_cfg, dict):
        stage_cfg = by_cat_cfg.get(stage, {})
        if isinstance(stage_cfg, dict):
            cat_limit = stage_cfg.get(info.category, None)
            if cat_limit is not None:
                try:
                    cat_limit_i = max(0, int(cat_limit))
                    max_retries = min(max_retries, cat_limit_i)
                except Exception:
                    pass

    return attempt_no <= max_retries


def next_backoff_seconds(retry_no: int, recovery_cfg: Dict[str, Any]) -> float:
    base = float(recovery_cfg.get("backoff_base_sec", 0.8) or 0.8)
    cap = float(recovery_cfg.get("backoff_cap_sec", 6.0) or 6.0)
    if retry_no <= 0:
        retry_no = 1
    wait = base * (2 ** (retry_no - 1))
    if wait > cap:
        wait = cap
    if wait < 0.0:
        wait = 0.0
    return wait
