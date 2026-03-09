#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class AttemptRetryDecision:
    action: str
    retry_wait: float
    reason: str


def should_use_cache_fallback(*, ok: bool, stage_cache_hit: bool, cache_fallback_used: bool) -> bool:
    return bool((not ok) and stage_cache_hit and (not cache_fallback_used))


def evaluate_attempt_retry_policy(
    *,
    stage: str,
    mcp_forced_retry_used: bool,
    codex_available: bool,
    failure_category: str,
    err: str,
    attempt_no: int,
    info: Any,
    recovery_cfg: dict,
    should_retry_fn: Callable[[str, int, Any, dict], bool],
    next_backoff_seconds_fn: Callable[[int, dict], float],
) -> AttemptRetryDecision:
    low_err = str(err or "").strip().lower()
    mcp_like_timeout = any(
        x in low_err
        for x in (
            "transport closed",
            "channel closed",
            "stream disconnected",
            "mcp",
            "ghidra",
            "handshaking",
            "initialize response",
        )
    )
    if (
        (stage in {"recon", "ida_slice"})
        and (not mcp_forced_retry_used)
        and codex_available
        and ((failure_category == "mcp_transient") or ((failure_category == "timeout") and mcp_like_timeout))
    ):
        retry_wait = max(0.2, next_backoff_seconds_fn(attempt_no, recovery_cfg))
        return AttemptRetryDecision(
            action="force_mcp_retry",
            retry_wait=retry_wait,
            reason=f"stage={stage} category={failure_category}",
        )
    if should_retry_fn(stage, attempt_no, info, recovery_cfg):
        retry_wait = next_backoff_seconds_fn(attempt_no, recovery_cfg)
        return AttemptRetryDecision(
            action="retry",
            retry_wait=retry_wait,
            reason=f"stage={stage} category={failure_category}",
        )
    return AttemptRetryDecision(action="stop", retry_wait=0.0, reason="")
