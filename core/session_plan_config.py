from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class SessionPlanConfig:
    stage_order: List[str]
    terminal_stage: str
    force_terminal_stage: bool
    unified_enabled: bool
    unified_loops: int
    max_loops: int


def load_session_plan_config(
    *,
    automation: Dict[str, Any],
    unified_cfg: Dict[str, Any],
    enable_exploit: bool,
    force_terminal_cfg: bool,
    args_max_loops: int,
    exploit_stage_level_fn: Callable[[str], int],
    terminal_exploit_stage_fn: Callable[[List[str]], str],
    ensure_terminal_stage_last_fn: Callable[[List[str], str], List[str]],
) -> SessionPlanConfig:
    stage_order = automation.get(
        "stage_order", ["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"]
    )
    if not isinstance(stage_order, list):
        stage_order = ["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"]
    stage_order = [str(x) for x in stage_order]

    if not enable_exploit:
        stage_order = [stage for stage in stage_order if exploit_stage_level_fn(stage) < 0]

    terminal_stage = terminal_exploit_stage_fn(stage_order) if enable_exploit else ""
    force_terminal_stage = bool(force_terminal_cfg and terminal_stage)
    if force_terminal_stage:
        stage_order = ensure_terminal_stage_last_fn(stage_order, terminal_stage)

    unified_enabled = bool(unified_cfg.get("enabled", True))
    unified_loops = max(1, int(unified_cfg.get("max_loops", 1) or 1))

    max_loops = args_max_loops if args_max_loops > 0 else int(automation.get("default_max_loops", 1) or 1)
    if unified_enabled and args_max_loops <= 0:
        max_loops = max(1, unified_loops)

    return SessionPlanConfig(
        stage_order=stage_order,
        terminal_stage=terminal_stage,
        force_terminal_stage=force_terminal_stage,
        unified_enabled=unified_enabled,
        unified_loops=unified_loops,
        max_loops=max_loops,
    )
