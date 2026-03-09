from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List


@dataclass(frozen=True)
class StrategyRouteSwitchConfig:
    enabled: bool
    no_progress_loops: int
    terminal_unsolved_loops: int
    weak_only: bool
    reset_no_progress: bool
    request_hint_after: int
    write_report: bool
    cycle: List[str]


@dataclass(frozen=True)
class HintGateConfig:
    enabled: bool
    no_progress_loops: int
    no_new_evidence_sec: float
    write_report: bool
    stop_on_trigger: bool


@dataclass(frozen=True)
class BlindModeConfig:
    enabled: bool
    skip_static_stages: bool
    skip_mcp_health_check: bool
    prefer_protocol_semantic_probe: bool
    default_strategy_hint: str
    route_switch_lock: bool


@dataclass(frozen=True)
class TimeoutNoEvidenceGateConfig:
    enabled: bool
    consecutive_loops: int
    require_no_progress: bool
    blind_only: bool
    write_report: bool
    stop_on_trigger: bool


@dataclass(frozen=True)
class DecisionRuntimeConfig:
    strategy_route_switch: StrategyRouteSwitchConfig
    hint_gate: HintGateConfig
    blind_mode: BlindModeConfig
    timeout_gate: TimeoutNoEvidenceGateConfig


def load_decision_runtime_config(
    decision_cfg: Dict[str, Any],
    *,
    normalize_strategy_hint_fn: Callable[[Any], str],
    normalize_strategy_hint_cycle_fn: Callable[..., List[str]],
    state: Dict[str, Any],
) -> DecisionRuntimeConfig:
    strategy_route_cfg = (
        decision_cfg.get("strategy_route_switch", {})
        if isinstance(decision_cfg.get("strategy_route_switch", {}), dict)
        else {}
    )
    hint_gate_cfg = (
        decision_cfg.get("hint_request_gate", {})
        if isinstance(decision_cfg.get("hint_request_gate", {}), dict)
        else {}
    )
    blind_mode_cfg = (
        decision_cfg.get("blind_mode", {})
        if isinstance(decision_cfg.get("blind_mode", {}), dict)
        else {}
    )
    timeout_gate_cfg = (
        decision_cfg.get("timeout_no_evidence_gate", {})
        if isinstance(decision_cfg.get("timeout_no_evidence_gate", {}), dict)
        else {}
    )

    return DecisionRuntimeConfig(
        strategy_route_switch=StrategyRouteSwitchConfig(
            enabled=bool(strategy_route_cfg.get("enabled", True)),
            no_progress_loops=max(1, int(strategy_route_cfg.get("no_progress_loops", 1) or 1)),
            terminal_unsolved_loops=max(1, int(strategy_route_cfg.get("terminal_unsolved_streak", 1) or 1)),
            weak_only=bool(strategy_route_cfg.get("only_when_weak_strategy", False)),
            reset_no_progress=bool(strategy_route_cfg.get("reset_no_progress_after_switch", True)),
            request_hint_after=max(0, int(strategy_route_cfg.get("request_hint_after_switches", 0) or 0)),
            write_report=bool(strategy_route_cfg.get("write_report", True)),
            cycle=normalize_strategy_hint_cycle_fn(strategy_route_cfg.get("cycle", []), state=state),
        ),
        hint_gate=HintGateConfig(
            enabled=bool(hint_gate_cfg.get("enabled", True)),
            no_progress_loops=max(0, int(hint_gate_cfg.get("no_progress_loops", 2) or 2)),
            no_new_evidence_sec=max(
                0.0,
                float(hint_gate_cfg.get("no_new_evidence_minutes", 30.0) or 30.0) * 60.0,
            ),
            write_report=bool(hint_gate_cfg.get("write_report", True)),
            stop_on_trigger=bool(hint_gate_cfg.get("stop_on_trigger", False)),
        ),
        blind_mode=BlindModeConfig(
            enabled=bool(blind_mode_cfg.get("enabled", True)),
            skip_static_stages=bool(blind_mode_cfg.get("skip_static_stages", True)),
            skip_mcp_health_check=bool(blind_mode_cfg.get("skip_mcp_health_check", True)),
            prefer_protocol_semantic_probe=bool(blind_mode_cfg.get("prefer_protocol_semantic_probe", True)),
            default_strategy_hint=normalize_strategy_hint_fn(
                blind_mode_cfg.get("default_strategy_hint", "js_shell_cmd_exec")
            )
            or "js_shell_cmd_exec",
            route_switch_lock=bool(blind_mode_cfg.get("route_switch_lock", True)),
        ),
        timeout_gate=TimeoutNoEvidenceGateConfig(
            enabled=bool(timeout_gate_cfg.get("enabled", True)),
            consecutive_loops=max(1, int(timeout_gate_cfg.get("consecutive_timeout_loops", 2) or 2)),
            require_no_progress=bool(timeout_gate_cfg.get("require_no_progress", True)),
            blind_only=bool(timeout_gate_cfg.get("blind_mode_only", True)),
            write_report=bool(timeout_gate_cfg.get("write_report", True)),
            stop_on_trigger=bool(timeout_gate_cfg.get("stop_on_trigger", True)),
        ),
    )
