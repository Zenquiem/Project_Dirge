#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.decision_config import load_decision_runtime_config


class DecisionConfigTests(unittest.TestCase):
    def test_load_decision_runtime_config_normalizes_nested_settings(self) -> None:
        cfg = load_decision_runtime_config(
            {
                "strategy_route_switch": {
                    "enabled": True,
                    "no_progress_loops": 3,
                    "terminal_unsolved_streak": 2,
                    "only_when_weak_strategy": True,
                    "reset_no_progress_after_switch": False,
                    "request_hint_after_switches": 4,
                    "write_report": False,
                    "cycle": ["ret2win", "ret2libc"],
                },
                "hint_request_gate": {
                    "enabled": True,
                    "no_progress_loops": 5,
                    "no_new_evidence_minutes": 1.5,
                    "write_report": False,
                    "stop_on_trigger": True,
                },
                "blind_mode": {
                    "enabled": True,
                    "skip_static_stages": False,
                    "skip_mcp_health_check": False,
                    "prefer_protocol_semantic_probe": False,
                    "default_strategy_hint": " js_shell_cmd_exec ",
                    "route_switch_lock": False,
                },
                "timeout_no_evidence_gate": {
                    "enabled": True,
                    "consecutive_timeout_loops": 7,
                    "require_no_progress": False,
                    "blind_mode_only": False,
                    "write_report": False,
                    "stop_on_trigger": False,
                },
            },
            normalize_strategy_hint_fn=lambda value: str(value or "").strip(),
            normalize_strategy_hint_cycle_fn=lambda items, state=None: [str(x).strip() for x in items],
            state={},
        )
        self.assertEqual(3, cfg.strategy_route_switch.no_progress_loops)
        self.assertTrue(cfg.strategy_route_switch.weak_only)
        self.assertEqual(["ret2win", "ret2libc"], cfg.strategy_route_switch.cycle)
        self.assertEqual(90.0, cfg.hint_gate.no_new_evidence_sec)
        self.assertEqual("js_shell_cmd_exec", cfg.blind_mode.default_strategy_hint)
        self.assertEqual(7, cfg.timeout_gate.consecutive_loops)
        self.assertFalse(cfg.timeout_gate.stop_on_trigger)

    def test_load_decision_runtime_config_clamps_defaults_and_ignores_non_dicts(self) -> None:
        cfg = load_decision_runtime_config(
            {
                "strategy_route_switch": {
                    "no_progress_loops": 0,
                    "terminal_unsolved_streak": -5,
                    "request_hint_after_switches": -2,
                    "cycle": "ret2win,ret2libc",
                },
                "hint_request_gate": {
                    "no_progress_loops": -3,
                    "no_new_evidence_minutes": -1,
                },
                "blind_mode": [],
                "timeout_no_evidence_gate": {
                    "consecutive_timeout_loops": 0,
                },
            },
            normalize_strategy_hint_fn=lambda value: str(value or "").strip().lower(),
            normalize_strategy_hint_cycle_fn=lambda items, state=None: [str(items)],
            state={},
        )
        self.assertEqual(1, cfg.strategy_route_switch.no_progress_loops)
        self.assertEqual(1, cfg.strategy_route_switch.terminal_unsolved_loops)
        self.assertEqual(0, cfg.strategy_route_switch.request_hint_after)
        self.assertEqual(["ret2win,ret2libc"], cfg.strategy_route_switch.cycle)
        self.assertEqual(0, cfg.hint_gate.no_progress_loops)
        self.assertEqual(0.0, cfg.hint_gate.no_new_evidence_sec)
        self.assertTrue(cfg.blind_mode.enabled)
        self.assertEqual("js_shell_cmd_exec", cfg.blind_mode.default_strategy_hint)
        self.assertEqual(2, cfg.timeout_gate.consecutive_loops)


if __name__ == "__main__":
    unittest.main()
