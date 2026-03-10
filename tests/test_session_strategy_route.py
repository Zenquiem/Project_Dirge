#!/usr/bin/env python3
from __future__ import annotations

import unittest

from session_strategy_route import apply_strategy_route_switch


class SessionStrategyRouteTests(unittest.TestCase):
    def test_apply_strategy_route_switch_updates_state_and_resets_progress(self) -> None:
        state = {"session": {"exp": {"strategy_hint": "ret2win", "strategy": "ret2win"}}}
        decision_state = {}
        notes = []
        reports = []

        outcome = apply_strategy_route_switch(
            after_loop_state=state,
            decision_state=decision_state,
            notes=notes,
            session_id="sess",
            loop_idx=2,
            enable_exploit=True,
            terminal_stage="exploit_l4",
            loop_terminal_unsolved=True,
            no_progress_loops=3,
            terminal_unsolved_streak=2,
            strategy_route_switch_enabled=True,
            strategy_route_switch_no_progress_loops=2,
            strategy_route_switch_terminal_unsolved_loops=2,
            strategy_route_switch_weak_only=False,
            exploit_precheck_weak_strategies={"ret2win"},
            strategy_route_switch_cycle=["ret2win", "ret2libc"],
            blind_mode_enabled=False,
            blind_mode_route_switch_lock=False,
            blind_mode_default_strategy_hint="ret2win",
            strategy_route_switch_count=0,
            strategy_route_switch_reset_no_progress=True,
            strategy_route_switch_request_hint_after=1,
            strategy_route_switch_write_report=True,
            normalize_strategy_hint_fn=lambda value: str(value or "").strip(),
            normalize_strategy_hint_cycle_fn=lambda items, state=None: list(items),
            pick_next_strategy_hint_fn=lambda s, cycle: ("ret2libc", "ret2win", "ret2win", cycle),
            detect_blind_mode_fn=lambda s: False,
            detect_lua_runtime_exec_hint_fn=lambda s: False,
            detect_repl_cmd_exec_hint_fn=lambda s: False,
            write_strategy_route_switch_report_fn=(
                lambda **kwargs: reports.append(kwargs) or "artifacts/reports/switch.json"
            ),
            utc_now_fn=lambda: "2026-01-01T00:00:00Z",
        )

        self.assertTrue(outcome.route_switch_applied)
        self.assertEqual(0, outcome.no_progress_loops)
        self.assertEqual(1, outcome.strategy_route_switch_count)
        self.assertEqual("ret2libc", state["session"]["exp"]["strategy_hint"])
        self.assertTrue(state["session"]["exp"]["force_regen_once"])
        self.assertTrue(decision_state["recommend_external_hint"])
        self.assertTrue(reports)
        self.assertTrue(notes)

    def test_apply_strategy_route_switch_respects_weak_only(self) -> None:
        state = {"session": {"exp": {"strategy_hint": "strong_route", "strategy": "strong_route"}}}
        outcome = apply_strategy_route_switch(
            after_loop_state=state,
            decision_state={},
            notes=[],
            session_id="sess",
            loop_idx=2,
            enable_exploit=True,
            terminal_stage="exploit_l4",
            loop_terminal_unsolved=True,
            no_progress_loops=3,
            terminal_unsolved_streak=2,
            strategy_route_switch_enabled=True,
            strategy_route_switch_no_progress_loops=2,
            strategy_route_switch_terminal_unsolved_loops=2,
            strategy_route_switch_weak_only=True,
            exploit_precheck_weak_strategies={"ret2win"},
            strategy_route_switch_cycle=["ret2win", "ret2libc"],
            blind_mode_enabled=False,
            blind_mode_route_switch_lock=False,
            blind_mode_default_strategy_hint="ret2win",
            strategy_route_switch_count=0,
            strategy_route_switch_reset_no_progress=True,
            strategy_route_switch_request_hint_after=1,
            strategy_route_switch_write_report=True,
            normalize_strategy_hint_fn=lambda value: str(value or "").strip(),
            normalize_strategy_hint_cycle_fn=lambda items, state=None: list(items),
            pick_next_strategy_hint_fn=lambda s, cycle: ("ret2libc", "strong_route", "strong_route", cycle),
            detect_blind_mode_fn=lambda s: False,
            detect_lua_runtime_exec_hint_fn=lambda s: False,
            detect_repl_cmd_exec_hint_fn=lambda s: False,
            write_strategy_route_switch_report_fn=lambda **kwargs: "artifacts/reports/switch.json",
            utc_now_fn=lambda: "2026-01-01T00:00:00Z",
        )
        self.assertFalse(outcome.route_switch_applied)
        self.assertEqual("strong_route", state["session"]["exp"]["strategy_hint"])


if __name__ == "__main__":
    unittest.main()
