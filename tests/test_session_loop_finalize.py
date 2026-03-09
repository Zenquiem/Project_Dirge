#!/usr/bin/env python3
from __future__ import annotations

import unittest
from types import SimpleNamespace

from session_loop_finalize import apply_loop_decision_state, evaluate_loop_stop


class FakeMetrics:
    def __init__(self) -> None:
        self.no_progress_loops = 0
        self.objective_score_latest = 0
        self.objective_target_hits = 0


class SessionLoopFinalizeTests(unittest.TestCase):
    def test_apply_loop_decision_state_updates_decision_state(self) -> None:
        state = {"progress": {}, "artifacts_index": {"latest": {"paths": {}}}, "session": {"exp": {}}}
        synced = []
        outcome = apply_loop_decision_state(
            after_loop_state=state,
            state_path="state.json",
            session_id="sess",
            loop_idx=2,
            terminal_stage="exploit_l4",
            loop_stage_order=["recon", "exploit_l4"],
            decision_report_rel="artifacts/reports/decision.json",
            active_hypothesis_ids=["h1"],
            notes=[],
            metrics=FakeMetrics(),
            post_obj=SimpleNamespace(score=7, target_achieved=False),
            loop_progress=False,
            no_progress_loops=1,
            loop_terminal_unsolved=True,
            terminal_unsolved_streak=2,
            no_new_evidence_sec=66.0,
            rewrite_elapsed_sec=10.0,
            hint_gate_enabled=True,
            hint_gate_no_progress_loops=2,
            hint_gate_no_new_evidence_sec=60.0,
            exploit_rewrite_request_hint_after_wall_sec=0.0,
            hint_gate_last_trigger_loop=1,
            hint_gate_write_report=True,
            hint_gate_stop_on_trigger=False,
            exploit_rewrite_stop_on_request_hint=False,
            timeout_gate_enabled=True,
            timeout_gate_blind_only=False,
            timeout_gate_require_no_progress=True,
            timeout_gate_consecutive_loops=2,
            timeout_gate_write_report=True,
            timeout_gate_stop_on_trigger=False,
            timeout_no_evidence_streak=1,
            loop_rc124_failures=1,
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
            stage_timeout_circuit_enabled=False,
            stage_timeout_circuit_stages=set(),
            stage_timeout_circuit_failure_categories=set(),
            stage_timeout_circuit_consecutive_failures=1,
            stage_timeout_circuit_cooldown_loops=1,
            stage_timeout_failure_streak={},
            stage_timeout_skip_remaining={},
            codex_unhealthy_enabled=False,
            codex_unhealthy_stages=set(),
            codex_unhealthy_failure_categories=set(),
            codex_unhealthy_consecutive_failures=1,
            codex_unhealthy_cooldown_loops=1,
            codex_unhealthy_failure_streak={},
            codex_unhealthy_skip_remaining={},
            adaptive_stage_order_enabled=False,
            detect_blind_mode_fn=lambda s: False,
            detect_lua_runtime_exec_hint_fn=lambda s: False,
            detect_repl_cmd_exec_hint_fn=lambda s: False,
            write_strategy_route_switch_report_fn=lambda **kwargs: "artifacts/reports/route.json",
            write_hint_request_gate_report_fn=lambda **kwargs: "artifacts/reports/hint.json",
            write_timeout_no_evidence_gate_report_fn=lambda **kwargs: "artifacts/reports/timeout.json",
            normalize_strategy_hint_fn=lambda v: str(v or "").strip(),
            normalize_strategy_hint_cycle_fn=lambda items, state=None: list(items),
            pick_next_strategy_hint_fn=lambda s, cycle: ("ret2libc", "ret2win", "ret2win", cycle),
            save_json_fn=lambda path, data: None,
            sync_meta_fn=lambda sid, data: synced.append((sid, data.copy())),
            utc_now_fn=lambda: "2026-01-01T00:00:00Z",
        )
        self.assertTrue(outcome.route_switch_applied)
        self.assertTrue(outcome.hint_gate_triggered)
        self.assertTrue(outcome.timeout_gate_triggered)
        self.assertIn("decision", state["progress"])
        self.assertTrue(synced)

    def test_evaluate_loop_stop_honors_hint_gate_stop(self) -> None:
        outcome = evaluate_loop_stop(
            notes=[],
            after_loop_state={"session": {}},
            state_path="state.json",
            session_id="sess",
            terminal_stage="exploit_l4",
            terminal_attempted_this_loop=False,
            terminal_local_verified_this_loop=False,
            loop_terminal_unsolved=False,
            exploit_rewrite_enabled=False,
            exploit_rewrite_until_success=False,
            exploit_rewrite_write_report=False,
            stage_results=[],
            base_max_loops=2,
            exploit_rewrite_extra_loops=0,
            rewrite_elapsed_sec=0.0,
            exploit_rewrite_same_error_streak=0,
            terminal_non_actionable_verify_streak=0,
            exploit_rewrite_last_error="",
            exploit_rewrite_last_verify_report="",
            exploit_rewrite_last_exp_path="",
            metrics=SimpleNamespace(),
            save_json_fn=lambda path, data: None,
            sync_meta_fn=lambda sid, data: None,
            loop_idx=1,
            loop_start=1,
            exploit_rewrite_max_wall_sec=0.0,
            exploit_rewrite_stop_on_same_error_streak=0,
            exploit_rewrite_stop_on_non_actionable_verify_streak=0,
            is_timeout_like_error_fn=lambda err: False,
            objective_enabled=False,
            objective_stop_on_achieved=False,
            post_obj=SimpleNamespace(target_achieved=False, score=0),
            force_terminal_stage=False,
            write_exploit_rewrite_report_fn=lambda **kwargs: "",
            current_exploit_rewrite_stop_reason="",
            stop_after_no_progress=2,
            no_progress_loops=0,
            stop_on_stage_failure=False,
            enable_exploit=False,
            hint_gate_triggered=True,
            hint_gate_stop_on_trigger=True,
            rewrite_hint_gate_triggered=False,
            exploit_rewrite_stop_on_request_hint=False,
            timeout_gate_triggered=False,
            timeout_gate_stop_on_trigger=False,
        )
        self.assertTrue(outcome.should_break)


if __name__ == "__main__":
    unittest.main()
