#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from session_loop_policy import (
    evaluate_exploit_rewrite_stop,
    evaluate_hint_gate,
    evaluate_no_progress_stop,
    evaluate_objective_stop,
    evaluate_stage_failure_flow,
    evaluate_stage_failure_stop,
    evaluate_timeout_no_evidence_gate,
)


class SessionLoopPolicyTests(unittest.TestCase):
    def test_evaluate_hint_gate_triggers_on_no_progress_and_rewrite_elapsed(self) -> None:
        outcome = evaluate_hint_gate(
            enabled=True,
            loop_terminal_unsolved=True,
            no_progress_loops=3,
            no_progress_threshold=2,
            no_new_evidence_sec=120,
            no_new_evidence_threshold=60,
            rewrite_elapsed_sec=100,
            rewrite_request_hint_after_wall_sec=90,
            loop_idx=4,
            last_trigger_loop=3,
        )
        self.assertTrue(outcome.triggered)
        self.assertTrue(outcome.rewrite_triggered)
        self.assertGreaterEqual(len(outcome.reasons), 2)

    def test_timeout_gate_respects_blind_only_and_progress(self) -> None:
        blocked = evaluate_timeout_no_evidence_gate(
            enabled=True,
            loop_rc124_failures=1,
            blind_mode=False,
            blind_only=True,
            require_no_progress=False,
            loop_progress=False,
            prev_timeout_streak=1,
            consecutive_loops=2,
        )
        self.assertFalse(blocked.applicable)

        triggered = evaluate_timeout_no_evidence_gate(
            enabled=True,
            loop_rc124_failures=1,
            blind_mode=True,
            blind_only=True,
            require_no_progress=True,
            loop_progress=False,
            prev_timeout_streak=1,
            consecutive_loops=2,
        )
        self.assertTrue(triggered.triggered)
        self.assertIn("rc=124", triggered.reason)

    def test_exploit_rewrite_stop_prefers_keep_rewriting_for_timeout_like_errors(self) -> None:
        outcome = evaluate_exploit_rewrite_stop(
            rewrite_elapsed_sec=10,
            max_wall_sec=100,
            same_error_streak=3,
            same_error_limit=3,
            last_error="timeout while waiting",
            non_actionable_verify_streak=0,
            non_actionable_verify_limit=2,
            extra_used=1,
            extra_loops_budget=10,
            is_timeout_like_error=lambda err: "timeout" in err,
        )
        self.assertEqual("", outcome.stop_reason)
        self.assertIn("keep rewriting", outcome.keep_rewriting_note)

    def test_loop_stop_decisions(self) -> None:
        objective = evaluate_objective_stop(
            objective_enabled=True,
            objective_stop_on_achieved=True,
            target_achieved=True,
            force_terminal_stage=False,
            terminal_attempted_this_loop=False,
            terminal_stage="exploit_l4",
            score=100,
        )
        self.assertTrue(objective.should_break)

        no_progress = evaluate_no_progress_stop(
            no_progress_loops=3,
            stop_after_no_progress=2,
            force_terminal_stage=False,
            terminal_attempted_this_loop=False,
            terminal_stage="exploit_l4",
            exploit_rewrite_enabled=False,
            loop_terminal_unsolved=False,
        )
        self.assertTrue(no_progress.should_break)

        stage_failure = evaluate_stage_failure_stop(
            stage_failed=True,
            stop_on_stage_failure=True,
            force_terminal_stage=False,
            terminal_attempted_this_loop=False,
            terminal_stage="exploit_l4",
            exploit_rewrite_enabled=False,
            enable_exploit=False,
        )
        self.assertTrue(stage_failure.should_break)

    def test_stage_failure_flow_can_continue_to_terminal_or_fail_open(self) -> None:
        fail_open = evaluate_stage_failure_flow(
            stage="ida_slice",
            failure_category="timeout",
            stop_on_stage_failure=True,
            fuse_triggered=False,
            ida_fail_open_enabled=True,
            ida_fail_open_categories={"timeout"},
            ida_fail_open_write_blocker=True,
            auto_continue_mcp_failure_set=set(),
            exploit_rewrite_enabled=False,
            enable_exploit=False,
            terminal_stage="exploit_l4",
            loop_stage_order=["recon", "ida_slice", "gdb_evidence"],
            force_terminal_stage=False,
        )
        self.assertEqual("continue", fail_open.action)
        self.assertTrue(fail_open.write_ida_blocker)

        continue_terminal = evaluate_stage_failure_flow(
            stage="recon",
            failure_category="timeout",
            stop_on_stage_failure=True,
            fuse_triggered=False,
            ida_fail_open_enabled=False,
            ida_fail_open_categories=set(),
            ida_fail_open_write_blocker=False,
            auto_continue_mcp_failure_set=set(),
            exploit_rewrite_enabled=True,
            enable_exploit=True,
            terminal_stage="exploit_l4",
            loop_stage_order=["recon", "ida_slice", "exploit_l4"],
            force_terminal_stage=False,
        )
        self.assertEqual("continue", continue_terminal.action)
        self.assertIn("exploit_l4", continue_terminal.note)


if __name__ == "__main__":
    unittest.main()
