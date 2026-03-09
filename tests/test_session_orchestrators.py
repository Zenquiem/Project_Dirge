#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from session_attempt_runtime import finalize_attempt
from session_loop_finalize import apply_loop_decision_state, evaluate_loop_stop
from session_stage_flow import apply_post_stage_flow
from session_stage_outcome import apply_stage_result_state, apply_stage_spec_check


class FakeMetrics:
    def __init__(self) -> None:
        self.stage_success = {}
        self.stage_failure = {}
        self.codex_errors = 0
        self.stage_retries = 0
        self.recoverable_failures = 0
        self.timeout_circuit_activations = 0
        self.objective_score_latest = 0
        self.objective_target_hits = 0
        self.no_progress_loops = 0

    def bump_stage_success(self, stage: str) -> None:
        self.stage_success[stage] = int(self.stage_success.get(stage, 0) or 0) + 1

    def bump_stage_failure(self, stage: str) -> None:
        self.stage_failure[stage] = int(self.stage_failure.get(stage, 0) or 0) + 1


class StageOutcomeTests(unittest.TestCase):
    def test_apply_stage_spec_check_marks_stage_spec_violation(self) -> None:
        state = {"session": {}, "artifacts_index": {"latest": {"paths": {}}}}
        normalized = []
        linked = []
        logs = []

        outcome = apply_stage_spec_check(
            ok=True,
            rc=0,
            err="",
            stage="exploit_l4",
            state_path="state.json",
            session_id="sess",
            loop_idx=2,
            stage_log_rel="artifacts/logs/run.log",
            log_abs="/tmp/run.log",
            is_exploit_stage=True,
            exp_verify_report="verify.json",
            failure_category="",
            failure_recoverable=True,
            load_json_fn=lambda _path: state,
            append_file_fn=lambda path, line: logs.append((path, line)),
            normalize_latest_artifact_keys_fn=lambda **kwargs: normalized.append(kwargs) or {},
            ensure_exploit_artifact_links_fn=lambda **kwargs: linked.append(kwargs),
            validate_stage_runner_spec_fn=lambda _state, _spec: ["missing required field"],
            stage_spec={"stage": "exploit_l4"},
        )

        self.assertFalse(outcome.ok)
        self.assertEqual(66, outcome.rc)
        self.assertEqual("stage runner spec validation failed", outcome.err)
        self.assertEqual("stage_spec_violation", outcome.failure_category)
        self.assertFalse(outcome.failure_recoverable)
        self.assertEqual(["missing required field"], outcome.stage_spec_errors)
        self.assertEqual("artifacts/logs/run.log", normalized[0]["stage_log_rel"])
        self.assertEqual("verify.json", linked[0]["verify_report_hint"])
        self.assertTrue(any("stage runner spec errors" in line for _, line in logs))

    def test_apply_stage_result_state_records_failure_and_rc124(self) -> None:
        metrics = FakeMetrics()
        state = {"summary": {}, "session": {}}
        saved = []
        synced = []

        outcome = apply_stage_result_state(
            state_path="state.json",
            stage="recon",
            ok=False,
            rc=124,
            err="timed out",
            contract_errors=["bad contract"],
            failure_category="timeout",
            metrics=metrics,
            loop_rc124_failures=1,
            load_json_fn=lambda _path: state,
            save_json_fn=lambda _path, data: saved.append(json.loads(json.dumps(data))),
            sync_meta_fn=lambda sid, data: synced.append((sid, json.loads(json.dumps(data)))),
            session_id="sess",
        )

        self.assertEqual(2, outcome.loop_rc124_failures)
        self.assertEqual(1, metrics.stage_failure["recon"])
        self.assertEqual(1, metrics.codex_errors)
        self.assertEqual("failed:recon", state["session"]["status"])
        self.assertEqual("timed out", state["session"]["last_error"])
        self.assertIn("recon: contract failed (1 errors)", state["summary"]["blockers"])
        self.assertEqual(1, len(saved))
        self.assertEqual(1, len(synced))


class AttemptRuntimeTests(unittest.TestCase):
    def test_finalize_attempt_retries_recoverable_failure(self) -> None:
        metrics = FakeMetrics()
        attempt_records = []
        logs = []

        outcome = finalize_attempt(
            ok=False,
            rc=124,
            err="timeout",
            contract_errors=[],
            validate_failed=False,
            verifier_failed=False,
            fuse_triggered=False,
            stage="recon",
            attempt_no=1,
            attempt_records=attempt_records,
            mcp_forced_retry_used=False,
            codex_available=True,
            recovery_cfg={},
            state_path="state.json",
            session_id="sess",
            loop_idx=1,
            health_cfg={},
            codex_bin="codex",
            log_abs="/tmp/run.log",
            metrics=metrics,
            classify_failure_fn=lambda *_args, **_kwargs: SimpleNamespace(category="timeout", recoverable=True),
            utc_now_fn=lambda: "2026-03-08T00:00:00Z",
            evaluate_attempt_retry_policy_fn=lambda **_kwargs: SimpleNamespace(
                action="retry", retry_wait=0.0, reason="retry timeout"
            ),
            should_retry_fn=lambda *_args, **_kwargs: True,
            next_backoff_seconds_fn=lambda *_args, **_kwargs: 0.0,
            run_mcp_self_heal_fn=lambda **_kwargs: "",
            append_file_fn=lambda path, line: logs.append((path, line)),
            sleep_fn=lambda _sec: None,
        )

        self.assertTrue(outcome.should_continue)
        self.assertFalse(outcome.should_break)
        self.assertEqual("timeout", outcome.failure_category)
        self.assertTrue(outcome.failure_recoverable)
        self.assertEqual(2, outcome.next_attempt_no)
        self.assertEqual(1, metrics.recoverable_failures)
        self.assertEqual(1, metrics.stage_retries)
        self.assertEqual("timeout", attempt_records[0]["failure_category"])
        self.assertTrue(any("retry timeout" in line for _, line in logs))


class StageFlowTests(unittest.TestCase):
    def test_apply_post_stage_flow_continues_terminal_rewrite_path(self) -> None:
        metrics = FakeMetrics()
        notes = []
        skip_static = set()

        outcome = apply_post_stage_flow(
            ok=False,
            stage="recon",
            err="timed out",
            log_rel="artifacts/logs/recon.log",
            log_abs="/tmp/recon.log",
            state_path="state.json",
            session_id="sess",
            loop_idx=1,
            loop_end=4,
            terminal_stage="exploit_l4",
            loop_stage_order=["recon", "exploit_l4"],
            stop_on_stage_failure=True,
            fuse_triggered=False,
            force_terminal_stage=False,
            exploit_rewrite_enabled=True,
            enable_exploit=True,
            failure_category="timeout",
            loop_l0_timeout_like_failure=False,
            skip_static_stages_this_loop=skip_static,
            notes=notes,
            metrics=metrics,
            stage_timeout_circuit_enabled=False,
            stage_timeout_circuit_stages=set(),
            stage_timeout_circuit_failure_categories=set(),
            stage_timeout_failure_streak={},
            stage_timeout_skip_remaining={},
            stage_timeout_circuit_consecutive_failures=2,
            stage_timeout_circuit_cooldown_loops=1,
            codex_unhealthy_enabled=False,
            codex_unhealthy_stages=set(),
            codex_unhealthy_failure_categories=set(),
            codex_unhealthy_failure_streak={},
            codex_unhealthy_skip_remaining={},
            codex_unhealthy_consecutive_failures=2,
            codex_unhealthy_cooldown_loops=1,
            ida_fail_open_enabled=False,
            ida_fail_open_categories=set(),
            ida_fail_open_write_blocker=False,
            auto_continue_mcp_failure_set=set(),
            append_file_fn=lambda _path, _line: None,
            write_ida_dual_evidence_bundle_fn=lambda *_args: "",
            write_ida_blocker_report_fn=lambda **_kwargs: "",
        )

        self.assertTrue(outcome.should_continue)
        self.assertFalse(outcome.should_break)
        self.assertTrue(outcome.loop_l0_timeout_like_failure)
        self.assertFalse(outcome.terminal_attempted_this_loop)
        self.assertTrue(any("rewrite 模式继续推进" in note for note in notes))


class LoopFinalizeTests(unittest.TestCase):
    def test_apply_loop_decision_state_updates_progress_without_triggering_gates(self) -> None:
        metrics = FakeMetrics()
        state = {}
        saved = []
        synced = []
        notes = []

        outcome = apply_loop_decision_state(
            after_loop_state=state,
            state_path="state.json",
            session_id="sess",
            loop_idx=3,
            terminal_stage="",
            loop_stage_order=["recon", "gdb_evidence"],
            decision_report_rel="artifacts/reports/decision.json",
            active_hypothesis_ids=["hyp_1"],
            notes=notes,
            metrics=metrics,
            post_obj=SimpleNamespace(score=7, target_achieved=False),
            loop_progress=False,
            no_progress_loops=2,
            loop_terminal_unsolved=False,
            terminal_unsolved_streak=0,
            no_new_evidence_sec=11.5,
            rewrite_elapsed_sec=0.0,
            hint_gate_enabled=False,
            hint_gate_no_progress_loops=2,
            hint_gate_no_new_evidence_sec=60.0,
            exploit_rewrite_request_hint_after_wall_sec=600.0,
            hint_gate_last_trigger_loop=0,
            hint_gate_write_report=False,
            hint_gate_stop_on_trigger=False,
            exploit_rewrite_stop_on_request_hint=False,
            timeout_gate_enabled=False,
            timeout_gate_blind_only=False,
            timeout_gate_require_no_progress=False,
            timeout_gate_consecutive_loops=2,
            timeout_gate_write_report=False,
            timeout_gate_stop_on_trigger=False,
            timeout_no_evidence_streak=0,
            loop_rc124_failures=0,
            strategy_route_switch_enabled=False,
            strategy_route_switch_no_progress_loops=2,
            strategy_route_switch_terminal_unsolved_loops=2,
            strategy_route_switch_weak_only=False,
            exploit_precheck_weak_strategies=set(),
            strategy_route_switch_cycle=[],
            blind_mode_enabled=False,
            blind_mode_route_switch_lock=False,
            blind_mode_default_strategy_hint="",
            strategy_route_switch_count=0,
            strategy_route_switch_reset_no_progress=False,
            strategy_route_switch_request_hint_after=0,
            strategy_route_switch_write_report=False,
            stage_timeout_circuit_enabled=False,
            stage_timeout_circuit_stages=set(),
            stage_timeout_circuit_failure_categories=set(),
            stage_timeout_circuit_consecutive_failures=2,
            stage_timeout_circuit_cooldown_loops=1,
            stage_timeout_failure_streak={},
            stage_timeout_skip_remaining={},
            codex_unhealthy_enabled=False,
            codex_unhealthy_stages=set(),
            codex_unhealthy_failure_categories=set(),
            codex_unhealthy_consecutive_failures=2,
            codex_unhealthy_cooldown_loops=1,
            codex_unhealthy_failure_streak={},
            codex_unhealthy_skip_remaining={},
            adaptive_stage_order_enabled=True,
            detect_blind_mode_fn=lambda _state: False,
            detect_lua_runtime_exec_hint_fn=lambda _state: False,
            detect_repl_cmd_exec_hint_fn=lambda _state: False,
            write_strategy_route_switch_report_fn=lambda **_kwargs: "",
            write_hint_request_gate_report_fn=lambda **_kwargs: "",
            write_timeout_no_evidence_gate_report_fn=lambda **_kwargs: "",
            normalize_strategy_hint_fn=lambda value: str(value or ""),
            normalize_strategy_hint_cycle_fn=lambda cycle, **_kwargs: list(cycle),
            pick_next_strategy_hint_fn=lambda *_args, **_kwargs: ("", "", "", []),
            save_json_fn=lambda _path, data: saved.append(json.loads(json.dumps(data))),
            sync_meta_fn=lambda sid, data: synced.append((sid, json.loads(json.dumps(data)))),
            utc_now_fn=lambda: "2026-03-08T00:00:00Z",
        )

        self.assertEqual(3, outcome.no_progress_loops)
        self.assertFalse(outcome.hint_gate_triggered)
        self.assertFalse(outcome.timeout_gate_triggered)
        self.assertEqual(1, state["progress"]["loop_seq"])
        self.assertEqual(["hyp_1"], state["progress"]["decision"]["last_active_hypothesis_ids"])
        self.assertEqual(3, metrics.no_progress_loops)
        self.assertEqual(7, metrics.objective_score_latest)
        self.assertEqual(1, len(saved))
        self.assertEqual(1, len(synced))

    def test_evaluate_loop_stop_breaks_when_terminal_verified(self) -> None:
        notes = []
        outcome = evaluate_loop_stop(
            notes=notes,
            after_loop_state={},
            state_path="state.json",
            session_id="sess",
            terminal_stage="exploit_l4",
            terminal_attempted_this_loop=True,
            terminal_local_verified_this_loop=True,
            loop_terminal_unsolved=False,
            exploit_rewrite_enabled=True,
            exploit_rewrite_until_success=True,
            exploit_rewrite_write_report=False,
            stage_results=[{"loop": 1, "ok": True}],
            base_max_loops=2,
            exploit_rewrite_extra_loops=1,
            rewrite_elapsed_sec=0.0,
            exploit_rewrite_same_error_streak=0,
            terminal_non_actionable_verify_streak=0,
            exploit_rewrite_last_error="",
            exploit_rewrite_last_verify_report="",
            exploit_rewrite_last_exp_path="exp.py",
            metrics=FakeMetrics(),
            save_json_fn=lambda _path, _data: None,
            sync_meta_fn=lambda _sid, _data: None,
            loop_idx=1,
            loop_start=1,
            exploit_rewrite_max_wall_sec=900.0,
            exploit_rewrite_stop_on_same_error_streak=0,
            exploit_rewrite_stop_on_non_actionable_verify_streak=0,
            is_timeout_like_error_fn=lambda _msg: False,
            objective_enabled=True,
            objective_stop_on_achieved=True,
            post_obj=SimpleNamespace(score=1, target_achieved=False),
            force_terminal_stage=False,
            write_exploit_rewrite_report_fn=lambda **_kwargs: "",
            current_exploit_rewrite_stop_reason="",
            stop_after_no_progress=2,
            no_progress_loops=0,
            stop_on_stage_failure=False,
            enable_exploit=True,
            hint_gate_triggered=False,
            hint_gate_stop_on_trigger=False,
            rewrite_hint_gate_triggered=False,
            exploit_rewrite_stop_on_request_hint=False,
            timeout_gate_triggered=False,
            timeout_gate_stop_on_trigger=False,
        )

        self.assertTrue(outcome.should_break)
        self.assertTrue(any("已通过 verify" in note for note in notes))

    def test_evaluate_loop_stop_keeps_running_on_hint_gate_in_until_success_mode(self) -> None:
        notes = []
        outcome = evaluate_loop_stop(
            notes=notes,
            after_loop_state={},
            state_path="state.json",
            session_id="sess",
            terminal_stage="exploit_l4",
            terminal_attempted_this_loop=True,
            terminal_local_verified_this_loop=False,
            loop_terminal_unsolved=True,
            exploit_rewrite_enabled=True,
            exploit_rewrite_until_success=True,
            exploit_rewrite_write_report=False,
            stage_results=[{"loop": 1, "ok": False}],
            base_max_loops=2,
            exploit_rewrite_extra_loops=1,
            rewrite_elapsed_sec=999.0,
            exploit_rewrite_same_error_streak=0,
            terminal_non_actionable_verify_streak=0,
            exploit_rewrite_last_error="timeout",
            exploit_rewrite_last_verify_report="verify.json",
            exploit_rewrite_last_exp_path="exp.py",
            metrics=FakeMetrics(),
            save_json_fn=lambda _path, _data: None,
            sync_meta_fn=lambda _sid, _data: None,
            loop_idx=3,
            loop_start=1,
            exploit_rewrite_max_wall_sec=600.0,
            exploit_rewrite_stop_on_same_error_streak=0,
            exploit_rewrite_stop_on_non_actionable_verify_streak=0,
            is_timeout_like_error_fn=lambda _msg: True,
            objective_enabled=True,
            objective_stop_on_achieved=True,
            post_obj=SimpleNamespace(score=0, target_achieved=False),
            force_terminal_stage=False,
            write_exploit_rewrite_report_fn=lambda **_kwargs: "",
            current_exploit_rewrite_stop_reason="",
            stop_after_no_progress=2,
            no_progress_loops=5,
            stop_on_stage_failure=True,
            enable_exploit=True,
            hint_gate_triggered=True,
            hint_gate_stop_on_trigger=True,
            rewrite_hint_gate_triggered=True,
            exploit_rewrite_stop_on_request_hint=True,
            timeout_gate_triggered=False,
            timeout_gate_stop_on_trigger=False,
        )

        self.assertFalse(outcome.should_break)
        self.assertTrue(any("continue until terminal exploit reaches shell/flag" in note for note in notes))

    def test_evaluate_loop_stop_ignores_rewrite_wall_in_until_success_mode(self) -> None:
        notes = []
        outcome = evaluate_loop_stop(
            notes=notes,
            after_loop_state={},
            state_path="state.json",
            session_id="sess",
            terminal_stage="exploit_l4",
            terminal_attempted_this_loop=True,
            terminal_local_verified_this_loop=False,
            loop_terminal_unsolved=True,
            exploit_rewrite_enabled=True,
            exploit_rewrite_until_success=True,
            exploit_rewrite_write_report=False,
            stage_results=[{"loop": 1, "ok": False}],
            base_max_loops=2,
            exploit_rewrite_extra_loops=1,
            rewrite_elapsed_sec=999.0,
            exploit_rewrite_same_error_streak=0,
            terminal_non_actionable_verify_streak=0,
            exploit_rewrite_last_error="timeout",
            exploit_rewrite_last_verify_report="verify.json",
            exploit_rewrite_last_exp_path="exp.py",
            metrics=FakeMetrics(),
            save_json_fn=lambda _path, _data: None,
            sync_meta_fn=lambda _sid, _data: None,
            loop_idx=3,
            loop_start=1,
            exploit_rewrite_max_wall_sec=10.0,
            exploit_rewrite_stop_on_same_error_streak=0,
            exploit_rewrite_stop_on_non_actionable_verify_streak=0,
            is_timeout_like_error_fn=lambda _msg: False,
            objective_enabled=True,
            objective_stop_on_achieved=True,
            post_obj=SimpleNamespace(score=0, target_achieved=False),
            force_terminal_stage=False,
            write_exploit_rewrite_report_fn=lambda **_kwargs: "",
            current_exploit_rewrite_stop_reason="",
            stop_after_no_progress=100,
            no_progress_loops=0,
            stop_on_stage_failure=False,
            enable_exploit=True,
            hint_gate_triggered=False,
            hint_gate_stop_on_trigger=False,
            rewrite_hint_gate_triggered=False,
            exploit_rewrite_stop_on_request_hint=False,
            timeout_gate_triggered=False,
            timeout_gate_stop_on_trigger=False,
        )

        self.assertFalse(outcome.should_break)


if __name__ == "__main__":
    unittest.main()
