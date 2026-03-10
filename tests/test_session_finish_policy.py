#!/usr/bin/env python3
from __future__ import annotations

import unittest

from scripts.session_finish_policy import (
    build_final_output_doc,
    derive_final_exit_decision,
    derive_final_rewrite_reason,
    derive_final_session_status,
)


class SessionFinishPolicyTests(unittest.TestCase):
    def test_derive_final_session_status_prefers_fuse_then_stop_then_fail(self) -> None:
        self.assertEqual(
            "fused",
            derive_final_session_status(fuse_triggered=True, stop_requested=True, has_fail=True),
        )
        self.assertEqual(
            "stopped",
            derive_final_session_status(fuse_triggered=False, stop_requested=True, has_fail=True),
        )
        self.assertEqual(
            "finished_with_errors",
            derive_final_session_status(fuse_triggered=False, stop_requested=False, has_fail=True),
        )
        self.assertEqual(
            "finished",
            derive_final_session_status(fuse_triggered=False, stop_requested=False, has_fail=False),
        )

    def test_derive_final_exit_decision_covers_fuse_stop_failure_and_success(self) -> None:
        fuse = derive_final_exit_decision(
            fuse_triggered=True,
            stop_requested=False,
            has_fail=False,
            acceptance_enabled=True,
            acceptance_passed=False,
        )
        self.assertEqual(68, fuse.exit_code)
        self.assertTrue(fuse.acceptance_failed)

        stopped = derive_final_exit_decision(
            fuse_triggered=False,
            stop_requested=True,
            has_fail=False,
            acceptance_enabled=False,
            acceptance_passed=True,
        )
        self.assertEqual(130, stopped.exit_code)

        failed = derive_final_exit_decision(
            fuse_triggered=False,
            stop_requested=False,
            has_fail=False,
            acceptance_enabled=True,
            acceptance_passed=False,
        )
        self.assertEqual(1, failed.exit_code)
        self.assertTrue(failed.acceptance_failed)

        ok = derive_final_exit_decision(
            fuse_triggered=False,
            stop_requested=False,
            has_fail=False,
            acceptance_enabled=True,
            acceptance_passed=True,
        )
        self.assertEqual(0, ok.exit_code)
        self.assertFalse(ok.acceptance_failed)

    def test_derive_final_rewrite_reason_uses_first_non_empty_source(self) -> None:
        self.assertEqual(
            "rewrite-limit",
            derive_final_rewrite_reason(
                exploit_rewrite_stop_reason="rewrite-limit",
                fuse_reason="fuse",
                session_last_error="boom",
                terminal_stage="exploit_l3",
            ),
        )
        self.assertEqual(
            "fuse",
            derive_final_rewrite_reason(
                exploit_rewrite_stop_reason="",
                fuse_reason="fuse",
                session_last_error="boom",
                terminal_stage="exploit_l3",
            ),
        )
        self.assertEqual(
            "exploit_l3 not solved after rewrite budget",
            derive_final_rewrite_reason(
                exploit_rewrite_stop_reason="",
                fuse_reason="",
                session_last_error="",
                terminal_stage="exploit_l3",
            ),
        )

    def test_build_final_output_doc_preserves_fields(self) -> None:
        doc = build_final_output_doc(
            session_id="sess-9",
            state_rel="state/state.json",
            report_rel="artifacts/reports/summary.md",
            metrics_rel="artifacts/reports/metrics.json",
            fast_mode=True,
            fuse_triggered=False,
            fuse_reason="",
            acceptance_report="artifacts/reports/acceptance.json",
            acceptance_passed=True,
            timeline_report="artifacts/reports/timeline.json",
            timing_report="artifacts/reports/timing.json",
            exploit_rewrite_report="artifacts/reports/rewrite.json",
            exit_code=0,
            stage_results=[{"stage": "recon", "ok": True}],
            notes=["done"],
        )
        self.assertEqual("sess-9", doc["session_id"])
        self.assertTrue(doc["fast_mode"])
        self.assertEqual(0, doc["exit_code"])
        self.assertEqual(["done"], doc["notes"])


if __name__ == "__main__":
    unittest.main()
