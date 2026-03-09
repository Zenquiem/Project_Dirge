#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest

from core.decision_report_utils import (
    write_hint_request_gate_report,
    write_strategy_route_switch_report,
    write_timeout_no_evidence_gate_report,
)


class DecisionReportUtilsTests(unittest.TestCase):
    def test_write_strategy_route_switch_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rel = write_strategy_route_switch_report(
                root_dir=tmp,
                session_id="sess",
                loop_idx=2,
                current_hint="ret2win",
                current_strategy="ret2win",
                next_hint="ret2libc",
                cycle=["ret2win", "ret2libc"],
                no_progress_loops=3,
                terminal_unsolved_streak=1,
                reason="switch",
                recommend_hint=True,
            )
            with open(os.path.join(tmp, rel), "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual("ret2libc", doc["next_hint"])
            self.assertTrue(doc["recommend_external_hint"])

    def test_write_hint_and_timeout_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rel1 = write_hint_request_gate_report(
                root_dir=tmp,
                session_id="sess",
                loop_idx=1,
                no_progress_loops=4,
                no_new_evidence_sec=12.34,
                reasons=["no progress"],
            )
            rel2 = write_timeout_no_evidence_gate_report(
                root_dir=tmp,
                session_id="sess",
                loop_idx=1,
                consecutive_timeout_loops=2,
                timeout_streak=2,
                rc124_failures_in_loop=1,
                no_progress_loops=4,
                no_new_evidence_sec=55.5,
                blind_mode=True,
                reason="timeout gate",
            )
            self.assertTrue(os.path.exists(os.path.join(tmp, rel1)))
            self.assertTrue(os.path.exists(os.path.join(tmp, rel2)))


if __name__ == "__main__":
    unittest.main()
