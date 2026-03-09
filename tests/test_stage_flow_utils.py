#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.stage_flow_utils import (
    ensure_counter_progress,
    ensure_terminal_stage_last,
    exploit_stage_level,
    stage_counter_key,
    terminal_exploit_stage,
)


class StageFlowUtilsTests(unittest.TestCase):
    def test_exploit_stage_level_and_terminal_selection(self) -> None:
        self.assertEqual(3, exploit_stage_level("exploit_l3"))
        self.assertEqual(-1, exploit_stage_level("recon"))
        self.assertEqual("exploit_l4", terminal_exploit_stage(["recon", "exploit_l3", "exploit_l4"]))

    def test_ensure_terminal_stage_last_deduplicates(self) -> None:
        stages = ["exploit_l4", "recon", "exploit_l3", "exploit_l4"]
        self.assertEqual(["recon", "exploit_l3", "exploit_l4"], ensure_terminal_stage_last(stages, "exploit_l4"))

    def test_stage_counter_key_and_progress_bump(self) -> None:
        self.assertEqual("gdb_runs", stage_counter_key("gdb_evidence"))
        self.assertEqual("exploit_runs", stage_counter_key("exploit_l4"))

        before = {"progress": {"run_seq": 1, "counters": {"total_runs": 2, "gdb_runs": 4}}}
        after = {"progress": {"run_seq": 1, "counters": {"total_runs": 2, "gdb_runs": 4}}}
        updated = ensure_counter_progress(before, after, "gdb_evidence")
        self.assertEqual(2, updated["progress"]["run_seq"])
        self.assertEqual(3, updated["progress"]["counters"]["total_runs"])
        self.assertEqual(5, updated["progress"]["counters"]["gdb_runs"])
        self.assertEqual("gdb_evidence", updated["progress"]["stage"])
        self.assertIn("last_updated_utc", updated["progress"])


if __name__ == "__main__":
    unittest.main()
