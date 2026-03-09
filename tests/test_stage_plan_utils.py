#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.stage_plan_utils import detect_bundle_plan


class StagePlanUtilsTests(unittest.TestCase):
    def test_detect_bundle_plan_disabled_or_incomplete(self) -> None:
        self.assertEqual(
            (False, "", []),
            detect_bundle_plan(
                ["recon", "ida_slice"],
                enabled=True,
                include_exploit_stages=False,
                exploit_stage_level_fn=lambda stage: -1,
            ),
        )
        self.assertEqual(
            (False, "", []),
            detect_bundle_plan(
                ["recon", "ida_slice", "gdb_evidence"],
                enabled=False,
                include_exploit_stages=False,
                exploit_stage_level_fn=lambda stage: -1,
            ),
        )

    def test_detect_bundle_plan_includes_exploit_stages(self) -> None:
        ok, trigger, ordered = detect_bundle_plan(
            ["prep", "recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"],
            enabled=True,
            include_exploit_stages=True,
            exploit_stage_level_fn=lambda stage: 3 if stage == "exploit_l3" else 4 if stage == "exploit_l4" else -1,
        )
        self.assertTrue(ok)
        self.assertEqual("recon", trigger)
        self.assertEqual(["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"], ordered)

    def test_detect_bundle_plan_rejects_wrong_order_when_consecutive_required(self) -> None:
        self.assertEqual(
            (False, "", []),
            detect_bundle_plan(
                ["ida_slice", "recon", "gdb_evidence"],
                enabled=True,
                include_exploit_stages=False,
                exploit_stage_level_fn=lambda stage: -1,
                require_consecutive=True,
            ),
        )


if __name__ == "__main__":
    unittest.main()
