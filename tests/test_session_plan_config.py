#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.session_plan_config import load_session_plan_config


class SessionPlanConfigTests(unittest.TestCase):
    def test_load_session_plan_config_keeps_terminal_stage_last(self) -> None:
        cfg = load_session_plan_config(
            automation={"stage_order": ["exploit_l4", "recon", "ida_slice", "gdb_evidence"], "default_max_loops": 3},
            unified_cfg={"enabled": True, "max_loops": 4},
            enable_exploit=True,
            force_terminal_cfg=True,
            args_max_loops=0,
            exploit_stage_level_fn=lambda stage: 4 if stage == "exploit_l4" else -1,
            terminal_exploit_stage_fn=lambda stages: "exploit_l4" if "exploit_l4" in stages else "",
            ensure_terminal_stage_last_fn=lambda stages, terminal: [s for s in stages if s != terminal] + [terminal],
        )
        self.assertEqual("exploit_l4", cfg.terminal_stage)
        self.assertEqual("exploit_l4", cfg.stage_order[-1])
        self.assertTrue(cfg.force_terminal_stage)
        self.assertEqual(4, cfg.max_loops)

    def test_load_session_plan_config_filters_exploit_when_disabled(self) -> None:
        cfg = load_session_plan_config(
            automation={"stage_order": ["recon", "exploit_l3", "gdb_evidence"], "default_max_loops": 2},
            unified_cfg={"enabled": False, "max_loops": 5},
            enable_exploit=False,
            force_terminal_cfg=True,
            args_max_loops=6,
            exploit_stage_level_fn=lambda stage: 3 if stage == "exploit_l3" else -1,
            terminal_exploit_stage_fn=lambda stages: "",
            ensure_terminal_stage_last_fn=lambda stages, terminal: stages,
        )
        self.assertEqual(["recon", "gdb_evidence"], cfg.stage_order)
        self.assertEqual("", cfg.terminal_stage)
        self.assertFalse(cfg.force_terminal_stage)
        self.assertEqual(6, cfg.max_loops)


if __name__ == "__main__":
    unittest.main()
