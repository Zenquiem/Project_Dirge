#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.capability_engine import infer_capabilities


class CapabilityEngineTests(unittest.TestCase):
    def test_pc_offset_without_offset_hint_does_not_imply_control_rip(self) -> None:
        state = {
            "dynamic_evidence": {
                "evidence": [
                    {
                        "gdb": {
                            "signal": "SIGSEGV",
                            "rip": "0x555555555170",
                            "pc_offset": "0x1170",
                        },
                        "mappings": {"pie_base": "0x555555554000"},
                    }
                ],
                "clusters": [{"count": 1}],
            },
            "capabilities": {},
        }
        inf = infer_capabilities(state, {})
        self.assertFalse(inf.after.get("control_rip"))
        self.assertEqual("no", inf.after.get("rip_control"))
        self.assertNotIn("offset_to_rip", inf.after)

    def test_offset_hint_implies_control_rip(self) -> None:
        state = {
            "dynamic_evidence": {
                "evidence": [
                    {
                        "gdb": {
                            "signal": "SIGSEGV",
                            "rip": "0x555555555170",
                            "pc_offset": "0x1170",
                            "offset_to_rip": 88,
                        },
                        "mappings": {"pie_base": "0x555555554000"},
                    }
                ],
                "clusters": [{"count": 2}],
            },
            "capabilities": {},
        }
        inf = infer_capabilities(state, {})
        self.assertTrue(inf.after.get("control_rip"))
        self.assertEqual("yes", inf.after.get("rip_control"))
        self.assertEqual(88, inf.after.get("offset_to_rip"))

    def test_gdb_evidence_can_downgrade_stale_control_rip(self) -> None:
        state = {
            "dynamic_evidence": {
                "evidence": [
                    {
                        "gdb": {
                            "signal": "SIGSEGV",
                            "rip": "0x555555555170",
                            "pc_offset": "0x1170",
                        },
                        "mappings": {"pie_base": "0x555555554000"},
                    }
                ],
                "clusters": [{"count": 1}],
            },
            "capabilities": {
                "control_rip": True,
                "rip_control": "yes",
                "offset_to_rip": 88,
            },
        }
        inf = infer_capabilities(state, {})
        self.assertFalse(inf.after.get("control_rip"))
        self.assertEqual("no", inf.after.get("rip_control"))
        self.assertNotIn("offset_to_rip", inf.after)

    def test_local_verified_ret2win_strategy_promotes_ret2win_path_verified(self) -> None:
        state = {
            "session": {
                "exp": {
                    "strategy": "ret2win",
                    "local_verify_passed": True,
                }
            },
            "capabilities": {},
        }
        inf = infer_capabilities(state, {})
        self.assertTrue(inf.after.get("exploit_success"))
        self.assertTrue(inf.after.get("ret2win_path_verified"))

    def test_dynamic_gdb_offset_candidates_promote_into_capabilities(self) -> None:
        state = {
            "dynamic_evidence": {
                "evidence": [
                    {
                        "gdb": {
                            "signal": "SIGSEGV",
                            "fault_offset_candidate": 65,
                            "static_offset_candidate": 72,
                        }
                    }
                ]
            },
            "capabilities": {},
        }
        inf = infer_capabilities(state, {})
        self.assertEqual(65, inf.after.get("fault_offset_candidate"))
        self.assertEqual(72, inf.after.get("static_offset_candidate"))
        self.assertFalse(inf.after.get("control_rip"))
        self.assertNotIn("offset_to_rip", inf.after)

    def test_fresh_dynamic_gdb_candidates_clear_stale_capability_hints(self) -> None:
        state = {
            "dynamic_evidence": {
                "evidence": [
                    {
                        "gdb": {
                            "signal": "SIGSEGV",
                        }
                    }
                ]
            },
            "capabilities": {
                "fault_offset_candidate": 65,
                "static_offset_candidate": 72,
            },
        }
        inf = infer_capabilities(state, {})
        self.assertNotIn("fault_offset_candidate", inf.after)
        self.assertNotIn("static_offset_candidate", inf.after)

    def test_static_recon_offset_guess_promotes_when_no_dynamic_or_capability_hint_exists(self) -> None:
        state = {
            "static_analysis": {
                "stack_smash_offset_guess": 72,
            },
            "capabilities": {},
        }
        inf = infer_capabilities(state, {})
        self.assertEqual(72, inf.after.get("static_offset_candidate"))
        self.assertFalse(inf.after.get("control_rip"))
        self.assertNotIn("offset_to_rip", inf.after)


if __name__ == "__main__":
    unittest.main()
