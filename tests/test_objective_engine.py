#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest

from core.objective_engine import evaluate_objectives, write_objective_report


class ObjectiveEngineTests(unittest.TestCase):
    def _base_state(self) -> dict:
        return {
            "challenge": {"binary_path": "bin/app", "workdir": "/tmp/app"},
            "protections": {"arch": "amd64", "pie": True},
            "static_analysis": {
                "entrypoints": ["main"],
                "suspects": ["vuln"],
                "hypotheses": [],
            },
            "dynamic_evidence": {
                "evidence": [{"kind": "crash"}],
                "clusters": [{"id": "c1"}],
            },
            "latest_bases": {"pie_base": "0x400000"},
            "session": {
                "exp": {
                    "path": "exp.py",
                    "status": "updated",
                    "local_verify_passed": True,
                },
                "remote": {"last_remote_ok": False, "last_remote_report": ""},
            },
            "capabilities": {"rip_control": True, "exploit_success": False},
        }

    def test_evaluate_objectives_marks_target_achieved_when_all_requirements_met(self) -> None:
        state = self._base_state()
        cfg = {
            "target": {
                "require_stage_completion": ["recon", "ida_slice", "gdb_evidence"],
                "require_exploit_when_enabled": True,
                "require_capabilities_all": ["rip_control"],
            }
        }
        result = evaluate_objectives(state, cfg, enable_exploit=True)
        self.assertTrue(result.target_achieved)
        self.assertEqual([], result.missing_stages)
        self.assertTrue(result.capabilities_all_ok)
        self.assertIn("exploit_l3", result.required_stages)
        self.assertEqual(100, result.score)

    def test_evaluate_objectives_reports_missing_stages_and_competition_success_sources(self) -> None:
        state = self._base_state()
        state["session"]["exp"]["local_verify_passed"] = False
        state["session"]["remote"] = {"last_remote_ok": True, "last_remote_report": "rep.json"}
        cfg = {
            "target": {
                "require_stage_completion": ["recon"],
                "require_exploit_when_enabled": True,
                "require_exploit_stage": "exploit_l2",
                "require_capabilities_any": ["shell", "rip_control"],
            }
        }
        result = evaluate_objectives(state, cfg, enable_exploit=True)
        self.assertFalse(result.target_achieved)
        self.assertIn("exploit_l2", result.missing_stages)
        self.assertTrue(result.capabilities_any_ok)
        self.assertTrue(result.competition_target_achieved)
        self.assertIn("session.remote.last_remote_ok=true", result.competition_reasons)
        self.assertTrue(any("stage incomplete: exploit_l2" in b for b in result.blockers))

    def test_evaluate_objectives_handles_missing_challenge_fields_and_capability_failures(self) -> None:
        state = self._base_state()
        state["challenge"] = {"binary_path": "", "workdir": ""}
        state["capabilities"] = {"shell": False}
        cfg = {
            "target": {
                "require_stage_completion": ["recon"],
                "require_capabilities_all": ["shell"],
                "require_capabilities_any": ["shell", "rip_control"],
            }
        }
        result = evaluate_objectives(state, cfg, enable_exploit=False)
        self.assertFalse(result.target_achieved)
        self.assertFalse(result.capabilities_all_ok)
        self.assertFalse(result.capabilities_any_ok)
        self.assertTrue(any("challenge.binary_path missing" in b for b in result.blockers))
        self.assertTrue(any("challenge.workdir missing" in b for b in result.blockers))
        self.assertTrue(any("required capabilities(all) not satisfied" in b for b in result.blockers))
        self.assertTrue(any("required capabilities(any) not satisfied" in b for b in result.blockers))

    def test_write_objective_report_writes_expected_payload(self) -> None:
        pre = evaluate_objectives(self._base_state(), {"target": {}}, enable_exploit=False)
        post = evaluate_objectives(self._base_state(), {"target": {}}, enable_exploit=False)
        with tempfile.TemporaryDirectory() as tmp:
            rel = write_objective_report(
                root_dir=tmp,
                session_id="sess-1",
                loop_idx=2,
                pre_eval=pre,
                post_eval=post,
                planned_stages=["recon", "ida_slice"],
                executed_stages=["recon"],
            )
            self.assertEqual("artifacts/reports/objective_sess-1_02.json", rel)
            with open(f"{tmp}/{rel}", "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual("sess-1", doc["session_id"])
            self.assertEqual(2, doc["loop"])
            self.assertEqual(["recon", "ida_slice"], doc["planned_stages"])
            self.assertIn("pre", doc)
            self.assertIn("post", doc)


if __name__ == "__main__":
    unittest.main()
