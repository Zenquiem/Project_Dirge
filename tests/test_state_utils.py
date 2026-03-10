#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest

from core.state_utils import get_path_value, validate_stage_runner_spec, value_present


class StateUtilsTests(unittest.TestCase):
    def test_get_path_value_handles_nested_paths(self) -> None:
        ok, value = get_path_value({"a": {"b": {"c": 1}}}, "a.b.c")
        self.assertTrue(ok)
        self.assertEqual(1, value)
        self.assertEqual((False, None), get_path_value({"a": {}}, "a.x"))

    def test_value_present_matches_runner_expectations(self) -> None:
        self.assertFalse(value_present(None))
        self.assertFalse(value_present("   "))
        self.assertFalse(value_present([]))
        self.assertTrue(value_present(0))
        self.assertTrue(value_present([1]))

    def test_validate_stage_runner_spec_checks_artifacts_state_and_last_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_rel = "artifacts/reports/demo.json"
            artifact_abs = os.path.join(tmp, artifact_rel)
            os.makedirs(os.path.dirname(artifact_abs), exist_ok=True)
            with open(artifact_abs, "w", encoding="utf-8") as f:
                f.write("{}")

            state = {
                "artifacts_index": {"latest": {"paths": {"demo_report": artifact_rel}}},
                "session": {"status": "ok"},
                "dynamic_evidence": {"evidence": [{"gdb": {"pc_offset": "0x10"}}]},
            }
            spec = {
                "required_artifact_keys": ["demo_report"],
                "required_state_paths": ["session.status"],
                "required_last_evidence_paths": ["gdb.pc_offset"],
                "required_last_evidence_any_of_paths": ["gdb.pc_offset", "gdb.signal"],
            }
            self.assertEqual([], validate_stage_runner_spec(state, spec, root_dir=tmp))

    def test_validate_stage_runner_spec_reports_receipt_stage_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_rel = "artifacts/reports/stage_receipt_sess-1_03_recon.json"
            artifact_abs = os.path.join(tmp, artifact_rel)
            os.makedirs(os.path.dirname(artifact_abs), exist_ok=True)
            with open(artifact_abs, "w", encoding="utf-8") as f:
                json.dump({"stage": "ida_slice"}, f)

            state = {"artifacts_index": {"latest": {"paths": {"recon_receipt": artifact_rel}}}}
            spec = {"required_artifact_keys": ["recon_receipt"]}
            errors = validate_stage_runner_spec(state, spec, root_dir=tmp)
            self.assertTrue(any("required receipt stage mismatch" in err for err in errors))

    def test_validate_stage_runner_spec_reports_receipt_session_and_loop_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            artifact_rel = "artifacts/reports/stage_receipt_sess-1_03_recon.json"
            artifact_abs = os.path.join(tmp, artifact_rel)
            os.makedirs(os.path.dirname(artifact_abs), exist_ok=True)
            with open(artifact_abs, "w", encoding="utf-8") as f:
                json.dump({"stage": "recon", "session_id": "sess-2", "loop": 4}, f)

            state = {"artifacts_index": {"latest": {"paths": {"recon_receipt": artifact_rel}}}}
            spec = {"required_artifact_keys": ["recon_receipt"]}
            errors = validate_stage_runner_spec(state, spec, root_dir=tmp)
            self.assertTrue(any("required receipt session mismatch" in err for err in errors))
            self.assertTrue(any("required receipt loop mismatch" in err for err in errors))

    def test_validate_stage_runner_spec_reports_missing_requirements(self) -> None:
        state = {"artifacts_index": {"latest": {"paths": {}}}, "dynamic_evidence": {"evidence": []}}
        spec = {
            "required_artifact_keys": ["missing"],
            "required_state_paths": ["session.status"],
            "required_last_evidence_paths": ["gdb.pc_offset"],
        }
        errors = validate_stage_runner_spec(state, spec, root_dir="/tmp")
        self.assertTrue(any("required artifact key missing/empty" in err for err in errors))
        self.assertTrue(any("required state path missing" in err for err in errors))
        self.assertTrue(any("required last evidence missing" in err for err in errors))


if __name__ == "__main__":
    unittest.main()
