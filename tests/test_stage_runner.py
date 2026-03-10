#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest

from core.stage_runner import (
    get_stage_spec,
    register_stage_receipt,
    stage_prompt_contract,
    write_stage_receipt,
)


class StageRunnerTests(unittest.TestCase):
    def test_get_stage_spec_normalizes_list_fields(self) -> None:
        spec = get_stage_spec(
            {
                "stages": {
                    "recon": {
                        "mcp_tools": [" ida ", "", 123],
                        "required_artifact_keys": ["report"],
                        "required_state_paths": ["session.status"],
                        "required_last_evidence_paths": ["gdb.pc"],
                        "required_last_evidence_any_of_paths": ["gdb.pc", "gdb.signal"],
                        "prompt_contract_lines": [" first ", "second"],
                    }
                }
            },
            "recon",
        )
        self.assertEqual([" ida ", "123"], spec["mcp_tools"])
        self.assertEqual(["report"], spec["required_artifact_keys"])
        self.assertEqual(["session.status"], spec["required_state_paths"])
        self.assertEqual("first second", stage_prompt_contract(spec))

    def test_get_stage_spec_returns_defaults_for_missing_or_invalid_stage(self) -> None:
        spec = get_stage_spec({"stages": {"recon": []}}, "recon")
        self.assertEqual([], spec["mcp_tools"])
        self.assertEqual("", stage_prompt_contract(spec))

    def test_write_and_register_stage_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rel = write_stage_receipt(
                root_dir=tmp,
                session_id="sess-1",
                loop_idx=3,
                stage="recon",
                spec={"mcp_tools": ["ida"]},
                stage_result={"ok": True, "rc": 0},
            )
            self.assertEqual("artifacts/reports/stage_receipt_sess-1_03_recon.json", rel)
            with open(f"{tmp}/{rel}", "r", encoding="utf-8") as f:
                doc = json.load(f)
            self.assertEqual("sess-1", doc["session_id"])
            self.assertEqual("recon", doc["stage"])
            self.assertTrue(doc["result"]["ok"])

            state = {}
            register_stage_receipt(state, "recon", rel)
            latest = state["artifacts_index"]["latest"]["paths"]
            self.assertEqual(rel, latest["stage_receipt"])
            self.assertEqual(rel, latest["recon_receipt"])


if __name__ == "__main__":
    unittest.main()
