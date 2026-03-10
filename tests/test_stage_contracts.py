#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.stage_contracts import validate_stage_contract


class StageContractsTests(unittest.TestCase):
    def test_validate_stage_contract_passes_for_satisfied_rules(self) -> None:
        state = {
            "session": {"status": "running", "loop": 2},
            "challenge": {"binary_path": "bin/app"},
            "artifacts": {"reports": ["a", "b"]},
            "progress": {"notes": ["x"]},
        }
        contracts = {
            "stages": {
                "recon": {
                    "must_equal": {"session.status": "running"},
                    "required_present": ["challenge.binary_path"],
                    "required_non_empty": ["challenge.binary_path"],
                    "at_least": {"session.loop": 1},
                    "max_items": {"artifacts.reports": 3},
                    "any_of_non_empty": [["progress.summary", "progress.notes"]],
                }
            }
        }
        self.assertEqual([], validate_stage_contract(state, "recon", contracts))

    def test_validate_stage_contract_reports_multiple_failures(self) -> None:
        state = {
            "session": {"status": "idle", "loop": "oops"},
            "challenge": {"binary_path": "   "},
            "artifacts": {"reports": "not-a-list"},
            "progress": {},
        }
        contracts = {
            "stages": {
                "recon": {
                    "must_equal": {"session.status": "running"},
                    "required_present": ["challenge.workdir"],
                    "required_non_empty": ["challenge.binary_path"],
                    "at_least": {"session.loop": 1},
                    "max_items": {"artifacts.reports": "bad-limit"},
                    "any_of_non_empty": [["progress.summary", "progress.notes"]],
                }
            }
        }
        errors = validate_stage_contract(state, "recon", contracts)
        self.assertTrue(any("must_equal failed" in e for e in errors))
        self.assertTrue(any("required_present missing" in e for e in errors))
        self.assertTrue(any("required_non_empty failed" in e for e in errors))
        self.assertTrue(any("at_least not numeric" in e for e in errors))
        self.assertTrue(any("max_items expects list" in e for e in errors))
        self.assertTrue(any("any_of_non_empty failed" in e for e in errors))

    def test_validate_stage_contract_handles_missing_stage_or_empty_contract(self) -> None:
        self.assertEqual([], validate_stage_contract({}, "recon", {}))
        self.assertEqual([], validate_stage_contract({}, "recon", {"stages": {"recon": {}}}))


if __name__ == "__main__":
    unittest.main()
