#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
import sys

SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from session_state_sync import sync_meta_from_state


class SessionStateSyncTests(unittest.TestCase):
    def test_sync_meta_from_state_skips_session_scoped_fields_on_session_id_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta_path = root / "sessions" / "sess-a" / "meta.json"
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            original = {
                "status": "pending",
                "codex": {"enabled": False, "pid": None},
                "exp": {"status": "stub_generated"},
                "challenge": {"name": "demo", "work_dir": "/old"},
                "latest_artifacts": {"old": "artifacts/reports/old.json"},
                "objective": {"score": 1},
            }
            meta_path.write_text(json.dumps(original), encoding="utf-8")

            state = {
                "session": {
                    "session_id": "sess-b",
                    "status": "running",
                    "codex_enabled": True,
                    "codex_pid": 123,
                    "exp": {"status": "updated", "local_verify_passed": True},
                },
                "challenge": {"name": "new-demo", "workdir": "/new"},
                "artifacts_index": {"latest": {"paths": {"new": "artifacts/reports/new.json"}}},
                "progress": {"objectives": {"score": 9, "target_achieved": True}},
            }

            sync_meta_from_state(
                str(root),
                "sess-a",
                state,
                report_rel="artifacts/reports/decision.json",
                metrics_rel="artifacts/reports/metrics.json",
                utc_now_fn=lambda: "2026-03-10T13:20:00Z",
            )

            written = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual("pending", written["status"])
            self.assertEqual(original["codex"], written["codex"])
            self.assertEqual(original["exp"], written["exp"])
            self.assertEqual(original["challenge"], written["challenge"])
            self.assertEqual(original["latest_artifacts"], written["latest_artifacts"])
            self.assertEqual(original["objective"], written["objective"])
            self.assertEqual("artifacts/reports/decision.json", written["latest_run"]["report"])
            self.assertEqual("artifacts/reports/metrics.json", written["latest_run"]["metrics"])
            self.assertEqual("2026-03-10T13:20:00Z", written["latest_run"]["updated_utc"])

    def test_sync_meta_from_state_carries_competition_reasons_when_session_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta_path = root / "sessions" / "sess-a" / "meta.json"
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            meta_path.write_text(json.dumps({"status": "pending"}), encoding="utf-8")

            state = {
                "session": {
                    "session_id": "sess-a",
                    "status": "running",
                    "remote": {"last_remote_ok": True},
                },
                "progress": {
                    "objectives": {
                        "score": 5,
                        "target_achieved": False,
                        "competition_target_achieved": False,
                        "competition_reasons": ["session.remote.last_remote_ok=true"],
                        "missing_stages": ["exploit_l4"],
                        "blockers": [],
                        "last_objective_report": "artifacts/reports/objective.json",
                        "last_eval_utc": "2026-03-10T13:21:00Z",
                    }
                },
            }

            sync_meta_from_state(str(root), "sess-a", state)
            written = json.loads(meta_path.read_text(encoding="utf-8"))

            self.assertEqual("running", written["status"])
            self.assertTrue(written["objective"]["competition_target_achieved"])
            self.assertEqual(["session.remote.last_remote_ok=true"], written["objective"]["competition_reasons"])
            self.assertEqual(["exploit_l4"], written["objective"]["missing_stages"])


if __name__ == "__main__":
    unittest.main()
