#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import sync_state_meta


class SyncStateMetaCliTests(unittest.TestCase):
    def test_main_carries_competition_reasons_into_meta_objective(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            meta_path = root / "sessions" / "sess-a" / "meta.json"
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            meta_path.write_text(json.dumps({"status": "pending"}), encoding="utf-8")
            state_path.write_text(
                json.dumps(
                    {
                        "session": {
                            "session_id": "sess-a",
                            "status": "running",
                            "remote": {"last_remote_ok": True},
                        },
                        "progress": {
                            "objectives": {
                                "score": 7,
                                "target_achieved": False,
                                "competition_target_achieved": False,
                                "competition_reasons": [
                                    "session.remote.last_remote_ok=true",
                                    "remote_exp_verify_report marker hit",
                                ],
                                "missing_stages": ["exploit_l4"],
                                "blockers": [],
                                "last_objective_report": "artifacts/reports/objective.json",
                                "last_eval_utc": "2026-03-10T13:33:00Z",
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(sync_state_meta, "ROOT_DIR", str(root)):
                with patch.object(sync_state_meta, "DEFAULT_STATE", str(state_path)):
                    with patch.object(
                        sys,
                        "argv",
                        [
                            "sync_state_meta.py",
                            "--state",
                            str(state_path),
                            "--session-id",
                            "sess-a",
                        ],
                    ):
                        rc = sync_state_meta.main()

            self.assertEqual(0, rc)
            written = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual("remote_verified", written["status"])
            self.assertTrue(written["objective"]["competition_target_achieved"])
            self.assertEqual(
                [
                    "session.remote.last_remote_ok=true",
                    "remote_exp_verify_report marker hit",
                ],
                written["objective"]["competition_reasons"],
            )
            self.assertEqual(["exploit_l4"], written["objective"]["missing_stages"])

    def test_main_creates_and_populates_challenge_meta_from_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            meta_path = root / "sessions" / "sess-a" / "meta.json"
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            meta_path.write_text(json.dumps({"status": "pending"}), encoding="utf-8")
            state_path.write_text(
                json.dumps(
                    {
                        "session": {"session_id": "sess-a", "status": "running"},
                        "challenge": {
                            "name": "demo-bin",
                            "binary_path": "/tmp/demo-bin",
                            "workdir": "/tmp/work",
                            "import_meta": {"source_dir": "/imports/demo"},
                        },
                    }
                ),
                encoding="utf-8",
            )

            with patch.object(sync_state_meta, "ROOT_DIR", str(root)):
                with patch.object(sync_state_meta, "DEFAULT_STATE", str(state_path)):
                    with patch.object(
                        sys,
                        "argv",
                        [
                            "sync_state_meta.py",
                            "--state",
                            str(state_path),
                            "--session-id",
                            "sess-a",
                        ],
                    ):
                        rc = sync_state_meta.main()

            self.assertEqual(0, rc)
            written = json.loads(meta_path.read_text(encoding="utf-8"))
            self.assertEqual(
                {
                    "name": "demo-bin",
                    "binary_path": "/tmp/demo-bin",
                    "work_dir": "/tmp/work",
                    "source_dir": "/imports/demo",
                },
                written["challenge"],
            )


if __name__ == "__main__":
    unittest.main()
