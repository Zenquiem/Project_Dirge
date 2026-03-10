#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from core import session_control


class SessionControlTests(unittest.TestCase):
    def test_acquire_and_release_run_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            lock = session_control.acquire_run_lock(tmp, "sess-1")
            self.assertTrue(lock.acquired)
            self.assertTrue(os.path.exists(lock.path))

            second = session_control.acquire_run_lock(tmp, "sess-1")
            self.assertFalse(second.acquired)
            self.assertIn("session already running", second.error)

            session_control.release_run_lock(lock)
            self.assertFalse(os.path.exists(lock.path))

    def test_acquire_run_lock_reclaims_stale_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = session_control.lock_file_path(tmp, "sess-2")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"pid": 999999, "session_id": "sess-2"}, f)

            with mock.patch.object(session_control, "_pid_alive", return_value=False):
                lock = session_control.acquire_run_lock(tmp, "sess-2")

            self.assertTrue(lock.acquired)
            self.assertTrue(lock.stale_reclaimed)
            session_control.release_run_lock(lock)

    def test_write_read_and_clear_stop_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = session_control.write_stop_request(tmp, "sess-3", " stop now ")
            self.assertTrue(os.path.exists(path))

            doc = session_control.read_stop_request(tmp, "sess-3")
            self.assertEqual("stop now", doc.get("reason"))
            self.assertIn("requested_utc", doc)

            session_control.clear_stop_request(tmp, "sess-3")
            self.assertEqual({}, session_control.read_stop_request(tmp, "sess-3"))

    def test_write_stop_request_blocked_by_env(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(
            os.environ, {"DIRGE_BLOCK_SELF_STOP": "1"}, clear=False
        ):
            with self.assertRaises(PermissionError):
                session_control.write_stop_request(tmp, "sess-4", "blocked")

    def test_read_stop_request_returns_empty_for_bad_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = session_control.stop_flag_path(tmp, "sess-5")
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write("not-json")
            self.assertEqual({}, session_control.read_stop_request(tmp, "sess-5"))


if __name__ == "__main__":
    unittest.main()
