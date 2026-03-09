#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.remote_target_utils import extract_remote_target


class RemoteTargetUtilsTests(unittest.TestCase):
    def test_extract_remote_target_prefers_session_target(self) -> None:
        state = {
            "session": {"remote": {"target": {"host": "sess.host", "port": 31337}}},
            "challenge": {"remote": {"host": "chal.host", "port": 10001}},
        }
        self.assertEqual(("sess.host", 31337), extract_remote_target(state))

    def test_extract_remote_target_falls_back_to_challenge_fields(self) -> None:
        state = {
            "challenge": {
                "target": {"host": "chal.target", "port": 10002},
                "remote_host": "legacy.host",
                "remote_port": 9999,
            }
        }
        self.assertEqual(("chal.target", 10002), extract_remote_target(state))

        legacy = {"challenge": {"remote_host": "legacy.host", "remote_port": 9999}}
        self.assertEqual(("legacy.host", 9999), extract_remote_target(legacy))

    def test_extract_remote_target_returns_empty_when_missing(self) -> None:
        self.assertEqual(("", 0), extract_remote_target({}))


if __name__ == "__main__":
    unittest.main()
