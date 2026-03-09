#!/usr/bin/env python3
from __future__ import annotations

import os
import tempfile
import time
import unittest

from core.path_utils import latest_file_by_patterns, parse_any_int


class PathUtilsTests(unittest.TestCase):
    def test_parse_any_int_supports_decimal_hex_and_invalid(self) -> None:
        self.assertEqual(12, parse_any_int(12))
        self.assertEqual(16, parse_any_int("0x10"))
        self.assertEqual(42, parse_any_int("42"))
        self.assertEqual(0, parse_any_int("nope"))

    def test_latest_file_by_patterns_picks_newest_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_path = os.path.join(tmp, "a.json")
            new_path = os.path.join(tmp, "b.json")
            with open(old_path, "w", encoding="utf-8") as f:
                f.write("old")
            time.sleep(0.01)
            with open(new_path, "w", encoding="utf-8") as f:
                f.write("new")

            rel = latest_file_by_patterns(
                ["*.json"],
                root_dir=tmp,
                repo_rel_fn=lambda path: os.path.basename(path),
            )
            self.assertEqual("b.json", rel)


if __name__ == "__main__":
    unittest.main()
