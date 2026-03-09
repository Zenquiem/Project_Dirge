#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.text_utils import compact_text, session_tag, truthy_flag


class TextUtilsTests(unittest.TestCase):
    def test_compact_text_normalizes_whitespace_and_truncates(self) -> None:
        self.assertEqual("hello world", compact_text(" hello\n world ", 20))
        self.assertEqual("abcd...", compact_text("abcdefghij", 7))

    def test_truthy_flag_accepts_common_true_forms(self) -> None:
        for value in (True, "1", "true", " yes ", "On"):
            self.assertTrue(truthy_flag(value))
        for value in (False, "0", "false", "", None, "off"):
            self.assertFalse(truthy_flag(value))

    def test_session_tag_sanitizes_and_falls_back(self) -> None:
        self.assertEqual("sess_1.test", session_tag(" sess 1.test "))
        self.assertEqual("shared", session_tag("***"))


if __name__ == "__main__":
    unittest.main()
