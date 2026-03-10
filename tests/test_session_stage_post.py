#!/usr/bin/env python3
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from session_stage_post import build_failure_context


class SessionStagePostTests(unittest.TestCase):
    def test_build_failure_context_compacts_stage_evidence(self) -> None:
        verify_detail = {
            "run_rc": 1,
            "run_timeout": False,
            "last_error": "x" * 400,
            "run_steps_summary": "y" * 400,
            "runtime_findings": ["a", "b", "c", "d", "e"],
            "stage_evidence": {
                "event_count": 23,
                "stage1_attempts": 5,
                "stage1_eof_attempts": 2,
                "stage1_success_proxy_attempts": 3,
                "stage1_success_proxy_rate": 0.6,
                "stage1_post_recv_raw_len_max": 128,
                "invalid_option_count": 4,
                "wrong_choice_count": 1,
                "menu_prompt_hits": 7,
                "last_stage": "stage1",
                "single_byte_selfcheck_ok": True,
                "leak_values_hex_tail": ["1", "2", "3", "4", "5"],
                "failure_addr_snapshot_tail": {
                    "exit": "0x401000",
                    "prog": "0x402000",
                    "noise": "ignore-me",
                },
                "events_tail": [
                    {"stage": "warmup", "event": "ignored", "blob": "z" * 500},
                    {"stage": "stage1", "event": "send", "attempt": "2", "eof": False, "raw_len": 12},
                    {"stage": "stage1", "event": "post_recv", "raw_len": 99, "extra": [1, 2, 3]},
                    {"stage": "stage1", "event": "single_byte_selfcheck", "ok": True, "pivot_off": "0xdeadbeef"},
                    {"stage": "stage2", "event": "addr_snapshot", "idx": 3, "ret": "0x41414141"},
                ],
                "huge_nested": {"payload": ["x" * 200 for _ in range(20)]},
            },
        }

        ctx = build_failure_context(
            root_dir=str(ROOT),
            stage="exploit_l4",
            rc=1,
            err="boom",
            failure_category="verify_failed",
            attempt_records=[{"attempt": 1}],
            log_rel="",
            exp_verify_report="verify.json",
            tail_text_file_fn=lambda _path, max_bytes: "",
            detect_stage_log_signature_fn=lambda _path: "",
            read_verify_report_detail_fn=lambda _path, max_error_chars: verify_detail,
            shorten_text_fn=lambda text, limit: str(text)[:limit],
            utc_now_fn=lambda: "2026-03-10T14:20:00Z",
        )

        verify = ctx["verify"]
        stage_evidence = verify["stage_evidence"]
        self.assertEqual(23, stage_evidence["event_count"])
        self.assertEqual(5, stage_evidence["stage1_attempts"])
        self.assertEqual(0.6, stage_evidence["stage1_success_proxy_rate"])
        self.assertEqual("stage1", stage_evidence["last_stage"])
        self.assertEqual(["2", "3", "4", "5"], stage_evidence["leak_values_hex_tail"])
        self.assertEqual({"exit": "0x401000", "prog": "0x402000"}, stage_evidence["failure_addr_snapshot_tail"])
        self.assertEqual(4, len(stage_evidence["events_tail"]))
        self.assertEqual("stage1", stage_evidence["events_tail"][0]["stage"])
        self.assertEqual(2, stage_evidence["events_tail"][0]["attempt"])
        self.assertEqual("stage2", stage_evidence["events_tail"][-1]["stage"])
        self.assertNotIn("huge_nested", stage_evidence)
        self.assertEqual(4, len(verify["runtime_findings"]))
        self.assertEqual(260, len(verify["last_error"]))
        self.assertEqual(260, len(verify["run_steps_summary"]))


if __name__ == "__main__":
    unittest.main()
