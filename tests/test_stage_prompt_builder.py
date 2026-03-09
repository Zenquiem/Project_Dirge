#!/usr/bin/env python3
from __future__ import annotations

import unittest

from core.stage_prompt_builder import build_stage_prompt


class StagePromptBuilderTests(unittest.TestCase):
    def test_recon_prompt_contains_session_and_binary(self) -> None:
        prompt = build_stage_prompt(
            "recon",
            {"session_id": "sess-1", "binary_path": "bin/chal", "state_digest": "ready"},
            root_dir="/tmp/repo",
            ida_prompt_builder=lambda ctx: "IDA",
            gdb_prompt_builder=lambda ctx: "GDB",
            exploit_stage_level_fn=lambda stage: 3 if stage.startswith("exploit_l") else -1,
            contract_hint="hint",
        )
        self.assertIn("sess-1", prompt)
        self.assertIn("bin/chal", prompt)
        self.assertIn("ready", prompt)
        self.assertIn("hint", prompt)

    def test_ida_and_gdb_prompt_reuse_adapter_builders(self) -> None:
        ida_prompt = build_stage_prompt(
            "ida_slice",
            {"symbol_map": "artifacts/ida/map.json", "active_hypothesis_ids": "h1,h2"},
            root_dir="/tmp/repo",
            ida_prompt_builder=lambda ctx: "IDA_BASE",
            gdb_prompt_builder=lambda ctx: "GDB_BASE",
            exploit_stage_level_fn=lambda stage: -1,
        )
        self.assertIn("IDA_BASE", ida_prompt)
        self.assertIn("symbol_map", ida_prompt)
        self.assertIn("h1,h2", ida_prompt)

        gdb_prompt = build_stage_prompt(
            "gdb_evidence",
            {"repl_cmd_exec_hint": "true", "mutation_manifest": "m1", "mutation_input_ids": "i1"},
            root_dir="/tmp/repo",
            ida_prompt_builder=lambda ctx: "IDA_BASE",
            gdb_prompt_builder=lambda ctx: "GDB_BASE",
            exploit_stage_level_fn=lambda stage: -1,
        )
        self.assertIn("GDB_BASE", gdb_prompt)
        self.assertIn("m1", gdb_prompt)
        self.assertIn("i1", gdb_prompt)

    def test_exploit_prompt_contains_remote_and_exp_path_hints(self) -> None:
        prompt = build_stage_prompt(
            "exploit_l4",
            {
                "session_id": "sess-2",
                "binary_path": "bin/chal",
                "exp_path": "sessions/sess-2/exp/exp.py",
                "allow_remote_exp": "1",
                "repl_cmd_exec_hint": "1",
                "nxoff_libc_free_hint": "1",
            },
            root_dir="/tmp/repo",
            ida_prompt_builder=lambda ctx: "IDA_BASE",
            gdb_prompt_builder=lambda ctx: "GDB_BASE",
            exploit_stage_level_fn=lambda stage: 4 if stage == "exploit_l4" else -1,
        )
        self.assertIn("sessions/sess-2/exp/exp.py", prompt)
        self.assertIn("远程连接参数", prompt)
        self.assertIn("JS/REPL", prompt)
        self.assertIn("NX=off", prompt)


if __name__ == "__main__":
    unittest.main()
