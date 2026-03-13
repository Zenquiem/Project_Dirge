import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(ROOT_DIR, "scripts")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import scripts.gdb_direct_probe as gdb_direct_probe
from core.gdb_evidence_utils import (
    cyclic_bytes_lower_triplet,
    cyclic_bytes_pwntools_lower,
    recover_cyclic_offset,
    recover_offset_hints,
)
from scripts.gdb_direct_probe import (
    _abi_info,
    _cyclic_find_offset,
    _cyclic_window_from_input,
    _select_direct_gdb_stdin,
    _stack_probe_command,
    compute_pc_offset,
    gdb_mcp_cmd,
    gdb_mcp_cwd,
    parse_pie_base,
    parse_rip,
    parse_stack_top_qword,
    parse_stack_words,
)


class GdbDirectProbeTests(unittest.TestCase):
    def test_parse_rip_accepts_eip_and_pc(self) -> None:
        self.assertEqual(parse_rip("eip            0x8049170"), "0x8049170")
        self.assertEqual(parse_rip("pc             0x401170"), "0x401170")

    def test_stack_probe_command_uses_i386_stack_words(self) -> None:
        self.assertEqual(_stack_probe_command({"arch": "i386", "bits": 32}), ("x/16wx $esp", 4))
        self.assertEqual(_stack_probe_command({"arch": "amd64", "bits": 64}), ("x/24gx $rsp", 8))

    def test_abi_info_detects_i386_elf(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            fake_bin = os.path.join(td, "chall32")
            with open(fake_bin, "wb") as f:
                f.write(b"\x7fELF" + bytes([1, 1, 1]) + b"\x00" * 11 + (3).to_bytes(2, "little") + b"\x00" * 16)
            abi = _abi_info(fake_bin)
        self.assertEqual(abi.get("arch"), "i386")
        self.assertEqual(abi.get("bits"), 32)

    def test_compute_pc_offset_accepts_non_pie_zero_base(self) -> None:
        self.assertEqual(compute_pc_offset("0x401170", "0x0"), "0x401170")

    def test_recover_cyclic_offset_prefers_rip_before_stack(self) -> None:
        cyclic = gdb_direct_probe._cyclic_bytes(160)
        rip = "0x" + cyclic[88:96][::-1].hex()
        stack_word = "0x" + cyclic[40:48][::-1].hex()
        off, source = recover_cyclic_offset(rip, [stack_word], 160, stack_word_size=8)
        self.assertEqual(off, 88)
        self.assertEqual(source, "rip")

    def test_recover_cyclic_offset_uses_stack_word_size_for_source(self) -> None:
        cyclic = gdb_direct_probe._cyclic_bytes(160)
        stack_word = "0x" + cyclic[44:48][::-1].hex()
        off, source = recover_cyclic_offset("", [stack_word], 160, stack_word_size=4)
        self.assertEqual(off, 44)
        self.assertEqual(source, "esp")

    def test_recover_cyclic_offset_accepts_pwntools_lowercase_pattern(self) -> None:
        cyclic = cyclic_bytes_pwntools_lower(160)
        stack_word = "0x" + cyclic[72:76][::-1].hex()
        off, source = recover_cyclic_offset("", [stack_word], 160, stack_word_size=8)
        self.assertEqual(off, 72)
        self.assertEqual(source, "rsp")

    def test_recover_cyclic_offset_accepts_fault_address_with_prefixed_garbage(self) -> None:
        cyclic = cyclic_bytes_lower_triplet(72)
        fault_word = b"i" + cyclic[65:72]
        fault_hex = "0x" + fault_word[::-1].hex()
        off, source = recover_cyclic_offset("0x0", [], 72, stack_word_size=8, extra_values=[("fault", fault_hex)])
        self.assertEqual(off, 65)
        self.assertEqual(source, "fault")

    def test_recover_offset_hints_promotes_rip_control_from_stack(self) -> None:
        cyclic = gdb_direct_probe._cyclic_bytes(160)
        stack_word = "0x" + cyclic[88:96][::-1].hex()
        hints = recover_offset_hints(
            value_hex="",
            stack_words=[stack_word],
            cyclic_len=160,
            stack_word_size=8,
            fault_addr="",
            static_guess=0,
        )
        self.assertTrue(hints.get("control_rip"))
        self.assertEqual(88, hints.get("offset_to_rip"))
        self.assertEqual("rsp", hints.get("offset_source"))
        self.assertEqual(0, hints.get("fault_offset_candidate"))
        self.assertEqual(0, hints.get("static_offset_candidate"))

    def test_recover_offset_hints_keeps_fault_only_offset_as_non_control(self) -> None:
        cyclic = cyclic_bytes_lower_triplet(72)
        fault_word = b"i" + cyclic[65:72]
        fault_hex = "0x" + fault_word[::-1].hex()
        hints = recover_offset_hints(
            value_hex="0x0",
            stack_words=[],
            cyclic_len=72,
            stack_word_size=8,
            fault_addr=fault_hex,
            static_guess=72,
        )
        self.assertFalse(hints.get("control_rip"))
        self.assertEqual(0, hints.get("offset_to_rip"))
        self.assertEqual("", hints.get("offset_source"))
        self.assertEqual(65, hints.get("fault_offset_candidate"))
        self.assertEqual(72, hints.get("static_offset_candidate"))

    def test_select_direct_gdb_stdin_accepts_text_seed(self) -> None:
        with mock.patch.dict(os.environ, {"DIRGE_GDB_DIRECT_STDIN_TEXT": "AAAA"}, clear=False):
            data, source, kind, cyclic_len = _select_direct_gdb_stdin()
        self.assertEqual(data, b"AAAA")
        self.assertEqual(source, "text-env")
        self.assertEqual(kind, "seeded_text")
        self.assertEqual(cyclic_len, 4)

    def test_select_direct_gdb_stdin_accepts_hex_seed(self) -> None:
        with mock.patch.dict(os.environ, {"DIRGE_GDB_DIRECT_STDIN_HEX": "41 42 43 44"}, clear=False):
            data, source, kind, cyclic_len = _select_direct_gdb_stdin()
        self.assertEqual(data, b"ABCD")
        self.assertEqual(source, "hex-env")
        self.assertEqual(kind, "seeded_hex")
        self.assertEqual(cyclic_len, 4)

    def test_select_direct_gdb_stdin_accepts_repo_relative_file_seed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            payload_rel = os.path.join("challenge", "cyclic.bin")
            payload_abs = os.path.join(td, payload_rel)
            os.makedirs(os.path.dirname(payload_abs), exist_ok=True)
            with open(payload_abs, "wb") as f:
                f.write(b"aA0aA1aA2aA3")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {"DIRGE_GDB_DIRECT_STDIN_FILE": payload_rel},
                clear=True,
            ):
                cwd_before = os.getcwd()
                try:
                    os.chdir("/")
                    data, source, kind, cyclic_len = _select_direct_gdb_stdin()
                finally:
                    os.chdir(cwd_before)
        self.assertEqual(data, b"aA0aA1aA2aA3")
        self.assertEqual(source, f"file:{payload_rel}")
        self.assertEqual(kind, "seeded_file")
        self.assertEqual(cyclic_len, 12)

    def test_select_direct_gdb_stdin_accepts_binary_dir_relative_file_seed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge", "bench_local_nonpie")
            payload_abs = os.path.join(challenge_dir, "cyclic88.txt")
            os.makedirs(challenge_dir, exist_ok=True)
            with open(payload_abs, "wb") as f:
                f.write(b"aA0aA1aA2aA3")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {"DIRGE_GDB_DIRECT_STDIN_FILE": "./cyclic88.txt"},
                clear=True,
            ):
                cwd_before = os.getcwd()
                try:
                    os.chdir("/")
                    data, source, kind, cyclic_len = _select_direct_gdb_stdin(search_dirs=[challenge_dir])
                finally:
                    os.chdir(cwd_before)
        self.assertEqual(data, b"aA0aA1aA2aA3")
        self.assertEqual(source, "file:./cyclic88.txt")
        self.assertEqual(kind, "seeded_file")
        self.assertEqual(cyclic_len, 12)

    def test_gdb_mcp_overrides_resolve_repo_relative_paths(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = os.path.join(td, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            fake_server = os.path.join(scripts_dir, "fake_gdb_mcp.py")
            with open(fake_server, "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": "python3 -u scripts/fake_gdb_mcp.py",
                    "DIRGE_GDB_MCP_CWD": ".",
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
                cwd = gdb_mcp_cwd()
        self.assertEqual(cmd[0], "python3")
        self.assertEqual(cmd[1], "-u")
        self.assertEqual(cmd[2], os.path.join(td, "scripts", "fake_gdb_mcp.py"))
        self.assertEqual(cwd, td)

    def test_gdb_mcp_overrides_resolve_env_launcher_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = os.path.join(td, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            fake_server = os.path.join(scripts_dir, "fake_gdb_mcp.py")
            with open(fake_server, "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -u scripts/fake_gdb_mcp.py",
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
        self.assertEqual(cmd[0], "/usr/bin/env")
        self.assertEqual(cmd[1], "python3")
        self.assertEqual(cmd[2], "-u")
        self.assertEqual(cmd[3], os.path.join(td, "scripts", "fake_gdb_mcp.py"))

    def test_gdb_mcp_module_launcher_keeps_module_name_unmodified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -m fake_gdb_mcp",
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
        self.assertEqual(cmd, ["/usr/bin/env", "python3", "-m", "fake_gdb_mcp"])

    def test_gdb_mcp_python_flag_values_do_not_mask_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = os.path.join(td, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            fake_server = os.path.join(scripts_dir, "fake_gdb_mcp.py")
            with open(fake_server, "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 -W ignore -X dev scripts/fake_gdb_mcp.py",
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
        self.assertEqual(
            cmd,
            ["/usr/bin/env", "python3", "-W", "ignore", "-X", "dev", os.path.join(td, "scripts", "fake_gdb_mcp.py")],
        )

    def test_gdb_mcp_env_split_string_normalizes_nested_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = os.path.join(td, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            fake_server = os.path.join(scripts_dir, "fake_gdb_mcp.py")
            with open(fake_server, "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": 'env -S "python3 -u scripts/fake_gdb_mcp.py"',
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
        self.assertEqual(
            cmd,
            ["env", "-S", f"python3 -u {os.path.join(td, 'scripts', 'fake_gdb_mcp.py')}"]
        )

    def test_gdb_mcp_python_long_flag_values_do_not_mask_script_path(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            scripts_dir = os.path.join(td, "scripts")
            os.makedirs(scripts_dir, exist_ok=True)
            fake_server = os.path.join(scripts_dir, "fake_gdb_mcp.py")
            with open(fake_server, "w", encoding="utf-8") as f:
                f.write("print('ok')\n")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.dict(
                os.environ,
                {
                    "DIRGE_GDB_MCP_CMD": "/usr/bin/env python3 --check-hash-based-pycs always scripts/fake_gdb_mcp.py",
                },
                clear=True,
            ), mock.patch.object(gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False):
                cmd = gdb_mcp_cmd()
        self.assertEqual(
            cmd,
            [
                "/usr/bin/env",
                "python3",
                "--check-hash-based-pycs",
                "always",
                os.path.join(td, "scripts", "fake_gdb_mcp.py"),
            ],
        )

    def test_gdb_mcp_prefers_path_binary_without_override_or_legacy_install(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False
        ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value="/usr/local/bin/gdb-mcp"):
            self.assertEqual(gdb_mcp_cmd(), ["/usr/local/bin/gdb-mcp"])
            self.assertEqual(gdb_mcp_cwd(), "")

    def test_gdb_mcp_falls_back_to_user_local_binary_when_path_lookup_misses(self) -> None:
        local_bin = "/home/test/.local/bin/gdb-mcp"
        with mock.patch.dict(os.environ, {"HOME": "/home/test"}, clear=True), mock.patch.object(
            gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False
        ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value=None), mock.patch.object(
            gdb_direct_probe.os.path, "isfile", side_effect=lambda path: path == local_bin
        ), mock.patch.object(gdb_direct_probe.os, "access", side_effect=lambda path, mode: path == local_bin):
            self.assertEqual(gdb_mcp_cmd(), [local_bin])
            self.assertEqual(gdb_mcp_cwd(), "")

    def test_gdb_mcp_legacy_fallback_uses_home_relative_paths(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=True
        ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value=None), mock.patch.object(
            gdb_direct_probe.os.path, "isfile", return_value=False
        ), mock.patch.object(gdb_direct_probe.os, "access", return_value=False), mock.patch.object(
            gdb_direct_probe, "LEGACY_GDB_MCP_CWD", "/tmp/fake-home/桌面/mcp/GDB-MCP"
        ), mock.patch.object(
            gdb_direct_probe,
            "LEGACY_GDB_MCP_CMD",
            ["/tmp/fake-home/桌面/mcp/GDB-MCP/.venv/bin/python", "server.py"],
        ):
            self.assertEqual(gdb_mcp_cmd(), ["/tmp/fake-home/桌面/mcp/GDB-MCP/.venv/bin/python", "server.py"])
            self.assertEqual(gdb_mcp_cwd(), "/tmp/fake-home/桌面/mcp/GDB-MCP")

    def test_gdb_mcp_returns_empty_without_override_path_or_legacy_install(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False
        ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value=None), mock.patch.object(
            gdb_direct_probe.os.path, "isfile", return_value=False
        ), mock.patch.object(gdb_direct_probe.os, "access", return_value=False):
            self.assertEqual(gdb_mcp_cmd(), [])
            self.assertEqual(gdb_mcp_cwd(), "")

    def test_mcp_stdio_client_allows_empty_cwd_for_path_discovered_binary(self) -> None:
        with mock.patch.object(gdb_direct_probe.subprocess, "Popen") as popen:
            proc = mock.Mock()
            proc.stdin = mock.Mock()
            proc.stdout = mock.Mock()
            proc.stdout.fileno.return_value = 0
            proc.poll.return_value = None
            proc.stdout.readline.side_effect = [
                '{"jsonrpc":"2.0","id":1,"result":{}}\n',
            ]
            popen.return_value = proc
            client = gdb_direct_probe.MCPStdioClient(["/usr/local/bin/gdb-mcp"], "")
            with mock.patch.object(gdb_direct_probe.select, "select", return_value=([0], [], [])):
                client.start()

        self.assertEqual(popen.call_args.kwargs.get("cwd"), None)

    def test_cyclic_window_detects_explicit_cyclic_seed(self) -> None:
        info = _cyclic_window_from_input(b"aA0aA1aA2aA3")
        self.assertTrue(info.get("cyclic_compatible"))
        self.assertEqual(info.get("cyclic_offset_start"), 0)
        self.assertEqual(info.get("cyclic_span"), 12)

    def test_cyclic_window_accepts_cyclic_seed_with_newline_suffix(self) -> None:
        info = _cyclic_window_from_input(b"aA0aA1aA2aA3\n")
        self.assertTrue(info.get("cyclic_compatible"))
        self.assertEqual(info.get("cyclic_offset_start"), 0)
        self.assertEqual(info.get("cyclic_window_len"), 12)
        self.assertEqual(info.get("cyclic_span"), 12)

    def test_cyclic_window_accepts_pwntools_lowercase_seed(self) -> None:
        info = _cyclic_window_from_input(b"aaaabaaacaaadaaaeaaafaaa\n")
        self.assertTrue(info.get("cyclic_compatible"))
        self.assertEqual(info.get("cyclic_offset_start"), 0)
        self.assertGreaterEqual(info.get("cyclic_window_len"), 24)

    def test_cyclic_window_rejects_non_cyclic_seed(self) -> None:
        info = _cyclic_window_from_input(b"AAAA")
        self.assertFalse(info.get("cyclic_compatible"))
        self.assertEqual(info.get("cyclic_span"), 0)

    def test_parse_stack_words_collects_multiple_words(self) -> None:
        raw = """0x7fffffffdc20: 0x0000000000000000 0x3144613044613943\n0x7fffffffdc30: 0x6144336144326144 0x4436614435614434\n"""
        self.assertEqual(
            parse_stack_words(raw),
            [
                "0x0000000000000000",
                "0x3144613044613943",
                "0x6144336144326144",
                "0x4436614435614434",
            ],
        )
        self.assertEqual(parse_stack_top_qword(raw), "0x0000000000000000")

    def test_stack_slice_offset_recovery_can_skip_unhelpful_top_word(self) -> None:
        raw = """0x7fffffffdc20: 0x0000000000000000 0x3144613044613943\n0x7fffffffdc30: 0x6144336144326144 0x4436614435614434\n"""
        stack_words = parse_stack_words(raw)
        self.assertEqual(_cyclic_find_offset(stack_words[0], 320), -1)
        recovered = next((
            _cyclic_find_offset(word, 320)
            for word in stack_words
            if _cyclic_find_offset(word, 320) >= 0
        ), -1)
        self.assertEqual(recovered, 88)

    def test_parse_stack_words_can_scan_deeper_stack_window(self) -> None:
        raw = "\n".join(
            [f"0x7fffffffdc{i:02x}: 0x0000000000000000 0x0000000000000000" for i in range(0x20, 0xa0, 0x10)]
            + ["0x7fffffffdd00: 0x3144613044613943 0x00007ffff7dea24a"]
        )
        stack_words = parse_stack_words(raw, max_lines=16)
        self.assertEqual(_cyclic_find_offset(stack_words[-2], 320), 88)

    def test_parse_pie_base_ignores_non_mapping_lines(self) -> None:
        raw = """Program received signal SIGSEGV, Segmentation fault.
0x0000000000401170 in main () at challenge/bench_local_nonpie/chall.c:11
rip            0x401170            0x401170 <main+58>
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
            0x400000           0x401000     0x1000        0x0  r--p   /home/ubuntu/.openclaw/workspace/Project_Dirge/challenge/bench_local_nonpie/chall
            0x401000           0x402000     0x1000     0x1000  r-xp   /home/ubuntu/.openclaw/workspace/Project_Dirge/challenge/bench_local_nonpie/chall
"""
        self.assertEqual(
            parse_pie_base(raw, "/home/ubuntu/.openclaw/workspace/Project_Dirge/challenge/bench_local_nonpie/chall"),
            "0x400000",
        )

    def test_main_repo_anchors_relative_state_path_from_non_root_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge", "bench_local_nonpie")
            os.makedirs(challenge_dir, exist_ok=True)
            state_dir = os.path.join(td, "state")
            os.makedirs(state_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(state_dir, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(
                    {"challenge": {"binary_path": "challenge/bench_local_nonpie/chall"}, "protections": {"pie": False}},
                    f,
                )

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False
            ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value=None), mock.patch.object(
                gdb_direct_probe.os.path, "isfile", return_value=False
            ), mock.patch.object(gdb_direct_probe.os, "access", return_value=False), mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    "state/state.json",
                    "--session-id",
                    "bench_missing_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ):
                cwd_before = os.getcwd()
                try:
                    os.chdir(challenge_dir)
                    rc = gdb_direct_probe.main()
                finally:
                    os.chdir(cwd_before)

            self.assertEqual(rc, 2)

    def test_main_fails_fast_without_gdb_mcp_config_or_legacy_install(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "_legacy_gdb_mcp_available", return_value=False
            ), mock.patch.object(gdb_direct_probe.shutil, "which", return_value=None), mock.patch.object(
                gdb_direct_probe.os.path, "isfile", return_value=False
            ), mock.patch.object(gdb_direct_probe.os, "access", return_value=False), mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_missing_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 2)

    def test_main_accepts_path_discovered_gdb_mcp_without_explicit_cwd(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.cmd = list(cmd)
                self.cwd = cwd

            def start(self):
                return None

            def close(self):
                return None

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "gdb_start":
                    return {"result": {"content": [{"type": "text", "text": "Session ID: fake-session"}]}}
                if name == "gdb_terminate":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                text = ""
                if command == "info proc mappings":
                    text = (
                        "Mapped address spaces:\n\n"
                        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                        f"            0x400000           0x401000     0x1000        0x0  r--p   {binary_path}\n"
                        f"            0x401000           0x402000     0x1000     0x1000  r-xp   {binary_path}\n"
                    )
                elif command == "info registers":
                    text = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    text = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    text = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    text = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    text = "0x7fffffffdc20: 0x3144613044613943 0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": text}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", FakeClient
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["/usr/local/bin/gdb-mcp"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=""
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_path_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)

    def test_main_reports_missing_gdb_mcp_with_path_aware_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cmd", return_value=[]
            ), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=""
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_missing_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ), mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 2)
            self.assertIn("install `gdb-mcp` on PATH", stderr.getvalue())

    def test_main_surfaces_startup_error_when_gdb_mcp_api_is_incompatible(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.cmd = list(cmd)
                self.cwd = cwd

            def start(self):
                return None

            def close(self):
                return None

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "gdb_start":
                    return {"result": {"content": [{"type": "text", "text": "Unknown tool: gdb_start"}]}}
                raise AssertionError("probe should stop after incompatible startup")

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", FakeClient
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["/usr/local/bin/gdb-mcp"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=""
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_incompatible_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ), mock.patch("sys.stderr", new_callable=io.StringIO) as stderr:
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 2)
            self.assertIn("startup failed: Unknown tool: gdb_start", stderr.getvalue())

    def test_main_adapts_to_tools_list_start_binary_and_stop_session(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.cmd = list(cmd)
                self.cwd = cwd
                self.calls = []

            def start(self):
                return None

            def close(self):
                return None

            def tools_list(self, timeout_sec=20.0):
                return {
                    "result": {
                        "tools": [
                            {"name": "start_binary"},
                            {"name": "gdb_command"},
                            {"name": "stop_session"},
                        ]
                    }
                }

            def tool_call(self, name, arguments, timeout_sec=20.0):
                self.calls.append((name, dict(arguments)))
                if name == "start_binary":
                    return {
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps({"session_id": "realistic-session", "session": {"id": "realistic-session"}}),
                                }
                            ]
                        }
                    }
                if name == "stop_session":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                text = ""
                if command == "info proc mappings":
                    text = (
                        "Mapped address spaces:\n\n"
                        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                        f"            0x400000           0x401000     0x1000        0x0  r--p   {binary_path}\n"
                        f"            0x401000           0x402000     0x1000     0x1000  r-xp   {binary_path}\n"
                    )
                elif command == "info registers":
                    text = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    text = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    text = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    text = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    text = "0x7fffffffdc20: 0x3144613044613943 0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": text}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            fake_client = FakeClient(["/usr/local/bin/gdb-mcp"], "")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", return_value=fake_client
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["/usr/local/bin/gdb-mcp"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=""
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_tools_list_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)
            self.assertEqual(fake_client.calls[0][0], "start_binary")
            self.assertEqual(fake_client.calls[0][1].get("binary_path"), binary_path)
            self.assertEqual(fake_client.calls[0][1].get("cwd"), challenge_dir)
            self.assertEqual(fake_client.calls[-1][0], "stop_session")
            self.assertEqual(fake_client.calls[-1][1].get("session_id"), "realistic-session")

    def test_main_decodes_json_wrapped_gdb_command_output_from_live_style_server(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.cmd = list(cmd)
                self.cwd = cwd

            def start(self):
                return None

            def close(self):
                return None

            def tools_list(self, timeout_sec=20.0):
                return {
                    "result": {
                        "tools": [
                            {"name": "start_binary"},
                            {"name": "gdb_command"},
                            {"name": "stop_session"},
                        ]
                    }
                }

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "start_binary":
                    return {
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps({"session_id": "live-style-session"}),
                                }
                            ]
                        }
                    }
                if name == "stop_session":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                output = ""
                if command == "info proc mappings":
                    output = (
                        "Mapped address spaces:\n\n"
                        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                        f"            0x400000           0x401000     0x1000        0x0  r--p   {binary_path}\n"
                        f"            0x401000           0x402000     0x1000     0x1000  r-xp   {binary_path}\n"
                    )
                elif command == "info registers":
                    output = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    output = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    output = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    output = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    output = "0x7fffffffdc20:\t0x3144613044613943\t0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": json.dumps({"output": output})}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            fake_client = FakeClient(["/usr/local/bin/gdb-mcp"], "")
            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", return_value=fake_client
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["/usr/local/bin/gdb-mcp"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=""
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_live_style_json_wrapped_gdb_mcp",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            self.assertEqual(state.get("latest_bases", {}).get("pie_base"), "0x400000")
            self.assertEqual(state.get("gdb", {}).get("pc_offset"), "0x1170")
            self.assertTrue(state.get("capabilities", {}).get("control_rip"))
            self.assertEqual(state.get("capabilities", {}).get("offset_to_rip"), 88)

    def test_main_clears_stale_rip_control_when_fresh_probe_has_no_offset(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.commands = []

            def start(self):
                return None

            def close(self):
                return None

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "gdb_start":
                    return {
                        "result": {
                            "content": [
                                {"type": "text", "text": "Session ID: fake-session"},
                            ]
                        }
                    }
                if name == "gdb_terminate":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                self.commands.append(command)
                text = ""
                if command == "info proc mappings":
                    text = (
                        "Mapped address spaces:\n\n"
                        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                        "            0x400000           0x401000     0x1000        0x0  r--p   /tmp/chall\n"
                        "            0x401000           0x402000     0x1000     0x1000  r-xp   /tmp/chall\n"
                    )
                elif command == "info registers":
                    text = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    text = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    text = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    text = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    text = "0x7fffffffdc20: 0x0000000000000000 0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": text}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "challenge": {"binary_path": "challenge/chall"},
                        "protections": {"pie": False},
                        "capabilities": {"control_rip": True, "rip_control": "yes", "offset_to_rip": 88},
                        "latest_bases": {"offset_to_rip": 88},
                        "io_profile": {"offset_to_rip": 88},
                    },
                    f,
                )

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", FakeClient
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["python3", "fake_gdb_mcp.py"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=td
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_noncontrol",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)
            with open(state_path, "r", encoding="utf-8") as f:
                updated = json.load(f)
            self.assertFalse(updated.get("capabilities", {}).get("control_rip"))
            self.assertEqual(updated.get("capabilities", {}).get("rip_control"), "no")
            self.assertNotIn("offset_to_rip", updated.get("capabilities", {}))
            self.assertNotIn("offset_to_rip", updated.get("latest_bases", {}))
            self.assertNotIn("offset_to_rip", updated.get("io_profile", {}))
            self.assertNotIn(
                "offset_to_rip",
                updated.get("dynamic_evidence", {}).get("evidence", [{}])[0].get("gdb", {}),
            )

    def test_main_accepts_non_pie_zero_base_and_prefers_post_run_registers(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.commands = []

            def start(self):
                return None

            def close(self):
                return None

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "gdb_start":
                    return {
                        "result": {
                            "content": [
                                {"type": "text", "text": "Session ID: fake-session"},
                            ]
                        }
                    }
                if name == "gdb_terminate":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                self.commands.append(command)
                text = ""
                if command == "info registers":
                    text = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    text = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    text = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    text = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    text = "0x7fffffffdc20: 0x0000000000000000 0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": text}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "challenge": {"binary_path": "challenge/chall"},
                        "protections": {"pie": False},
                    },
                    f,
                )

            with mock.patch.object(gdb_direct_probe, "ROOT_DIR", td), mock.patch.object(
                gdb_direct_probe, "MCPStdioClient", FakeClient
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cmd", return_value=["python3", "fake_gdb_mcp.py"]), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cwd", return_value=td
            ), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_nonpie",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)
            with open(state_path, "r", encoding="utf-8") as f:
                updated = json.load(f)
            latest = updated.get("artifacts_index", {}).get("latest", {}).get("paths", {})
            self.assertEqual(updated.get("latest_bases", {}).get("pie_base"), "0x0")
            self.assertEqual(updated.get("dynamic_evidence", {}).get("evidence", [{}])[0].get("gdb", {}).get("rip"), "0x401170")
            self.assertEqual(updated.get("dynamic_evidence", {}).get("evidence", [{}])[0].get("gdb", {}).get("pc_offset"), "0x401170")
            self.assertEqual(updated.get("dynamic_evidence", {}).get("inputs", [{}])[0].get("stdin_source"), "auto-cyclic")
            self.assertEqual(updated.get("dynamic_evidence", {}).get("inputs", [{}])[0].get("kind"), "auto_cyclic")
            self.assertTrue(updated.get("dynamic_evidence", {}).get("inputs", [{}])[0].get("cyclic_compatible"))
            self.assertEqual(updated.get("gdb", {}).get("mode"), "gdb_direct_probe")
            self.assertEqual(updated.get("gdb", {}).get("source"), "gdb_direct_probe")
            self.assertEqual(updated.get("gdb", {}).get("stdin_source"), "auto-cyclic")
            self.assertEqual(updated.get("gdb", {}).get("stdin_kind"), "auto_cyclic")
            self.assertEqual(updated.get("gdb", {}).get("report"), latest.get("gdb_summary"))
            self.assertEqual(updated.get("gdb", {}).get("raw"), latest.get("gdb_raw"))
            self.assertEqual(updated.get("gdb", {}).get("offset_to_rip"), 0)
            self.assertTrue(latest.get("gdb_summary"))
            self.assertTrue(latest.get("capabilities_report"))
            with open(os.path.join(td, latest.get("gdb_summary")), "r", encoding="utf-8") as f:
                summary_doc = json.load(f)
            with open(os.path.join(td, latest.get("capabilities_report")), "r", encoding="utf-8") as f:
                cap_doc = json.load(f)
            self.assertEqual(summary_doc.get("mode"), "gdb_direct_probe")
            self.assertEqual(summary_doc.get("source"), "gdb_direct_probe")
            self.assertTrue(cap_doc.get("after", {}).get("has_crash"))

    def test_main_does_not_infer_offset_from_non_cyclic_seeded_text(self) -> None:
        class FakeClient:
            def __init__(self, cmd, cwd):
                self.commands = []

            def start(self):
                return None

            def close(self):
                return None

            def tool_call(self, name, arguments, timeout_sec=20.0):
                if name == "gdb_start":
                    return {
                        "result": {
                            "content": [
                                {"type": "text", "text": "Session ID: fake-session"},
                            ]
                        }
                    }
                if name == "gdb_terminate":
                    return {"result": {"content": []}}
                command = str(arguments.get("command", ""))
                self.commands.append(command)
                text = ""
                if command == "info proc mappings":
                    text = (
                        "Mapped address spaces:\n\n"
                        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
                        "            0x400000           0x401000     0x1000        0x0  r--p   /tmp/chall\n"
                        "            0x401000           0x402000     0x1000     0x1000  r-xp   /tmp/chall\n"
                    )
                elif command == "info registers":
                    text = "rip            0x401040            0x401040 <_start>"
                elif command.startswith("run < "):
                    text = "Program received signal SIGSEGV, Segmentation fault."
                elif command == "info registers rip eip pc":
                    text = "rip            0x401170            0x401170 <main+58>"
                elif command.startswith("bt"):
                    text = "#0  0x0000000000401170 in main ()"
                elif command.startswith("x/"):
                    text = "0x7fffffffdc20: 0x3144613044613943 0x00007ffff7dea24a"
                return {"result": {"content": [{"type": "text", "text": text}]}}

        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_path = os.path.join(challenge_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "challenge/chall"}, "protections": {"pie": False}}, f)

            with mock.patch.dict(os.environ, {"DIRGE_GDB_DIRECT_STDIN_TEXT": "AAAA"}, clear=False), mock.patch.object(
                gdb_direct_probe, "ROOT_DIR", td
            ), mock.patch.object(gdb_direct_probe, "MCPStdioClient", FakeClient), mock.patch.object(
                gdb_direct_probe, "gdb_mcp_cmd", return_value=["python3", "fake_gdb_mcp.py"]
            ), mock.patch.object(gdb_direct_probe, "gdb_mcp_cwd", return_value=td), mock.patch.object(
                sys,
                "argv",
                [
                    "gdb_direct_probe.py",
                    "--state",
                    state_path,
                    "--session-id",
                    "bench_seeded_text",
                    "--loop",
                    "1",
                ],
            ):
                rc = gdb_direct_probe.main()

            self.assertEqual(rc, 0)
            with open(state_path, "r", encoding="utf-8") as f:
                updated = json.load(f)
            input_doc = updated.get("dynamic_evidence", {}).get("inputs", [{}])[0]
            gdb_doc = updated.get("dynamic_evidence", {}).get("evidence", [{}])[0].get("gdb", {})
            self.assertEqual(input_doc.get("stdin_source"), "text-env")
            self.assertFalse(input_doc.get("cyclic_compatible"))
            self.assertFalse(updated.get("capabilities", {}).get("control_rip"))
            self.assertNotIn("offset_to_rip", gdb_doc)


if __name__ == "__main__":
    unittest.main()
