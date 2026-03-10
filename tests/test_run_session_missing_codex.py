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

from scripts.run_session import (
    _select_local_gdb_stdin,
    adjust_loop_budget_for_missing_codex,
    choose_missing_codex_stage_order,
    run_local_gdb_fallback,
    run_local_recon_fallback,
)


class RunSessionMissingCodexLoopBudgetTests(unittest.TestCase):
    def test_missing_codex_disables_until_success_and_caps_extra_loops(self):
        res = adjust_loop_budget_for_missing_codex(
            allow_codex_missing=True,
            codex_available=False,
            enable_exploit=True,
            terminal_stage="exploit_l4",
            loop_start=1,
            base_max_loops=4,
            exploit_rewrite_enabled=True,
            exploit_rewrite_until_success=True,
            exploit_rewrite_extra_loops=400,
        )

        self.assertEqual(res["loop_end"], 6)
        self.assertFalse(res["exploit_rewrite_until_success"])
        self.assertEqual(res["exploit_rewrite_extra_loops"], 1)
        self.assertIn("bound exploit rewrite loop", res["note"])

    def test_available_codex_keeps_until_success_behavior(self):
        res = adjust_loop_budget_for_missing_codex(
            allow_codex_missing=True,
            codex_available=True,
            enable_exploit=True,
            terminal_stage="exploit_l4",
            loop_start=3,
            base_max_loops=4,
            exploit_rewrite_enabled=True,
            exploit_rewrite_until_success=True,
            exploit_rewrite_extra_loops=5,
        )

        self.assertTrue(res["exploit_rewrite_until_success"])
        self.assertEqual(res["exploit_rewrite_extra_loops"], 5)
        self.assertGreaterEqual(res["loop_end"], 3 + 1_000_000)
        self.assertEqual(res["note"], "")


class RunSessionMissingCodexStagePlanTests(unittest.TestCase):
    def test_choose_missing_codex_stage_order_prefers_local_recon_when_binary_exists(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            stage_order, mode = choose_missing_codex_stage_order(
                stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                state_path=state_path,
                terminal_stage="exploit_l4",
            )

            self.assertEqual(stage_order, ["recon"])
            self.assertEqual(mode, "local_recon_only")

    def test_choose_missing_codex_stage_order_prefers_local_recon_plus_gdb_when_seeded(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", return_value="/usr/bin/gdb"):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_gdb")


class RunSessionLocalReconFallbackTests(unittest.TestCase):
    def test_run_local_recon_fallback_writes_recon_report_and_updates_state(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            session_id = "ut_missing_codex"
            log_rel = f"artifacts/logs/{session_id}_recon.log"
            log_abs = os.path.join(ROOT_DIR, log_rel)
            os.makedirs(os.path.dirname(log_abs), exist_ok=True)
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write("[run_session] start\n")

            ok, report_rel, err = run_local_recon_fallback(
                state_path=state_path,
                session_id=session_id,
                loop_idx=1,
                log_abs=log_abs,
                log_rel=log_rel,
            )

            self.assertTrue(ok)
            self.assertEqual(err, "")
            self.assertTrue(report_rel.endswith("_local.json"))
            self.assertTrue(os.path.exists(os.path.join(ROOT_DIR, report_rel)))

            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
            self.assertEqual(latest.get("recon_log"), log_rel)
            self.assertEqual(latest.get("recon_report"), report_rel)
            self.assertEqual(state.get("challenge", {}).get("analysis_ready"), True)
            self.assertGreaterEqual(state.get("progress", {}).get("objectives", {}).get("score", 0), 1)
            self.assertEqual(state.get("recon", {}).get("mode"), "local_recon_fallback")
            self.assertEqual(state.get("recon", {}).get("report"), report_rel)
            self.assertEqual(state.get("recon", {}).get("log"), log_rel)
            self.assertEqual(state.get("recon", {}).get("binary_path"), "/bin/ls")
            self.assertTrue(state.get("recon", {}).get("analysis_ready"))
            self.assertIsInstance(state.get("recon", {}).get("imports_sample"), list)
            self.assertIsInstance(state.get("recon", {}).get("io_profile"), dict)

            os.remove(os.path.join(ROOT_DIR, report_rel))
            os.remove(log_abs)


if __name__ == "__main__":
    unittest.main()


class RunSessionLocalGdbSeedSelectionTests(unittest.TestCase):
    def test_select_local_gdb_stdin_prefers_text_env(self):
        with mock.patch.dict(os.environ, {"DIRGE_LOCAL_GDB_STDIN_TEXT": "hello\n"}, clear=False):
            data, source = _select_local_gdb_stdin()
        self.assertEqual(data, b"hello\n")
        self.assertEqual(source, "text-env")

    def test_select_local_gdb_stdin_rejects_bad_hex(self):
        with mock.patch.dict(os.environ, {"DIRGE_LOCAL_GDB_STDIN_HEX": "abc"}, clear=False):
            with self.assertRaises(RuntimeError):
                _select_local_gdb_stdin()


class RunSessionLocalGdbFallbackTests(unittest.TestCase):
    def test_run_local_gdb_fallback_writes_evidence_and_reports(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            session_id = "ut_missing_codex_gdb"
            log_rel = f"artifacts/logs/{session_id}_gdb.log"
            log_abs = os.path.join(ROOT_DIR, log_rel)
            os.makedirs(os.path.dirname(log_abs), exist_ok=True)
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write("[run_session] start\n")

            fake_gdb = """Program received signal SIGSEGV, Segmentation fault.
rip            0x555555555234
Mapped address spaces:
0x555555554000 0x555555556000 0x2000 0x0 /bin/ls
"""
            with mock.patch.dict(os.environ, {"DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n"}, clear=False), mock.patch(
                "scripts.run_session.shutil.which", return_value="/usr/bin/gdb"
            ), mock.patch("scripts.run_session._run_capture_quick", return_value=(0, fake_gdb, "")) as run_cap:
                ok, report_rel, err = run_local_gdb_fallback(
                    state_path=state_path,
                    session_id=session_id,
                    loop_idx=1,
                    log_abs=log_abs,
                    log_rel=log_rel,
                )

            self.assertTrue(ok)
            self.assertEqual(err, "")
            self.assertTrue(report_rel.endswith("_local.json"))
            self.assertTrue(os.path.exists(os.path.join(ROOT_DIR, report_rel)))

            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
            self.assertTrue(latest.get("gdb_raw", "").endswith("_local.txt"))
            self.assertEqual(latest.get("gdb_summary"), report_rel)
            self.assertTrue(latest.get("gdb_clusters", "").endswith("_crash_clusters.json"))
            self.assertTrue(latest.get("capabilities_report", "").endswith(".json"))
            self.assertEqual(state.get("latest_bases", {}).get("pie_base"), "0x555555554000")
            self.assertTrue(state.get("capabilities", {}).get("has_crash"))
            self.assertTrue(state.get("dynamic_evidence", {}).get("evidence"))
            gdb = state["dynamic_evidence"]["evidence"][-1]["gdb"]
            self.assertEqual(gdb.get("signal"), "SIGSEGV")
            self.assertEqual(gdb.get("pc_offset"), hex(0x1234))
            self.assertEqual(state["dynamic_evidence"]["inputs"][-1].get("stdin_source"), "text-env")
            self.assertEqual(state["dynamic_evidence"]["inputs"][-1].get("size"), 5)
            self.assertEqual(state.get("gdb", {}).get("mode"), "local_gdb_fallback")
            self.assertEqual(state.get("gdb", {}).get("report"), report_rel)
            self.assertEqual(state.get("gdb", {}).get("log"), log_rel)
            self.assertEqual(state.get("gdb", {}).get("signal"), "SIGSEGV")
            self.assertEqual(state.get("gdb", {}).get("pie_base"), "0x555555554000")
            self.assertEqual(state.get("gdb", {}).get("pc_offset"), hex(0x1234))
            self.assertEqual(state.get("gdb", {}).get("stdin_source"), "text-env")
            self.assertTrue(state.get("gdb", {}).get("analysis_ready"))
            gdb_cmd = run_cap.call_args.args[0]
            self.assertEqual(gdb_cmd[:4], ["gdb", "-q", "-nx", "-batch"])
            self.assertEqual(gdb_cmd[-2:], ["--args", "/bin/ls"])

    def test_run_local_gdb_fallback_returns_reason_without_signal(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            session_id = "ut_missing_codex_gdb_nosig"
            log_rel = f"artifacts/logs/{session_id}_gdb.log"
            log_abs = os.path.join(ROOT_DIR, log_rel)
            os.makedirs(os.path.dirname(log_abs), exist_ok=True)
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write("[run_session] start\n")

            with mock.patch("scripts.run_session.shutil.which", return_value="/usr/bin/gdb"), mock.patch(
                "scripts.run_session._run_capture_quick", return_value=(0, "Inferior exited normally", "")
            ):
                ok, report_rel, err = run_local_gdb_fallback(
                    state_path=state_path,
                    session_id=session_id,
                    loop_idx=1,
                    log_abs=log_abs,
                    log_rel=log_rel,
                )

            self.assertFalse(ok)
            self.assertEqual(report_rel, "")
            self.assertEqual(err, "gdb_no_crash_signal")
