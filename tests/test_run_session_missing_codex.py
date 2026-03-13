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
    _cyclic_bytes,
    _derive_verify_success_markers,
    _select_local_gdb_stdin,
    adjust_loop_budget_for_missing_codex,
    choose_missing_codex_stage_order,
    describe_missing_codex_plan_notes,
    maybe_prepare_remote_prompt,
    run_local_gdb_fallback,
    run_local_recon_fallback,
    should_defer_objective_stop_for_missing_codex_plan,
)


class RunSessionVerifyMarkerDerivationTests(unittest.TestCase):
    def test_derive_verify_success_markers_harvests_ret2win_banner_from_binary(self):
        with tempfile.TemporaryDirectory() as td:
            chall_dir = os.path.join(td, "challenge")
            os.makedirs(chall_dir, exist_ok=True)
            bin_abs = os.path.join(chall_dir, "chall")
            with open(bin_abs, "wb") as f:
                f.write(b"\x7fELFfake....DIRGE_RET2WIN_OK....boring-text")
            state = {
                "challenge": {"binary_path": os.path.relpath(bin_abs, ROOT_DIR)},
                "static_analysis": {"suspects": [{"name": "ret2win"}]},
            }
            markers = _derive_verify_success_markers(state)
        self.assertIn("DIRGE_RET2WIN_OK", markers)


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

    def test_choose_missing_codex_stage_order_resolves_binary_relative_to_state_workdir(self):
        with tempfile.TemporaryDirectory() as td:
            challenge_dir = os.path.join(td, "challenge")
            os.makedirs(challenge_dir, exist_ok=True)
            binary_abs = os.path.join(challenge_dir, "chall")
            with open(binary_abs, "wb") as f:
                f.write(b"\x7fELFfake")

            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "chall", "workdir": "challenge"}}, f)

            stage_order, mode = choose_missing_codex_stage_order(
                stage_order=["recon", "gdb_evidence", "exploit_l4"],
                state_path=state_path,
                terminal_stage="exploit_l4",
            )

            self.assertEqual(stage_order, ["recon"])
            self.assertEqual(mode, "local_recon_only")

    def test_choose_missing_codex_stage_order_prefers_local_recon_plus_direct_gdb_when_only_direct_probe_available(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return None
                if name == "gdb-mcp":
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_GDB_MCP_CMD": "python3 scripts/fake_gdb_mcp.py",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_direct_gdb")

    def test_choose_missing_codex_stage_order_prefers_local_gdb_over_path_discovered_direct_probe_without_explicit_seed(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                if name == "gdb-mcp":
                    return "/usr/bin/gdb-mcp"
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_gdb")

    def test_choose_missing_codex_stage_order_prefers_local_recon_plus_gdb_when_seeded(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb-mcp":
                    return None
                if name == "gdb":
                    return "/usr/bin/gdb"
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_gdb")

    def test_choose_missing_codex_stage_order_prefers_direct_gdb_when_only_direct_seed_is_provided(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                if name == "gdb-mcp":
                    return "/usr/bin/gdb-mcp"
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_GDB_DIRECT_STDIN_TEXT": "boom\n",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_direct_gdb")

    def test_choose_missing_codex_stage_order_can_force_direct_gdb_even_when_local_seed_exists(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                    "DIRGE_FORCE_DIRECT_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_GDB_MCP_CMD": "python3 scripts/fake_gdb_mcp.py",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_direct_gdb")

    def test_choose_missing_codex_stage_order_prefers_seeded_local_gdb_over_direct_probe(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                    "DIRGE_GDB_MCP_CMD": "python3 scripts/fake_gdb_mcp.py",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence"])
            self.assertEqual(mode, "local_recon_gdb")

    def test_choose_missing_codex_stage_order_can_opt_into_local_exploit_after_gdb(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                if name == "gdb-mcp":
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l3", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence", "exploit_l3"])
            self.assertEqual(mode, "local_recon_gdb_exploit")

    def test_choose_missing_codex_stage_order_can_reinsert_local_exploit_when_only_terminal_stage_was_planned(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return "/usr/bin/gdb"
                if name == "gdb-mcp":
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING": "1",
                    "DIRGE_LOCAL_GDB_STDIN_TEXT": "boom\n",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "ida_slice", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence", "exploit_l3"])
            self.assertEqual(mode, "local_recon_gdb_exploit")

    def test_choose_missing_codex_stage_order_can_reinsert_direct_gdb_local_exploit_even_without_planned_exploit_stage(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name == "gdb":
                    return None
                if name == "gdb-mcp":
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING": "1",
                    "DIRGE_GDB_MCP_CMD": "python3 scripts/fake_gdb_mcp.py",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "gdb_evidence"],
                    state_path=state_path,
                    terminal_stage="gdb_evidence",
                )

            self.assertEqual(stage_order, ["recon", "gdb_evidence", "exploit_l3"])
            self.assertEqual(mode, "local_recon_direct_gdb_exploit")

    def test_choose_missing_codex_stage_order_can_fall_back_to_recon_plus_local_exploit_without_any_gdb(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name in {"gdb", "gdb-mcp"}:
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING": "1",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["recon", "gdb_evidence", "exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "exploit_l3"])
            self.assertEqual(mode, "local_recon_exploit")

    def test_choose_missing_codex_stage_order_reinserts_recon_for_terminal_only_local_exploit_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": "/bin/ls"}}, f)

            def fake_which(name: str) -> str | None:
                if name in {"gdb", "gdb-mcp"}:
                    return None
                return None

            with mock.patch.dict(
                os.environ,
                {
                    "DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1",
                    "DIRGE_ALLOW_LOCAL_EXP_ON_CODEX_MISSING": "1",
                },
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", side_effect=fake_which):
                stage_order, mode = choose_missing_codex_stage_order(
                    stage_order=["exploit_l4"],
                    state_path=state_path,
                    terminal_stage="exploit_l4",
                )

            self.assertEqual(stage_order, ["recon", "exploit_l3"])
            self.assertEqual(mode, "local_recon_exploit")


class RunSessionMissingCodexPlanNoteTests(unittest.TestCase):
    def test_local_recon_gdb_notes_expose_disabled_direct_probe_in_fast_mode(self):
        notes = describe_missing_codex_plan_notes("local_recon_gdb", fast_mode=True)
        self.assertIn("direct gdb probe: off", notes)
        self.assertIn(
            "fast profile: disable direct gdb probe to honor local gdb fallback preference when codex is unavailable",
            notes,
        )

    def test_local_recon_gdb_exploit_notes_expose_local_plugin(self):
        notes = describe_missing_codex_plan_notes("local_recon_gdb_exploit", fast_mode=False)
        self.assertIn("direct gdb probe: off", notes)
        self.assertIn("local exploit plugin: on", notes)

    def test_local_recon_direct_gdb_notes_expose_probe_enabled(self):
        notes = describe_missing_codex_plan_notes("local_recon_direct_gdb", fast_mode=True)
        self.assertEqual(notes, ["direct gdb probe: on"])

    def test_local_recon_direct_gdb_exploit_notes_expose_probe_and_plugin(self):
        notes = describe_missing_codex_plan_notes("local_recon_direct_gdb_exploit", fast_mode=False)
        self.assertEqual(notes, ["direct gdb probe: on", "local exploit plugin: on"])

    def test_local_recon_exploit_notes_expose_recon_only_exploit_route(self):
        notes = describe_missing_codex_plan_notes("local_recon_exploit", fast_mode=False)
        self.assertEqual(
            notes,
            [
                "direct gdb probe: off",
                "gdb evidence unavailable: exploit after recon",
                "local exploit plugin: on",
            ],
        )


class RunSessionMissingCodexObjectiveStopTests(unittest.TestCase):
    def test_exploit_plan_defers_objective_stop_until_local_exploit_runs(self):
        self.assertTrue(
            should_defer_objective_stop_for_missing_codex_plan(
                "local_recon_gdb_exploit",
                enable_exploit=True,
                stage_order=["recon", "gdb_evidence", "exploit_l3"],
            )
        )

    def test_non_exploit_plan_keeps_objective_stop_behavior(self):
        self.assertFalse(
            should_defer_objective_stop_for_missing_codex_plan(
                "local_recon_gdb",
                enable_exploit=True,
                stage_order=["recon", "gdb_evidence"],
            )
        )
        self.assertFalse(
            should_defer_objective_stop_for_missing_codex_plan(
                "local_recon_gdb_exploit",
                enable_exploit=False,
                stage_order=["recon", "gdb_evidence", "exploit_l3"],
            )
        )


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

    def test_run_local_recon_fallback_collects_local_symbol_hints_and_symbol_map(self):
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "ret2win.c")
            binary = os.path.join(td, "ret2win")
            with open(src, "w", encoding="utf-8") as f:
                f.write(
                    "#include <stdio.h>\n"
                    "#include <stdlib.h>\n"
                    "void win(void){ puts(\"pwned\"); system(\"/bin/true\"); }\n"
                    "int main(void){ char buf[64]; puts(\"hi\"); gets(buf); return 0; }\n"
                )
            os.system(f"gcc -no-pie -fno-stack-protector -O0 -g -o {binary} {src} >/dev/null 2>&1")
            self.assertTrue(os.path.exists(binary))

            state_path = os.path.join(td, "state.json")
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": binary}}, f)

            session_id = "ut_missing_codex_symbols"
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
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            static = state.get("static_analysis", {})
            entry_names = {str(x.get("name", "")) for x in static.get("entrypoints", []) if isinstance(x, dict)}
            hypo_names = {str(x.get("name", "")) for x in static.get("hypotheses", []) if isinstance(x, dict)}
            latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
            self.assertIn("main", entry_names)
            self.assertIn("win", entry_names)
            self.assertIn("win", hypo_names)
            self.assertEqual(state.get("static_analysis", {}).get("stack_smash_offset_guess"), 72)
            self.assertEqual(state.get("capabilities", {}).get("static_offset_candidate"), 72)
            self.assertTrue(str(latest.get("symbol_map", "")).endswith("_01.json"))
            self.assertTrue(os.path.exists(os.path.join(ROOT_DIR, latest.get("symbol_map"))))

            with open(os.path.join(ROOT_DIR, report_rel), "r", encoding="utf-8") as f:
                report_doc = json.load(f)
            self.assertEqual(report_doc.get("static_offset_candidate"), 72)

            os.remove(os.path.join(ROOT_DIR, report_rel))
            os.remove(os.path.join(ROOT_DIR, latest.get("symbol_map")))
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
            self.assertEqual(state["dynamic_evidence"]["inputs"][-1].get("kind"), "seeded_text")
            self.assertFalse(state["dynamic_evidence"]["inputs"][-1].get("cyclic_compatible"))
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

    def test_run_local_gdb_fallback_recovers_offset_and_seed_metadata_from_cyclic_sendline(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            binary_path = os.path.join(td, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": binary_path}, "protections": {"pie": False}}, f)

            session_id = "ut_missing_codex_gdb_offset"
            log_rel = f"artifacts/logs/{session_id}_gdb.log"
            log_abs = os.path.join(ROOT_DIR, log_rel)
            os.makedirs(os.path.dirname(log_abs), exist_ok=True)
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write("[run_session] start\n")

            cyclic = _cyclic_bytes(120)
            word = cyclic[88:96]
            stack_hex = "0x" + word[::-1].hex()
            fake_gdb = (
                "Program received signal SIGSEGV, Segmentation fault.\n"
                "rip            0x401170            0x401170 <main+58>\n"
                "Mapped address spaces:\n"
                f"0x400000 0x401000 0x1000 0x0 r--p {binary_path}\n"
                f"0x401000 0x402000 0x1000 0x1000 r-xp {binary_path}\n"
                f"0x7fffffffdc20: {stack_hex} 0x00007ffff7dea24a\n"
            )
            with mock.patch.dict(
                os.environ,
                {"DIRGE_LOCAL_GDB_STDIN_TEXT": cyclic.decode("latin1") + "\n"},
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", return_value="/usr/bin/gdb"), mock.patch(
                "scripts.run_session._run_capture_quick", return_value=(0, fake_gdb, "")
            ):
                ok, report_rel, err = run_local_gdb_fallback(
                    state_path=state_path,
                    session_id=session_id,
                    loop_idx=1,
                    log_abs=log_abs,
                    log_rel=log_rel,
                )

            self.assertTrue(ok)
            self.assertEqual(err, "")
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            self.assertEqual(state.get("latest_bases", {}).get("pie_base"), "0x400000")
            self.assertEqual(state.get("gdb", {}).get("pc_offset"), "0x1170")
            self.assertEqual(state.get("gdb", {}).get("stdin_kind"), "seeded_text")
            self.assertEqual(state.get("gdb", {}).get("offset_to_rip"), 88)
            self.assertEqual(state.get("capabilities", {}).get("offset_to_rip"), 88)
            self.assertTrue(state.get("capabilities", {}).get("control_rip"))
            input_doc = state.get("dynamic_evidence", {}).get("inputs", [{}])[-1]
            self.assertTrue(input_doc.get("cyclic_compatible"))
            self.assertEqual(input_doc.get("cyclic_window_len"), 120)
            self.assertEqual(input_doc.get("cyclic_span"), 120)
            self.assertEqual(state.get("dynamic_evidence", {}).get("evidence", [{}])[-1].get("gdb", {}).get("offset_to_rip"), 88)

    def test_run_local_gdb_fallback_recovers_offset_from_fault_address_when_rip_is_zero(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            binary_path = os.path.join(td, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 11 + (62).to_bytes(2, "little") + b"\x00" * 16)
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump({"challenge": {"binary_path": binary_path}, "protections": {"pie": False}}, f)

            session_id = "ut_missing_codex_gdb_fault_offset"
            log_rel = f"artifacts/logs/{session_id}_gdb.log"
            log_abs = os.path.join(ROOT_DIR, log_rel)
            os.makedirs(os.path.dirname(log_abs), exist_ok=True)
            with open(log_abs, "w", encoding="utf-8") as f:
                f.write("[run_session] start\n")

            with open(os.path.join(ROOT_DIR, "challenge", "bench_ret2win", "cyclic72.txt"), "rb") as f:
                cyclic = f.read()
            fault_word = b"i" + cyclic[65:72]
            fault_hex = "0x" + fault_word[::-1].hex()
            fake_gdb = (
                "Program received signal SIGSEGV, Segmentation fault.\n"
                "0x0000000000000000 in ?? ()\n"
                "rip            0x0                 0x0\n"
                f"Backtrace stopped: Cannot access memory at address {fault_hex}\n"
                "Mapped address spaces:\n"
                f"0x400000 0x401000 0x1000 0x0 r--p {binary_path}\n"
                f"0x401000 0x402000 0x1000 0x1000 r-xp {binary_path}\n"
                "0x7fffffffe358:\t0x00000000004011e6\t0x0000000100000000\n"
            )
            with mock.patch.dict(
                os.environ,
                {"DIRGE_LOCAL_GDB_STDIN_FILE": "challenge/bench_ret2win/cyclic72.txt"},
                clear=False,
            ), mock.patch("scripts.run_session.shutil.which", return_value="/usr/bin/gdb"), mock.patch(
                "scripts.run_session._run_capture_quick", return_value=(0, fake_gdb, "")
            ), mock.patch("scripts.run_session.infer_static_stack_smash_offset", return_value=72):
                ok, report_rel, err = run_local_gdb_fallback(
                    state_path=state_path,
                    session_id=session_id,
                    loop_idx=1,
                    log_abs=log_abs,
                    log_rel=log_rel,
                )

            self.assertTrue(ok)
            self.assertEqual(err, "")
            with open(state_path, "r", encoding="utf-8") as f:
                state = json.load(f)
            self.assertEqual(state.get("gdb", {}).get("fault_offset_candidate"), 65)
            self.assertEqual(state.get("gdb", {}).get("static_offset_candidate"), 72)
            self.assertEqual(state.get("gdb", {}).get("offset_to_rip"), 0)
            self.assertFalse(state.get("capabilities", {}).get("control_rip", False))
            gdb_doc = state.get("dynamic_evidence", {}).get("evidence", [{}])[-1].get("gdb", {})
            self.assertEqual(gdb_doc.get("fault_addr"), fault_hex)
            self.assertEqual(gdb_doc.get("fault_offset_candidate"), 65)
            self.assertEqual(gdb_doc.get("static_offset_candidate"), 72)
            self.assertIsNone(gdb_doc.get("offset_to_rip"))
            self.assertEqual(report_rel.endswith("_local.json"), True)

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


class RunSessionRemotePromptTests(unittest.TestCase):
    def test_remote_prompt_defaults_disabled_when_policy_omits_it(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            state = {
                "session": {
                    "exp": {
                        "path": "sessions/sess/exp/exp.py",
                        "local_verify_passed": True,
                    }
                },
                "artifacts_index": {"latest": {"paths": {}}},
            }
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(state, f)

            notes = []
            req_rel = maybe_prepare_remote_prompt(
                state=state,
                state_path=state_path,
                session_id="sess",
                remote_prompt_cfg={},
                enable_exploit=True,
                allow_remote_exp=True,
                stage_results=[{"stage": "exploit_l3", "ok": True}],
                notes=notes,
            )

            self.assertEqual(req_rel, "")
            self.assertFalse(os.path.exists(os.path.join(ROOT_DIR, "sessions", "sess", "control", "remote.requested.json")))
            self.assertFalse(state.get("session", {}).get("remote", {}).get("ask_pending", False))
            self.assertEqual(notes, [])

    def test_remote_prompt_still_works_when_explicitly_enabled(self):
        with tempfile.TemporaryDirectory() as td:
            state_path = os.path.join(td, "state.json")
            state = {
                "session": {
                    "exp": {
                        "path": "sessions/sess_enabled/exp/exp.py",
                        "local_verify_passed": True,
                    }
                },
                "artifacts_index": {"latest": {"paths": {}}},
            }
            with open(state_path, "w", encoding="utf-8") as f:
                json.dump(state, f)

            notes = []
            req_rel = maybe_prepare_remote_prompt(
                state=state,
                state_path=state_path,
                session_id="sess_enabled",
                remote_prompt_cfg={"enabled": True},
                enable_exploit=True,
                allow_remote_exp=True,
                stage_results=[{"stage": "exploit_l3", "ok": True}],
                notes=notes,
            )

            self.assertEqual(req_rel, "sessions/sess_enabled/control/remote.requested.json")
            self.assertTrue(os.path.exists(os.path.join(ROOT_DIR, req_rel)))
            self.assertTrue(state.get("session", {}).get("remote", {}).get("ask_pending", False))
            self.assertIn("已生成远程连接询问（pending）", notes)
