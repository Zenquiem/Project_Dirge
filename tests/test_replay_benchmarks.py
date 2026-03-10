import json
import os
import tempfile
import unittest

from scripts import replay_benchmarks as rb


class ReplayBenchmarksTests(unittest.TestCase):
    def test_build_case_commands_default_init_only(self):
        plan = rb.build_case_commands(
            {
                "challenge_dir": "challenge/demo",
                "binary": "chall_true",
                "max_loops": 2,
            },
            case_id="demo_local",
            session_id="bench_demo_local_20260310T000000Z",
            allow_codex_missing_default=False,
        )

        self.assertIn("--no-codex", plan["cmd_start"])
        self.assertEqual(plan["cmd_run"][-1], "2")
        self.assertNotIn("--allow-codex-missing", plan["cmd_run"])
        self.assertEqual(plan["env"], {})
        self.assertEqual(plan["expect"], {})

    def test_build_case_commands_supports_portable_runtime_knobs(self):
        plan = rb.build_case_commands(
            {
                "challenge_dir": "challenge/demo",
                "binary": "chall_true",
                "max_loops": 3,
                "allow_codex_missing": True,
                "ensure_binary_executable": True,
                "start_no_codex": False,
                "start_session_args": ["--no-exp", "--prompt", "host-like run"],
                "run_session_args": ["--fast", "--fresh-loops"],
                "env": {
                    "CODEX_BIN": "/usr/local/bin/codex",
                    "CODEX_DEFAULT_MODEL": "gpt-5.4",
                    "PWN_INPUT_ALIGN_MODE": "auto",
                    "EMPTY_OK": "",
                },
                "expect": {
                    "run_rc": 0,
                    "final_exit_code": 0,
                    "acceptance_passed": True,
                    "required_success_stages": ["recon", "ida_slice"],
                    "stage_sequence": ["recon", "ida_slice"],
                    "forbid_stage_cache_hits": ["recon"],
                    "metrics_min": {"runs_total": 1},
                    "state_paths": {"session.status": "finished"},
                    "report_paths": {"report": "file", "timeline_report": "file"},
                    "report_path_contains": {"report": "{{SESSION_ID}}"},
                    "report_json_paths": {"report": {"session_id": "{{SESSION_ID}}"}},
                },
            },
            case_id="host_portable",
            session_id="bench_host_portable_20260310T000000Z",
            allow_codex_missing_default=False,
        )

        self.assertNotIn("--no-codex", plan["cmd_start"])
        self.assertIn("--no-exp", plan["cmd_start"])
        self.assertTrue(plan["ensure_binary_executable"])
        self.assertEqual(plan["cmd_start"][-2:], ["--prompt", "host-like run"])
        self.assertEqual(plan["cmd_run"][-3:], ["--allow-codex-missing", "--fast", "--fresh-loops"])
        self.assertEqual(plan["env"]["CODEX_BIN"], "/usr/local/bin/codex")
        self.assertEqual(plan["env"]["EMPTY_OK"], "")
        self.assertEqual(plan["expect"]["required_success_stages"], ["recon", "ida_slice"])
        self.assertEqual(plan["expect"]["stage_sequence"], ["recon", "ida_slice"])
        self.assertEqual(plan["expect"]["forbid_stage_cache_hits"], ["recon"])
        self.assertEqual(plan["expect"]["report_paths"]["report"], "file")
        self.assertEqual(plan["expect"]["report_path_contains"]["report"], "{{SESSION_ID}}")
        self.assertEqual(plan["expect"]["report_json_paths"]["report"]["session_id"], "{{SESSION_ID}}")

    def test_invalid_case_shapes_raise(self):
        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "start_session_args": "--no-exp",
                },
                case_id="bad_case",
                session_id="bench_bad_case_20260310T000000Z",
                allow_codex_missing_default=False,
            )

        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "env": ["CODEX_BIN=/usr/bin/codex"],
                },
                case_id="bad_env",
                session_id="bench_bad_env_20260310T000000Z",
                allow_codex_missing_default=False,
            )

        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "expect": {"required_success_stages": "recon"},
                },
                case_id="bad_expect",
                session_id="bench_bad_expect_20260310T000000Z",
                allow_codex_missing_default=False,
            )

        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "expect": {"report_paths": ["report"]},
                },
                case_id="bad_report_paths",
                session_id="bench_bad_report_paths_20260310T000000Z",
                allow_codex_missing_default=False,
            )

        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "expect": {"report_path_contains": {"report": ""}},
                },
                case_id="bad_report_path_contains",
                session_id="bench_bad_report_path_contains_20260310T000000Z",
                allow_codex_missing_default=False,
            )

        with self.assertRaises(ValueError):
            rb.build_case_commands(
                {
                    "challenge_dir": "challenge/demo",
                    "expect": {"report_json_paths": {"report": "session.status"}},
                },
                case_id="bad_report_json_paths",
                session_id="bench_bad_report_json_paths_20260310T000000Z",
                allow_codex_missing_default=False,
            )

    def test_evaluate_case_expectations_checks_run_output_metrics_and_state(self):
        with tempfile.TemporaryDirectory() as td:
            state_abs = os.path.join(td, "bench_demo_state.json")
            metrics_abs = os.path.join(td, "bench_demo_20260310_metrics.json")
            report_abs = os.path.join(td, "session_bench_demo_20260310_summary.json")
            receipt_abs = os.path.join(td, "stage_receipt_bench_demo_20260310_01_recon.json")
            with open(state_abs, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "session": {"status": "finished"},
                        "progress": {"stage": "exploit"},
                        "dynamic_evidence": {
                            "evidence": [{"gdb": {"signal": "SIGSEGV", "pc_offset": "0x1234"}}],
                            "inputs": [{"stdin_source": "text-env", "size": 6}],
                        },
                    },
                    f,
                )
            with open(metrics_abs, "w", encoding="utf-8") as f:
                json.dump({"runs_total": 1, "objective_score_latest": 7, "exploit_success": 1}, f)
            with open(report_abs, "w", encoding="utf-8") as f:
                json.dump({"session_id": "bench_demo_20260310", "status": "finished"}, f)
            with open(receipt_abs, "w", encoding="utf-8") as f:
                json.dump({"session_id": "bench_demo_20260310", "loop": 1, "stage": "recon"}, f)

            item = {
                "session_id": "bench_demo_20260310",
                "run_rc": 0,
                "run_output": {
                    "exit_code": 0,
                    "acceptance_passed": True,
                    "state": state_abs,
                    "metrics": metrics_abs,
                    "report": report_abs,
                    "stage_results": [
                        {"stage": "recon", "ok": True, "stage_cache_hit": False, "stage_receipt": receipt_abs},
                        {"stage": "exploit", "ok": True, "stage_cache_hit": False},
                    ],
                },
                "metrics": rb._metrics_from_case_result({"run_output": {"metrics": metrics_abs}}),
            }
            res = rb.evaluate_case_expectations(
                item,
                {
                    "run_rc": 0,
                    "final_exit_code": 0,
                    "acceptance_passed": True,
                    "min_objective_score": 5,
                    "required_success_stages": ["recon", "exploit"],
                    "stage_sequence": ["recon", "exploit"],
                    "forbid_stage_cache_hits": ["recon"],
                    "metrics_min": {"runs_total": 1, "exploit_success": 1},
                    "state_paths": {
                        "session.status": "finished",
                        "progress.stage": "exploit",
                        "dynamic_evidence.evidence[0].gdb.signal": "SIGSEGV",
                        "dynamic_evidence.inputs[0].stdin_source": "text-env",
                    },
                    "report_paths": {
                        "state": "file",
                        "metrics": "file",
                    },
                    "report_path_contains": {
                        "state": "state",
                        "metrics": "{{SESSION_ID}}",
                    },
                    "report_json_paths": {
                        "report": {
                            "session_id": "{{SESSION_ID}}",
                            "status": "finished",
                        },
                        "stage_results[0].stage_receipt": {
                            "session_id": "{{SESSION_ID}}",
                            "loop": 1,
                            "stage": "recon",
                        },
                    },
                },
            )

            self.assertTrue(res["ok"])
            self.assertEqual(res["errors"], [])

    def test_ensure_case_binary_executable_sets_owner_exec_bit(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = os.path.join(td, "challenge")
            os.makedirs(case_dir, exist_ok=True)
            binary_path = os.path.join(case_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"\x7fELFdemo")
            os.chmod(binary_path, 0o644)

            info = rb.ensure_case_binary_executable(case_dir, "chall", enabled=True)

            self.assertTrue(info["exists"])
            self.assertFalse(info["before_user_executable"])
            self.assertTrue(info["changed"])
            self.assertTrue(info["after_user_executable"])
            self.assertTrue(os.stat(binary_path).st_mode & 0o100)

    def test_clear_case_cached_artifacts_removes_binary_scoped_cache_files(self):
        with tempfile.TemporaryDirectory() as td:
            case_dir = os.path.join(td, "challenge")
            os.makedirs(case_dir, exist_ok=True)
            binary_path = os.path.join(case_dir, "chall")
            with open(binary_path, "wb") as f:
                f.write(b"cache-target")

            binary_sha = rb._file_sha256(binary_path)
            cache_dir = os.path.join(rb.ROOT_DIR, "artifacts", "cache")
            os.makedirs(cache_dir, exist_ok=True)
            doomed = [
                os.path.join(cache_dir, f"{binary_sha}_recon.json"),
                os.path.join(cache_dir, f"{binary_sha}_exploit_profile.json"),
            ]
            survivor = os.path.join(cache_dir, "unrelated_recon.json")
            for path in doomed + [survivor]:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("{}")

            info = rb.clear_case_cached_artifacts(case_dir, "chall", enabled=True)

            self.assertTrue(info["exists"])
            self.assertEqual(info["binary_sha256"], binary_sha)
            self.assertEqual(sorted(info["removed"]), sorted(os.path.relpath(x, rb.ROOT_DIR) for x in doomed))
            self.assertFalse(os.path.exists(doomed[0]))
            self.assertFalse(os.path.exists(doomed[1]))
            self.assertTrue(os.path.exists(survivor))
            os.remove(survivor)

    def test_evaluate_case_expectations_reports_mismatches(self):
        item = {
            "run_rc": 1,
            "run_output": {
                "exit_code": 1,
                "acceptance_passed": False,
                "stage_results": [{"stage": "recon", "ok": False, "stage_cache_hit": True}],
            },
            "metrics": {"objective_score_latest": 0, "runs_total": 0},
        }

        res = rb.evaluate_case_expectations(
            item,
            {
                "run_rc": 0,
                "final_exit_code": 0,
                "acceptance_passed": True,
                "min_objective_score": 1,
                "required_success_stages": ["recon"],
                "stage_sequence": ["recon", "gdb_evidence"],
                "forbid_stage_cache_hits": ["recon"],
                "metrics_min": {"runs_total": 1},
                "state_paths": {"session.status": "finished"},
                "report_paths": {"state": "file"},
                "report_json_paths": {"report": {"session_id": "{{SESSION_ID}}"}},
            },
        )

        self.assertFalse(res["ok"])
        self.assertIn("stage_sequence", res["checks"])
        self.assertGreaterEqual(len(res["errors"]), 7)

    def test_compare_with_baseline_flags_case_level_regression_even_if_scoreboard_budget_allows_it(self):
        stable_contract = {
            "challenge_dir": "challenge/demo",
            "binary": "chall",
            "max_loops": 1,
            "allow_codex_missing": True,
            "start_no_codex": True,
            "start_session_args": [],
            "run_session_args": [],
            "env": {},
            "expect": {"stage_sequence": ["recon", "gdb_evidence"]},
            "ensure_binary_executable": True,
            "clear_cached_artifacts": True,
            "start_timeout_seconds": None,
            "run_timeout_seconds": None,
        }
        baseline = {
            "scoreboard": {
                "success_rate": 1.0,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            "cases": [
                {"case_id": "demo_local", "ok": True, "run_rc": 0},
                {
                    "case_id": "demo_local_gdb",
                    "ok": True,
                    "run_rc": 0,
                    "final_exit_code": 0,
                    "acceptance_passed": True,
                    "success_stages": ["recon", "gdb_evidence"],
                    "stage_sequence": ["recon", "gdb_evidence"],
                    "case_contract_hash": rb._json_sha256(stable_contract),
                },
            ],
        }
        current_results = [
            {"case_id": "demo_local", "ok": True, "run_rc": 0},
            {
                "case_id": "demo_local_gdb",
                "ok": False,
                "run_rc": 0,
                "case_contract": stable_contract,
                "run_output": {
                    "exit_code": 1,
                    "acceptance_passed": False,
                    "stage_results": [
                        {"stage": "recon", "ok": True},
                        {"stage": "exploit_l4", "ok": False},
                    ],
                },
            },
        ]

        res = rb.compare_with_baseline(
            current={
                "success_rate": 0.5,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            baseline=baseline,
            max_success_drop=0.6,
            max_codex_error_increase=0,
            max_stage_retry_increase=0,
            current_results=current_results,
        )

        self.assertFalse(res["ok"])
        self.assertIn("demo_local_gdb", res["case_checks"])
        self.assertFalse(res["case_checks"]["demo_local_gdb"]["ok"])
        self.assertEqual(res["case_checks"]["demo_local_gdb"]["actual_final_exit_code"], 1)
        self.assertEqual(res["case_checks"]["demo_local_gdb"]["actual_success_stages"], ["recon"])
        self.assertEqual(res["case_checks"]["demo_local_gdb"]["actual_stage_sequence"], ["recon", "exploit_l4"])
        self.assertTrue(any("baseline case regressed: demo_local_gdb" in x for x in res["errors"]))

    def test_summarize_case_for_baseline_includes_exit_acceptance_and_success_stages(self):
        case_contract = {
            "challenge_dir": "challenge/demo",
            "binary": "chall",
            "max_loops": 1,
            "allow_codex_missing": True,
            "start_no_codex": True,
            "start_session_args": [],
            "run_session_args": ["--fast"],
            "env": {"DIRGE_PREFER_LOCAL_GDB_ON_CODEX_MISSING": "1"},
            "expect": {"stage_sequence": ["recon", "gdb_evidence", "exploit_l4"]},
            "ensure_binary_executable": True,
            "clear_cached_artifacts": False,
            "start_timeout_seconds": None,
            "run_timeout_seconds": 30,
        }
        summary = rb.summarize_case_for_baseline(
            {
                "case_id": "demo_local_gdb",
                "ok": True,
                "run_rc": 0,
                "case_contract": case_contract,
                "run_output": {
                    "exit_code": 0,
                    "acceptance_passed": True,
                    "stage_results": [
                        {"stage": "recon", "ok": True},
                        {"stage": "gdb_evidence", "ok": True},
                        {"stage": "exploit_l4", "ok": False},
                    ],
                },
            }
        )

        self.assertEqual(summary["case_id"], "demo_local_gdb")
        self.assertEqual(summary["final_exit_code"], 0)
        self.assertTrue(summary["acceptance_passed"])
        self.assertEqual(summary["success_stages"], ["gdb_evidence", "recon"])
        self.assertEqual(summary["stage_sequence"], ["recon", "gdb_evidence", "exploit_l4"])
        self.assertEqual(summary["case_contract"], case_contract)
        self.assertEqual(summary["case_contract_hash"], rb._json_sha256(case_contract))

    def test_compare_with_baseline_flags_case_contract_drift(self):
        baseline_contract = {
            "challenge_dir": "challenge/demo",
            "binary": "chall",
            "max_loops": 1,
            "allow_codex_missing": True,
            "start_no_codex": True,
            "start_session_args": [],
            "run_session_args": [],
            "env": {"DIRGE_LOCAL_GDB_STDIN_TEXT": "CRASH\\n"},
            "expect": {"stage_sequence": ["recon", "gdb_evidence"]},
            "ensure_binary_executable": True,
            "clear_cached_artifacts": True,
            "start_timeout_seconds": None,
            "run_timeout_seconds": None,
        }
        weaker_contract = dict(baseline_contract)
        weaker_contract["expect"] = {"required_success_stages": ["recon"]}

        baseline = {
            "scoreboard": {
                "success_rate": 1.0,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            "cases": [
                {
                    "case_id": "demo_local_gdb",
                    "ok": True,
                    "run_rc": 0,
                    "case_contract_hash": rb._json_sha256(baseline_contract),
                },
            ],
        }

        res = rb.compare_with_baseline(
            current={
                "success_rate": 1.0,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            baseline=baseline,
            max_success_drop=0.0,
            max_codex_error_increase=0,
            max_stage_retry_increase=0,
            current_results=[
                {
                    "case_id": "demo_local_gdb",
                    "ok": True,
                    "run_rc": 0,
                    "case_contract": weaker_contract,
                }
            ],
        )

        self.assertFalse(res["ok"])
        self.assertFalse(res["case_checks"]["demo_local_gdb"]["ok"])
        self.assertIn("expected_case_contract_hash", res["case_checks"]["demo_local_gdb"])
        self.assertTrue(any("case_contract_hash mismatch" in x for x in res["case_checks"]["demo_local_gdb"]["errors"]))

    def test_compare_with_baseline_flags_missing_case(self):
        baseline = {
            "scoreboard": {
                "success_rate": 1.0,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            "cases": [
                {"case_id": "demo_local", "ok": True, "run_rc": 0},
            ],
        }

        res = rb.compare_with_baseline(
            current={
                "success_rate": 1.0,
                "codex_errors_total": 0,
                "stage_retries_total": 0,
            },
            baseline=baseline,
            max_success_drop=0.0,
            max_codex_error_increase=0,
            max_stage_retry_increase=0,
            current_results=[],
        )

        self.assertFalse(res["ok"])
        self.assertFalse(res["case_checks"]["demo_local"]["ok"])
        self.assertTrue(any("baseline case missing from current run: demo_local" in x for x in res["errors"]))


if __name__ == "__main__":
    unittest.main()
