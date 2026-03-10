#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from session_run_finalize import finalize_run_outputs


class FakeMetrics:
    def __init__(self) -> None:
        self.capability_updates = 0
        self.objective_score_latest = 0
        self.saved = False

    def save(self, path: str) -> None:
        self.saved = True


class SessionRunFinalizeTests(unittest.TestCase):
    def test_finalize_persists_final_status_before_reload(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            state_path = Path(td) / "state.json"
            state_path.write_text(json.dumps({"session": {"status": "running:recon"}}), encoding="utf-8")
            metrics = FakeMetrics()

            def load_json(path: str):
                return json.loads(Path(path).read_text(encoding="utf-8"))

            def save_json(path: str, data):
                Path(path).write_text(json.dumps(data), encoding="utf-8")

            outcome = finalize_run_outputs(
                root_dir=str(ROOT),
                state_path=str(state_path),
                session_id="sess",
                loop_end=2,
                fast_mode=True,
                enable_exploit=False,
                allow_remote_exp=False,
                exploit_rewrite_enabled=False,
                exploit_rewrite_write_report=False,
                terminal_stage="",
                base_max_loops=1,
                exploit_rewrite_extra_loops=0,
                exploit_rewrite_started_monotonic=0.0,
                exploit_rewrite_same_error_streak=0,
                terminal_non_actionable_verify_streak=0,
                exploit_rewrite_last_error="",
                exploit_rewrite_last_verify_report="",
                exploit_rewrite_last_exp_path="",
                exploit_rewrite_stop_reason="",
                fuse_triggered=False,
                fuse_reason="",
                stop_requested=False,
                has_fail=False,
                max_codex_calls=0,
                max_prompt_chars=0,
                max_wall_time_sec=0.0,
                max_autofix_rounds=0,
                acceptance_cfg={"enabled": False},
                remote_prompt_cfg={},
                kpi_enabled=False,
                per_session_abs=str(Path(td) / "metrics.json"),
                global_kpi_abs=str(Path(td) / "global_metrics.json"),
                metrics=metrics,
                stage_results=[{"loop": 1, "stage": "recon", "ok": True}],
                notes=[],
                cap_cfg={"enabled": False},
                objective_cfg={},
                load_json_fn=load_json,
                save_json_fn=save_json,
                infer_capabilities_fn=lambda state, cfg: SimpleNamespace(changed=False),
                evaluate_objectives_fn=lambda state, cfg, enable_exploit: SimpleNamespace(score=1, to_dict=lambda: {}, target_achieved=False),
                apply_objective_state_fn=lambda state, obj, reason="": state.setdefault("progress", {}).update({"objectives": obj}),
                derive_final_session_status_fn=lambda **kwargs: "finished",
                derive_final_rewrite_reason_fn=lambda **kwargs: "",
                derive_final_exit_decision_fn=lambda **kwargs: SimpleNamespace(exit_code=0, acceptance_failed=False),
                write_exploit_rewrite_report_fn=lambda **kwargs: "",
                write_cost_fuse_report_fn=lambda **kwargs: "artifacts/reports/cost.json",
                write_acceptance_report_fn=lambda **kwargs: ("artifacts/reports/acceptance.json", True),
                ensure_exploit_artifact_links_fn=lambda **kwargs: None,
                maybe_prepare_remote_prompt_fn=lambda **kwargs: "",
                write_timeline_report_fn=lambda *args, **kwargs: "artifacts/reports/timeline.json",
                write_timing_report_fn=lambda *args, **kwargs: "artifacts/reports/timing.json",
                write_summary_report_fn=lambda *args, **kwargs: None,
                merge_external_metric_counters_fn=lambda *args, **kwargs: None,
                refresh_global_kpi_fn=lambda *args, **kwargs: None,
                sync_meta_from_state_fn=lambda *args, **kwargs: None,
                sync_state_meta_cli_fn=lambda *args, **kwargs: None,
                repo_rel_fn=lambda path: path,
                monotonic_now_fn=lambda: 0.0,
            )

            persisted = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(outcome.exit_code, 0)
            self.assertEqual(outcome.final_state.get("session", {}).get("status"), "finished")
            self.assertEqual(persisted.get("session", {}).get("status"), "finished")


if __name__ == "__main__":
    unittest.main()
