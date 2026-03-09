#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CASES_DIR = os.path.join(ROOT_DIR, "benchmarks", "cases")
DEFAULT_BASELINE = os.path.join(ROOT_DIR, "benchmarks", "baseline", "latest.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_case(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("case is not an object")
    return data


def load_json_or(path: str, default: Any) -> Any:
    if not path:
        return default
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def run_cmd(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)


def _metrics_from_case_result(item: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "runs_total": 0,
        "loops_total": 0,
        "codex_errors": 0,
        "stage_retries": 0,
        "recoverable_failures": 0,
        "capability_updates": 0,
        "objective_score_latest": 0,
        "exploit_success": 0,
    }
    run_output = item.get("run_output")
    if not isinstance(run_output, dict):
        return out
    metrics_rel = str(run_output.get("metrics", "")).strip()
    if not metrics_rel:
        return out
    metrics_abs = metrics_rel if os.path.isabs(metrics_rel) else os.path.join(ROOT_DIR, metrics_rel)
    m = load_json_or(metrics_abs, {})
    if not isinstance(m, dict):
        return out
    for k in out.keys():
        try:
            out[k] = int(m.get(k, out[k]) or 0)
        except Exception:
            pass
    return out


def compute_scoreboard(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    executed = [x for x in results if not x.get("skipped")]
    ok_cases = [x for x in executed if x.get("ok")]
    failed_cases = [x for x in executed if not x.get("ok")]
    metric_rows = [_metrics_from_case_result(x) for x in executed]
    metric_count = len(metric_rows) if metric_rows else 1

    def total(key: str) -> int:
        return sum(int(x.get(key, 0) or 0) for x in metric_rows)

    return {
        "cases_total": len(results),
        "cases_executed": len(executed),
        "cases_skipped": sum(1 for x in results if x.get("skipped")),
        "cases_ok": len(ok_cases),
        "cases_failed": len(failed_cases),
        "success_rate": (len(ok_cases) / len(executed)) if executed else 0.0,
        "codex_errors_total": total("codex_errors"),
        "stage_retries_total": total("stage_retries"),
        "recoverable_failures_total": total("recoverable_failures"),
        "capability_updates_total": total("capability_updates"),
        "exploit_success_total": total("exploit_success"),
        "objective_score_avg": (total("objective_score_latest") / metric_count) if metric_rows else 0.0,
    }


def compare_with_baseline(
    *,
    current: Dict[str, Any],
    baseline: Dict[str, Any],
    max_success_drop: float,
    max_codex_error_increase: int,
    max_stage_retry_increase: int,
) -> Dict[str, Any]:
    base_score = baseline.get("scoreboard", baseline)
    if not isinstance(base_score, dict):
        return {"ok": False, "errors": ["baseline scoreboard invalid"]}

    errors: List[str] = []
    cur_success = float(current.get("success_rate", 0.0) or 0.0)
    base_success = float(base_score.get("success_rate", 0.0) or 0.0)
    if cur_success < (base_success - float(max_success_drop)):
        errors.append(
            f"success_rate dropped too much: current={cur_success:.4f} baseline={base_success:.4f} allowed_drop={max_success_drop:.4f}"
        )

    cur_codex = int(current.get("codex_errors_total", 0) or 0)
    base_codex = int(base_score.get("codex_errors_total", 0) or 0)
    if cur_codex > (base_codex + int(max_codex_error_increase)):
        errors.append(
            f"codex_errors_total increased too much: current={cur_codex} baseline={base_codex} allowed_inc={max_codex_error_increase}"
        )

    cur_retry = int(current.get("stage_retries_total", 0) or 0)
    base_retry = int(base_score.get("stage_retries_total", 0) or 0)
    if cur_retry > (base_retry + int(max_stage_retry_increase)):
        errors.append(
            f"stage_retries_total increased too much: current={cur_retry} baseline={base_retry} allowed_inc={max_stage_retry_increase}"
        )

    return {"ok": len(errors) == 0, "errors": errors, "baseline_scoreboard": base_score}


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay benchmark cases for run_session workflow")
    ap.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)
    ap.add_argument("--only", default="", help="run only case_id contains this keyword")
    ap.add_argument("--allow-codex-missing", action="store_true")
    ap.add_argument("--baseline", default="")
    ap.add_argument("--gate", action="store_true", help="enable regression gate against baseline")
    ap.add_argument("--max-success-rate-drop", type=float, default=0.05)
    ap.add_argument("--max-codex-errors-increase", type=int, default=2)
    ap.add_argument("--max-stage-retries-increase", type=int, default=4)
    ap.add_argument("--write-baseline", default="", help="write current scoreboard as baseline json")
    ap.add_argument("--fail-on-case-error", action="store_true")
    args = ap.parse_args()

    case_files = sorted(glob.glob(os.path.join(args.cases_dir, "*.json")))
    if not case_files:
        print(f"[replay_benchmarks] no case files under: {args.cases_dir}", file=sys.stderr)
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: List[Dict[str, Any]] = []

    for path in case_files:
        case_id = os.path.splitext(os.path.basename(path))[0]
        if args.only and args.only not in case_id:
            continue

        try:
            case = load_case(path)
        except Exception as e:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "error": f"invalid case json: {e}",
                }
            )
            continue

        if case.get("enabled", True) is False:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": True,
                    "skipped": True,
                    "reason": "enabled=false",
                }
            )
            continue

        challenge_dir = str(case.get("challenge_dir", "")).strip()
        binary = str(case.get("binary", "")).strip()
        max_loops = int(case.get("max_loops", 1) or 1)
        allow_missing = bool(case.get("allow_codex_missing", args.allow_codex_missing))

        if not challenge_dir:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "error": "challenge_dir is required",
                }
            )
            continue

        session_id = f"bench_{case_id}_{ts}"

        cmd_start = [
            "bash",
            os.path.join(ROOT_DIR, "scripts", "start_session.sh"),
            "--challenge-dir",
            challenge_dir,
            "--session-id",
            session_id,
            "--no-codex",
        ]
        if binary:
            cmd_start.extend(["--binary", binary])

        p_start = run_cmd(cmd_start)
        if p_start.returncode != 0:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "session_id": session_id,
                    "start_rc": p_start.returncode,
                    "start_stderr": p_start.stderr[-2000:],
                }
            )
            continue

        cmd_run = [
            sys.executable,
            os.path.join(ROOT_DIR, "scripts", "run_session.py"),
            "--session-id",
            session_id,
            "--max-loops",
            str(max_loops),
        ]
        if allow_missing:
            cmd_run.append("--allow-codex-missing")

        p_run = run_cmd(cmd_run)
        item: Dict[str, Any] = {
            "case_id": case_id,
            "path": os.path.relpath(path, ROOT_DIR),
            "session_id": session_id,
            "ok": p_run.returncode == 0,
            "run_rc": p_run.returncode,
        }

        if p_run.stdout.strip():
            try:
                item["run_output"] = json.loads(p_run.stdout)
            except Exception:
                item["run_stdout_tail"] = p_run.stdout[-2000:]
        if p_run.stderr.strip():
            item["run_stderr_tail"] = p_run.stderr[-2000:]

        item["metrics"] = _metrics_from_case_result(item)
        results.append(item)

    scoreboard = compute_scoreboard(results)
    summary = {
        "generated_utc": utc_now(),
        "scoreboard": scoreboard,
        "results": results,
    }

    baseline_path = args.baseline.strip() or (args.write_baseline.strip() or DEFAULT_BASELINE)
    gate_result: Dict[str, Any] = {"enabled": bool(args.gate), "ok": True, "errors": []}
    if args.gate:
        baseline = load_json_or(baseline_path, {})
        if not isinstance(baseline, dict) or not baseline:
            gate_result = {
                "enabled": True,
                "ok": False,
                "errors": [f"baseline not found or invalid: {os.path.relpath(baseline_path, ROOT_DIR)}"],
            }
        else:
            cmp_res = compare_with_baseline(
                current=scoreboard,
                baseline=baseline,
                max_success_drop=float(args.max_success_rate_drop),
                max_codex_error_increase=int(args.max_codex_errors_increase),
                max_stage_retry_increase=int(args.max_stage_retries_increase),
            )
            gate_result = {
                "enabled": True,
                "ok": bool(cmp_res.get("ok", False)),
                "errors": list(cmp_res.get("errors", [])),
                "baseline_path": os.path.relpath(os.path.abspath(baseline_path), ROOT_DIR),
                "baseline_scoreboard": cmp_res.get("baseline_scoreboard", {}),
            }
    summary["gate"] = gate_result

    out_rel = f"artifacts/reports/benchmark_replay_{ts}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    baseline_write_target = args.write_baseline.strip()
    if baseline_write_target:
        target_abs = baseline_write_target if os.path.isabs(baseline_write_target) else os.path.join(ROOT_DIR, baseline_write_target)
        os.makedirs(os.path.dirname(target_abs), exist_ok=True)
        baseline_doc = {
            "generated_utc": utc_now(),
            "source_report": out_rel,
            "scoreboard": scoreboard,
            "cases": [
                {
                    "case_id": x.get("case_id", ""),
                    "ok": bool(x.get("ok")),
                    "run_rc": int(x.get("run_rc", 0) or 0),
                }
                for x in results
                if not x.get("skipped")
            ],
        }
        with open(target_abs, "w", encoding="utf-8") as f:
            json.dump(baseline_doc, f, ensure_ascii=False, indent=2)
        summary["baseline_written"] = os.path.relpath(os.path.abspath(target_abs), ROOT_DIR)

    print(json.dumps({"report": out_rel, "summary": summary}, ensure_ascii=False, indent=2))

    if args.gate and (not gate_result.get("ok", True)):
        return 3
    if args.fail_on_case_error and int(scoreboard.get("cases_failed", 0) or 0) > 0:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
