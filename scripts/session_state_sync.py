#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any, Callable, Dict


def sync_meta_from_state(
    root_dir: str,
    session_id: str,
    state: Dict[str, Any],
    report_rel: str = "",
    metrics_rel: str = "",
    utc_now_fn: Callable[[], str] | None = None,
) -> None:
    meta_path = os.path.join(root_dir, "sessions", session_id, "meta.json")
    if not os.path.exists(meta_path):
        return
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
    except Exception:
        return

    now = utc_now_fn() if callable(utc_now_fn) else ""
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    same_sid = str(sess.get("session_id", "")).strip() == str(session_id).strip()

    if same_sid:
        meta["status"] = sess.get("status", meta.get("status", ""))
        meta.setdefault("codex", {})["enabled"] = bool(
            sess.get("codex_enabled", meta.get("codex", {}).get("enabled", False))
        )
        meta["codex"]["pid"] = sess.get("codex_pid", meta.get("codex", {}).get("pid"))
        if "last_error" in sess:
            meta["codex"]["last_error"] = sess.get("last_error")

        meta.setdefault("exp", {})
        for key in [
            "path",
            "status",
            "generated_utc",
            "last_error",
            "strategy",
            "strategy_hint",
            "plan_report",
            "local_verify_passed",
            "local_verified_utc",
            "verify_report",
        ]:
            if key in exp:
                meta["exp"][key] = exp.get(key)
        if bool(exp.get("local_verify_passed", False)):
            cur_status = str(meta.get("status", "")).strip()
            if cur_status not in {"remote_verified", "finished", "finished_with_errors", "local_verified"}:
                if (not cur_status) or cur_status.startswith("failed:") or cur_status in {"running", "pending"}:
                    meta["status"] = "local_verified"

        remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
        if remote:
            meta["remote"] = remote

        ch_state = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
        if ch_state:
            ch_meta = meta.setdefault("challenge", {})
            name_val = str(ch_state.get("name", "")).strip()
            if name_val:
                ch_meta["name"] = name_val
            bin_val = str(ch_state.get("binary_path", "")).strip()
            if bin_val:
                ch_meta["binary_path"] = bin_val
            work_val = str(ch_state.get("workdir", "")).strip()
            if work_val:
                ch_meta["work_dir"] = work_val
            import_meta = ch_state.get("import_meta", {}) if isinstance(ch_state.get("import_meta", {}), dict) else {}
            src_val = str(import_meta.get("source_dir", "")).strip()
            if src_val:
                ch_meta["source_dir"] = src_val

        latest_paths = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
        if isinstance(latest_paths, dict):
            meta["latest_artifacts"] = latest_paths

        objectives = (
            state.get("progress", {}).get("objectives", {})
            if isinstance(state.get("progress", {}), dict)
            and isinstance(state.get("progress", {}).get("objectives", {}), dict)
            else {}
        )
        if objectives:
            sess_remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
            competition_ok = bool(
                objectives.get("competition_target_achieved", False) or sess_remote.get("last_remote_ok", False)
            )
            reasons = objectives.get("competition_reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            meta["objective"] = {
                "score": int(objectives.get("score", 0) or 0),
                "target_achieved": bool(objectives.get("target_achieved", False)),
                "competition_target_achieved": competition_ok,
                "competition_reasons": list(reasons),
                "missing_stages": objectives.get("missing_stages", []),
                "blockers": objectives.get("blockers", []),
                "last_objective_report": str(objectives.get("last_objective_report", "")).strip(),
                "last_eval_utc": str(objectives.get("last_eval_utc", "")).strip(),
            }

    if report_rel or metrics_rel:
        meta.setdefault("latest_run", {})
        if report_rel:
            meta["latest_run"]["report"] = report_rel
        if metrics_rel:
            meta["latest_run"]["metrics"] = metrics_rel
        if now:
            meta["latest_run"]["updated_utc"] = now

    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)


def sync_state_meta_cli(
    root_dir: str,
    session_id: str,
    state_path: str,
    report_rel: str = "",
    metrics_rel: str = "",
) -> None:
    if not session_id:
        return
    cmd = [
        sys.executable,
        os.path.join(root_dir, "scripts", "sync_state_meta.py"),
        "--state",
        state_path,
        "--session-id",
        session_id,
    ]
    if report_rel:
        cmd.extend(["--report", report_rel])
    if metrics_rel:
        cmd.extend(["--metrics", metrics_rel])
    try:
        subprocess.run(cmd, cwd=root_dir, text=True, capture_output=True, check=False, timeout=3.0)
    except Exception:
        return
