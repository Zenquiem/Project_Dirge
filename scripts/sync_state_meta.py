#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict

from core.meta_sync_utils import promote_remote_verification_meta

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main() -> int:
    ap = argparse.ArgumentParser(description="sync state/session fields into sessions/<sid>/meta.json")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--session-id", default="")
    ap.add_argument("--report", default="", help="optional latest_run.report override")
    ap.add_argument("--metrics", default="", help="optional latest_run.metrics override")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    state = _load_json(args.state, {})
    if not isinstance(state, dict):
        print(json.dumps({"ok": False, "error": "invalid state json"}, ensure_ascii=False, indent=2))
        return 2

    sid = str(args.session_id or "").strip()
    if not sid:
        sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
        sid = str(sess.get("session_id", "")).strip()
    if not sid:
        print(json.dumps({"ok": False, "error": "empty session_id"}, ensure_ascii=False, indent=2))
        return 2

    meta_path = os.path.join(ROOT_DIR, "sessions", sid, "meta.json")
    meta = _load_json(meta_path, {})
    if not isinstance(meta, dict) or (not meta):
        print(json.dumps({"ok": False, "error": f"meta not found: sessions/{sid}/meta.json"}, ensure_ascii=False, indent=2))
        return 1

    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    same_sid = str(sess.get("session_id", "")).strip() == sid

    changed = False
    if same_sid:
        status = str(sess.get("status", "")).strip()
        if status and meta.get("status") != status:
            meta["status"] = status
            changed = True

        meta.setdefault("codex", {})
        codex = meta.get("codex", {}) if isinstance(meta.get("codex", {}), dict) else {}
        for k_state, k_meta in [("codex_enabled", "enabled"), ("codex_pid", "pid")]:
            if k_state in sess and codex.get(k_meta) != sess.get(k_state):
                codex[k_meta] = sess.get(k_state)
                changed = True
        if "last_error" in sess and codex.get("last_error") != sess.get("last_error"):
            codex["last_error"] = sess.get("last_error")
            changed = True
        meta["codex"] = codex

        meta.setdefault("exp", {})
        exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
        exp_meta = meta.get("exp", {}) if isinstance(meta.get("exp", {}), dict) else {}
        for k in [
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
            if k in exp and exp_meta.get(k) != exp.get(k):
                exp_meta[k] = exp.get(k)
                changed = True
        meta["exp"] = exp_meta
        if bool(exp.get("local_verify_passed", False)):
            cur_status = str(meta.get("status", "")).strip()
            if cur_status not in {"remote_verified", "finished", "finished_with_errors", "local_verified"}:
                if (not cur_status) or cur_status.startswith("failed:") or cur_status in {"running", "pending"}:
                    meta["status"] = "local_verified"
                    changed = True

        remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
        if remote and meta.get("remote") != remote:
            meta["remote"] = remote
            changed = True

        if challenge:
            ch_meta = meta.setdefault("challenge", {})
            if not isinstance(ch_meta, dict):
                ch_meta = {}
            for sk, mk in [("name", "name"), ("workdir", "work_dir"), ("binary_path", "binary_path")]:
                value = challenge.get(sk)
                if value and ch_meta.get(mk) != value:
                    ch_meta[mk] = value
                    changed = True
            import_meta = challenge.get("import_meta", {}) if isinstance(challenge.get("import_meta", {}), dict) else {}
            source_dir = str(import_meta.get("source_dir", "")).strip()
            if source_dir and ch_meta.get("source_dir") != source_dir:
                ch_meta["source_dir"] = source_dir
                changed = True
            meta["challenge"] = ch_meta

        latest_paths = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
        if isinstance(latest_paths, dict) and meta.get("latest_artifacts") != latest_paths:
            meta["latest_artifacts"] = latest_paths
            changed = True

        objectives = (
            state.get("progress", {}).get("objectives", {})
            if isinstance(state.get("progress", {}), dict) and isinstance(state.get("progress", {}).get("objectives", {}), dict)
            else {}
        )
        if objectives:
            remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
            competition_ok = bool(objectives.get("competition_target_achieved", False) or remote.get("last_remote_ok", False))
            reasons = objectives.get("competition_reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            obj_meta = {
                "score": int(objectives.get("score", 0) or 0),
                "target_achieved": bool(objectives.get("target_achieved", False)),
                "competition_target_achieved": competition_ok,
                "competition_reasons": list(reasons),
                "missing_stages": objectives.get("missing_stages", []),
                "blockers": objectives.get("blockers", []),
                "last_objective_report": str(objectives.get("last_objective_report", "")).strip(),
                "last_eval_utc": str(objectives.get("last_eval_utc", "")).strip(),
            }
            if meta.get("objective") != obj_meta:
                meta["objective"] = obj_meta
                changed = True

    rep = str(args.report or "").strip()
    met = str(args.metrics or "").strip()
    if rep or met:
        latest = meta.get("latest_run", {}) if isinstance(meta.get("latest_run", {}), dict) else {}
        if rep and latest.get("report") != rep:
            latest["report"] = rep
            changed = True
        if met and latest.get("metrics") != met:
            latest["metrics"] = met
            changed = True
        latest["updated_utc"] = utc_now()
        meta["latest_run"] = latest

    # Drift guard: remote flag already captured but meta/status still shows failed.
    if promote_remote_verification_meta(root_dir=ROOT_DIR, state=state, meta=meta):
        changed = True

    out = {
        "ok": True,
        "session_id": sid,
        "meta_path": os.path.relpath(meta_path, ROOT_DIR),
        "changed": bool(changed),
        "same_session_in_state": bool(same_sid),
    }
    if changed and (not args.dry_run):
        _save_json(meta_path, meta)
        out["written"] = True
    else:
        out["written"] = False
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
