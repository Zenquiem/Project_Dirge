#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
FLAG_RE = re.compile(r"(?:flag|ctf|cyberpeace)\{[^\r\n]{2,200}\}", re.IGNORECASE)


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


def _resolve_repo_path(raw: str) -> str:
    p = str(raw or "").strip()
    if not p:
        return ""
    if os.path.isabs(p):
        return p
    return os.path.join(ROOT_DIR, p)


def _remote_report_indicates_success(report_path: str) -> bool:
    ap = _resolve_repo_path(report_path)
    if not ap or (not os.path.exists(ap)) or (not os.path.isfile(ap)):
        return False
    if ap.lower().endswith(".json"):
        doc = _load_json(ap, {})
        if isinstance(doc, dict):
            for k in ["ok", "remote_ok", "success", "verified", "last_remote_ok"]:
                if k in doc and bool(doc.get(k)):
                    return True
            verify = doc.get("verify", {}) if isinstance(doc.get("verify", {}), dict) else {}
            if bool(verify.get("ok", False)):
                return True
            try:
                payload = json.dumps(doc, ensure_ascii=False)
            except Exception:
                payload = ""
            if payload and FLAG_RE.search(payload):
                return True
    try:
        with open(ap, "rb") as f:
            data = f.read(16384)
        txt = data.decode("latin-1", errors="ignore")
    except Exception:
        txt = ""
    low = txt.lower()
    if "__pwn_verify_ok__" in low:
        return True
    if "you pwned me" in low:
        return True
    if FLAG_RE.search(txt):
        return True
    return False


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

        ch_meta = meta.get("challenge", {}) if isinstance(meta.get("challenge", {}), dict) else {}
        if ch_meta:
            for sk, mk in [("name", "name"), ("workdir", "work_dir"), ("binary_path", "binary_path")]:
                if sk in challenge and challenge.get(sk) and ch_meta.get(mk) != challenge.get(sk):
                    ch_meta[mk] = challenge.get(sk)
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
    remote_state = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
    remote_ok = bool(remote_state.get("last_remote_ok", False) or remote_meta.get("last_remote_ok", False))
    report_candidates: List[str] = []

    def _push_report(p: str) -> None:
        s = str(p or "").strip()
        if (not s) or (s in report_candidates):
            return
        report_candidates.append(s)

    for src in [remote_state, remote_meta]:
        if isinstance(src, dict):
            _push_report(str(src.get("last_remote_report", "")).strip())
    latest_state = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    latest_meta = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
    for src in [latest_state, latest_meta]:
        if not isinstance(src, dict):
            continue
        for key in [
            "remote_exp_verify_report",
            "remote_run_report",
            "remote_flag_report",
            "remote_flag_capture_report",
            "remote_exp_success",
            "remote_exp_success_report",
            "remote_flag_raw",
        ]:
            _push_report(str(src.get(key, "")).strip())

    if (not remote_ok) and report_candidates:
        remote_ok = any(_remote_report_indicates_success(p) for p in report_candidates)

    if remote_ok:
        remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
        if not bool(remote_meta.get("last_remote_ok", False)):
            remote_meta["last_remote_ok"] = True
            changed = True
        meta["remote"] = remote_meta

        cur_status = str(meta.get("status", "")).strip()
        if cur_status not in {"finished", "finished_with_errors", "remote_verified"}:
            meta["status"] = "remote_verified"
            changed = True

        obj_meta = meta.get("objective", {}) if isinstance(meta.get("objective", {}), dict) else {}
        if not bool(obj_meta.get("competition_target_achieved", False)):
            obj_meta["competition_target_achieved"] = True
            changed = True
        reasons = obj_meta.get("competition_reasons", [])
        if not isinstance(reasons, list):
            reasons = []
        if "session.remote.last_remote_ok=true" not in reasons:
            reasons.append("session.remote.last_remote_ok=true")
            obj_meta["competition_reasons"] = reasons
            changed = True
        meta["objective"] = obj_meta

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
