from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List

FLAG_RE = re.compile(r"(?:flag|ctf|cyberpeace)\{[^\r\n]{2,200}\}", re.IGNORECASE)


def resolve_repo_path(root_dir: str, raw: str) -> str:
    path = str(raw or "").strip()
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.join(root_dir, path)


def remote_report_indicates_success(root_dir: str, report_path: str) -> bool:
    ap = resolve_repo_path(root_dir, report_path)
    if not ap or (not os.path.exists(ap)) or (not os.path.isfile(ap)):
        return False
    if ap.lower().endswith(".json"):
        try:
            with open(ap, "r", encoding="utf-8") as f:
                doc = json.load(f)
        except Exception:
            doc = {}
        if isinstance(doc, dict):
            for key in ("ok", "remote_ok", "success", "verified", "last_remote_ok"):
                if key in doc and bool(doc.get(key)):
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


def collect_remote_report_candidates(state: Dict[str, Any], meta: Dict[str, Any]) -> List[str]:
    candidates: List[str] = []

    def _push_report(raw: Any) -> None:
        value = str(raw or "").strip()
        if (not value) or (value in candidates):
            return
        candidates.append(value)

    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote_state = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
    for src in (remote_state, remote_meta):
        if isinstance(src, dict):
            _push_report(src.get("last_remote_report", ""))

    latest_state = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    latest_meta = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
    report_keys = (
        "remote_exp_verify_report",
        "remote_run_report",
        "remote_flag_report",
        "remote_flag_capture_report",
        "remote_exp_success",
        "remote_exp_success_report",
        "remote_flag_raw",
    )
    for src in (latest_state, latest_meta):
        if not isinstance(src, dict):
            continue
        for key in report_keys:
            _push_report(src.get(key, ""))

    return candidates


def promote_remote_verification_meta(*, root_dir: str, state: Dict[str, Any], meta: Dict[str, Any]) -> bool:
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    remote_state = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
    remote_ok = bool(remote_state.get("last_remote_ok", False) or remote_meta.get("last_remote_ok", False))
    if (not remote_ok):
        remote_ok = any(remote_report_indicates_success(root_dir, p) for p in collect_remote_report_candidates(state, meta))
    if not remote_ok:
        return False

    changed = False
    remote_meta = dict(remote_meta) if isinstance(remote_meta, dict) else {}
    if not bool(remote_meta.get("last_remote_ok", False)):
        remote_meta["last_remote_ok"] = True
        changed = True
    if meta.get("remote") != remote_meta:
        meta["remote"] = remote_meta
        changed = True

    cur_status = str(meta.get("status", "")).strip()
    if cur_status not in {"finished", "finished_with_errors", "remote_verified"}:
        meta["status"] = "remote_verified"
        changed = True

    obj_meta = meta.get("objective", {}) if isinstance(meta.get("objective", {}), dict) else {}
    obj_meta = dict(obj_meta)
    if not bool(obj_meta.get("competition_target_achieved", False)):
        obj_meta["competition_target_achieved"] = True
        changed = True
    reasons = obj_meta.get("competition_reasons", [])
    if not isinstance(reasons, list):
        reasons = []
    if "session.remote.last_remote_ok=true" not in reasons:
        reasons = list(reasons)
        reasons.append("session.remote.last_remote_ok=true")
        obj_meta["competition_reasons"] = reasons
        changed = True
    if meta.get("objective") != obj_meta:
        meta["objective"] = obj_meta
        changed = True
    return changed
