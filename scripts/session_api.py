#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Any, Dict, List

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATE_PATH = os.path.join(ROOT_DIR, "state", "state.json")
ARTIFACTS_DIR = os.path.join(ROOT_DIR, "artifacts")
KPI_PATH = os.path.join(ROOT_DIR, "artifacts", "reports", "kpi_latest.json")
sys.path.insert(0, ROOT_DIR)

from core.session_control import self_stop_blocked_by_env, write_stop_request  # noqa: E402


def run_cmd(cmd: List[str], *, passthrough_stdio: bool = False) -> int:
    if passthrough_stdio:
        p = subprocess.run(cmd, cwd=ROOT_DIR, check=False)
        return int(p.returncode)

    p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)
    if p.stdout:
        print(p.stdout, end="")
    if p.stderr:
        print(p.stderr, end="", file=sys.stderr)
    return int(p.returncode)


def _metrics_path_for(session_id: str) -> str:
    return os.path.join(ROOT_DIR, "sessions", session_id, "metrics.json")


def _bump_metric(session_id: str, key: str, delta: int = 1) -> None:
    if not session_id or (not key):
        return
    meta_path = _session_meta_path(session_id)
    if not os.path.exists(meta_path):
        return
    p = _metrics_path_for(session_id)
    doc = _read_json_or(p, {})
    if not isinstance(doc, dict):
        doc = {}
    cur = int(doc.get(key, 0) or 0)
    doc[key] = max(0, cur + int(delta))
    doc["session_id"] = str(doc.get("session_id", "") or session_id)
    doc["updated_utc"] = utc_now()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)


def _sync_state_meta(session_id: str, report: str = "", metrics: str = "") -> None:
    if not session_id:
        return
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "sync_state_meta.py"),
        "--state",
        STATE_PATH,
        "--session-id",
        session_id,
    ]
    if report:
        cmd.extend(["--report", report])
    if metrics:
        cmd.extend(["--metrics", metrics])
    try:
        subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False, timeout=3.0)
    except Exception:
        return


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _read_json_or(path: str, default: Any) -> Any:
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _session_meta_path(session_id: str) -> str:
    return os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")


def _session_metrics_path(meta: Dict[str, Any], session_id: str) -> str:
    latest = meta.get("latest_run", {}) if isinstance(meta.get("latest_run", {}), dict) else {}
    p = str(latest.get("metrics", "")).strip()
    if p:
        return os.path.join(ROOT_DIR, p) if not os.path.isabs(p) else p
    return os.path.join(ROOT_DIR, "sessions", session_id, "metrics.json")


def _recent_transactions(session_id: str, tail: int = 8) -> List[Dict[str, Any]]:
    tx_dir = os.path.join(ROOT_DIR, "sessions", session_id, "transactions")
    if not os.path.isdir(tx_dir):
        return []
    metas: List[str] = []
    for name in os.listdir(tx_dir):
        if name.endswith(".meta.json"):
            metas.append(os.path.join(tx_dir, name))
    metas.sort()
    out: List[Dict[str, Any]] = []
    for p in metas[-max(1, int(tail)) :]:
        obj = _read_json_or(p, {})
        if isinstance(obj, dict):
            obj = dict(obj)
            obj["meta_path"] = os.path.relpath(p, ROOT_DIR)
            out.append(obj)
    return out


def _current_state_for_session(session_id: str) -> Dict[str, Any]:
    s = _read_json_or(STATE_PATH, {})
    if not isinstance(s, dict):
        return {}
    cur_sid = str(s.get("session", {}).get("session_id", "")).strip() if isinstance(s.get("session", {}), dict) else ""
    return s if cur_sid == session_id else {}


def _session_summary(session_id: str, tail: int = 8) -> Dict[str, Any]:
    meta_path = _session_meta_path(session_id)
    meta = _read_json_or(meta_path, {})
    if not isinstance(meta, dict):
        return {"session_id": session_id, "error": "session not found"}

    metrics_path = _session_metrics_path(meta, session_id)
    metrics = _read_json_or(metrics_path, {})
    if not isinstance(metrics, dict):
        metrics = {}

    tx = _recent_transactions(session_id, tail=tail)
    state = _current_state_for_session(session_id)

    challenge = meta.get("challenge", {}) if isinstance(meta.get("challenge", {}), dict) else {}
    exp = meta.get("exp", {}) if isinstance(meta.get("exp", {}), dict) else {}
    latest_run = meta.get("latest_run", {}) if isinstance(meta.get("latest_run", {}), dict) else {}
    remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
    remote_state = state.get("session", {}).get("remote", {}) if isinstance(state.get("session", {}).get("remote", {}), dict) else {}
    remote = remote_state if remote_state else remote_meta
    progress = state.get("progress", {}) if isinstance(state.get("progress", {}), dict) else {}
    objectives = progress.get("objectives", {}) if isinstance(progress.get("objectives", {}), dict) else {}
    if not objectives:
        objectives = meta.get("objective", {}) if isinstance(meta.get("objective", {}), dict) else {}
    competition_target_achieved = bool(
        objectives.get("competition_target_achieved", False) or remote.get("last_remote_ok", False)
    )

    last_tx = tx[-1] if tx else {}
    return {
        "session_id": session_id,
        "created_utc": meta.get("created_utc", ""),
        "status": meta.get("status", ""),
        "challenge": {
            "name": challenge.get("name", ""),
            "source_dir": challenge.get("source_dir", ""),
            "work_dir": challenge.get("work_dir", ""),
            "binary_path": challenge.get("binary_path", ""),
        },
        "exp": {
            "path": exp.get("path", ""),
            "status": exp.get("status", ""),
            "strategy": exp.get("strategy", ""),
            "plan_report": exp.get("plan_report", ""),
            "local_verify_passed": exp.get("local_verify_passed", False),
        },
        "remote": {
            "ask_pending": bool(remote.get("ask_pending", False)),
            "request_file": remote.get("request_file", ""),
            "requested_utc": remote.get("requested_utc", ""),
            "answer": remote.get("answer", ""),
            "answered_utc": remote.get("answered_utc", ""),
            "target": remote.get("target", {"host": "", "port": 0}),
            "last_preflight_report": remote.get("last_preflight_report", ""),
            "last_remote_report": remote.get("last_remote_report", ""),
            "last_remote_ok": bool(remote.get("last_remote_ok", False)),
        },
        "metrics": {
            "runs_total": metrics.get("runs_total", 0),
            "loops_total": metrics.get("loops_total", 0),
            "codex_calls": metrics.get("codex_calls", 0),
            "prompt_chars_total": metrics.get("prompt_chars_total", 0),
            "avg_stage_sec": metrics.get("avg_stage_sec", 0),
            "wall_time_sec": metrics.get("wall_time_sec", 0),
            "codex_errors": metrics.get("codex_errors", 0),
            "stage_retries": metrics.get("stage_retries", 0),
            "timeout_circuit_activations": metrics.get("timeout_circuit_activations", 0),
            "timeout_circuit_skips": metrics.get("timeout_circuit_skips", 0),
            "objective_score_latest": metrics.get("objective_score_latest", 0),
            "objective_target_hits": metrics.get("objective_target_hits", 0),
            "remote_connect_attempts": metrics.get("remote_connect_attempts", 0),
            "self_stop_blocked": metrics.get("self_stop_blocked", 0),
            "autofix_rounds_total": metrics.get("autofix_rounds_total", 0),
        },
        "objective": {
            "score": objectives.get("score", 0),
            "target_achieved": objectives.get("target_achieved", False),
            "competition_target_achieved": competition_target_achieved,
            "missing_stages": objectives.get("missing_stages", []),
            "blockers": objectives.get("blockers", []),
            "last_objective_report": objectives.get("last_objective_report", ""),
        },
        "latest": {
            "report": latest_run.get("report", ""),
            "metrics": latest_run.get("metrics", ""),
            "last_stage": last_tx.get("stage", ""),
            "last_stage_ok": last_tx.get("ok", None),
            "last_stage_tx_meta": last_tx.get("meta_path", ""),
            "artifacts": meta.get("latest_artifacts", {}),
        },
        "recent_transactions": tx,
    }


def find_session_pid(session_id: str) -> int:
    meta_path = os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")
    pid_path = os.path.join(ROOT_DIR, "sessions", session_id, "codex.pid")

    if os.path.exists(meta_path):
        try:
            m = load_json(meta_path)
            pid = m.get("codex", {}).get("pid")
            if isinstance(pid, int) and pid > 0:
                return pid
        except Exception:
            pass

    if os.path.exists(pid_path):
        try:
            with open(pid_path, "r", encoding="utf-8") as f:
                raw = f.read().strip()
            if raw.isdigit():
                return int(raw)
        except Exception:
            pass

    return 0


def process_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def update_session_status(session_id: str, status: str, last_error: str = "") -> None:
    meta_path = os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")
    if os.path.exists(meta_path):
        try:
            meta = load_json(meta_path)
            meta["status"] = status
            meta.setdefault("codex", {})["pid"] = None
            if last_error:
                meta["codex"]["last_error"] = last_error
            save_json(meta_path, meta)
        except Exception:
            pass

    if os.path.exists(STATE_PATH):
        try:
            s = load_json(STATE_PATH)
            cur_sid = s.get("session", {}).get("session_id", "")
            if cur_sid == session_id:
                s.setdefault("session", {})["status"] = status
                s["session"]["codex_pid"] = None
                if last_error:
                    s["session"]["last_error"] = last_error
                save_json(STATE_PATH, s)
        except Exception:
            pass


def current_meta_status(session_id: str) -> str:
    meta_path = os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")
    if not os.path.exists(meta_path):
        return ""
    try:
        return str(load_json(meta_path).get("status", "")).strip()
    except Exception:
        return ""


def choose_stop_status(session_id: str) -> str:
    cur = current_meta_status(session_id)
    if cur in {"finished", "finished_with_errors"}:
        return cur
    return "stopped"


def cmd_stop(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py stop", description="stop running codex process for a session")
    sp.add_argument("session_id")
    sp.add_argument("--force", action="store_true", help="use SIGKILL if SIGTERM timeout")
    sp.add_argument("--timeout-sec", type=float, default=3.0)
    args = sp.parse_args(argv)

    session_id = args.session_id
    if self_stop_blocked_by_env():
        _bump_metric(session_id, "self_stop_blocked", 1)
        _sync_state_meta(session_id)
        print(
            json.dumps(
                {
                    "session_id": session_id,
                    "ok": False,
                    "blocked": True,
                    "error": "stop blocked in autorun context",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 1

    pid = find_session_pid(session_id)
    result: Dict[str, Any] = {
        "session_id": session_id,
        "pid": pid,
        "stopped": False,
        "was_running": False,
        "signal": "",
    }

    try:
        flag_path = write_stop_request(ROOT_DIR, session_id, "requested by session_api stop")
        result["stop_request"] = os.path.relpath(flag_path, ROOT_DIR)
    except Exception as e:
        if isinstance(e, PermissionError):
            _bump_metric(session_id, "self_stop_blocked", 1)
        result["stop_request_error"] = str(e)

    if pid <= 0:
        update_session_status(session_id, choose_stop_status(session_id), "no codex pid found")
        _sync_state_meta(session_id)
        result["error"] = "no codex pid found"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if not process_exists(pid):
        update_session_status(session_id, choose_stop_status(session_id), "process not running")
        _sync_state_meta(session_id)
        result["error"] = "process not running"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    result["was_running"] = True

    try:
        os.kill(pid, signal.SIGTERM)
        result["signal"] = "SIGTERM"
    except Exception as e:
        result["error"] = f"SIGTERM failed: {e}"
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 1

    deadline = time.time() + max(1.0, float(args.timeout_sec))
    while time.time() < deadline:
        if not process_exists(pid):
            result["stopped"] = True
            break
        time.sleep(0.1)

    if not result["stopped"] and args.force:
        try:
            os.kill(pid, signal.SIGKILL)
            result["signal"] = "SIGKILL"
            time.sleep(0.1)
            result["stopped"] = not process_exists(pid)
        except Exception as e:
            result["error"] = f"SIGKILL failed: {e}"

    if result["stopped"]:
        update_session_status(session_id, choose_stop_status(session_id), "stopped by session_api")
    else:
        update_session_status(session_id, "stop_failed", "unable to stop process")
    _sync_state_meta(session_id)

    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["stopped"] else 1


def cmd_inspect(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py inspect", description="show enriched session detail for UI")
    sp.add_argument("session_id")
    sp.add_argument("--tail", type=int, default=8)
    args = sp.parse_args(argv)
    summary = _session_summary(args.session_id, tail=args.tail)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if "error" not in summary else 1


def cmd_overview(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py overview", description="list enriched session overview for UI")
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--tail", type=int, default=3)
    args = sp.parse_args(argv)

    sessions_dir = os.path.join(ROOT_DIR, "sessions")
    if not os.path.isdir(sessions_dir):
        print("[]")
        return 0

    metas: List[Dict[str, Any]] = []
    for name in os.listdir(sessions_dir):
        p = os.path.join(sessions_dir, name, "meta.json")
        m = _read_json_or(p, {})
        if isinstance(m, dict) and m:
            metas.append(m)
    metas.sort(key=lambda x: str(x.get("created_utc", "")), reverse=True)

    out: List[Dict[str, Any]] = []
    for m in metas[: max(1, int(args.limit))]:
        sid = str(m.get("session_id", "")).strip()
        if not sid:
            continue
        out.append(_session_summary(sid, tail=args.tail))
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_timeline(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py timeline", description="show stage timeline for a session")
    sp.add_argument("session_id")
    sp.add_argument("--limit", type=int, default=30)
    args = sp.parse_args(argv)
    tx = _recent_transactions(args.session_id, tail=max(1, int(args.limit)))
    out: List[Dict[str, Any]] = []
    for t in tx:
        out.append(
            {
                "loop": t.get("loop", 0),
                "stage": t.get("stage", ""),
                "ok": t.get("ok", False),
                "started_utc": t.get("started_utc", ""),
                "ended_utc": t.get("ended_utc", ""),
                "attempt_count": t.get("attempt_count", 1),
                "failure_category": t.get("failure_category", ""),
                "log": t.get("log", ""),
                "meta_path": t.get("meta_path", ""),
            }
        )
    print(json.dumps({"session_id": args.session_id, "timeline": out}, ensure_ascii=False, indent=2))
    return 0


def cmd_artifacts(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py artifacts", description="show latest artifacts map for a session")
    sp.add_argument("session_id")
    args = sp.parse_args(argv)
    meta = _read_json_or(_session_meta_path(args.session_id), {})
    if not isinstance(meta, dict) or not meta:
        print(json.dumps({"session_id": args.session_id, "error": "session not found"}, ensure_ascii=False, indent=2))
        return 1
    latest = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
    print(json.dumps({"session_id": args.session_id, "latest_artifacts": latest}, ensure_ascii=False, indent=2))
    return 0


def _remote_request_path(session_id: str) -> str:
    return os.path.join(ROOT_DIR, "sessions", session_id, "control", "remote.requested.json")


def _remote_answer_path(session_id: str) -> str:
    return os.path.join(ROOT_DIR, "sessions", session_id, "control", "remote.answered.json")


def _sync_meta_remote(session_id: str, state: Dict[str, Any]) -> None:
    meta_path = _session_meta_path(session_id)
    if not os.path.exists(meta_path):
        return
    meta = _read_json_or(meta_path, {})
    if not isinstance(meta, dict):
        return
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    if exp:
        meta.setdefault("exp", {})
        if "local_verify_passed" in exp:
            meta["exp"]["local_verify_passed"] = bool(exp.get("local_verify_passed", False))
    if remote:
        meta["remote"] = remote
        if bool(remote.get("last_remote_ok", False)):
            status = str(meta.get("status", "")).strip()
            if status not in {"finished", "finished_with_errors"}:
                meta["status"] = "remote_verified"
            obj = meta.get("objective", {}) if isinstance(meta.get("objective", {}), dict) else {}
            obj["competition_target_achieved"] = True
            reasons = obj.get("competition_reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            if "session.remote.last_remote_ok=true" not in reasons:
                reasons.append("session.remote.last_remote_ok=true")
            obj["competition_reasons"] = reasons
            meta["objective"] = obj
    latest_paths = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    if isinstance(latest_paths, dict):
        meta["latest_artifacts"] = latest_paths
    save_json(meta_path, meta)


def _run_remote_preflight(session_id: str, host: str, port: int, timeout_sec: float) -> Tuple[Dict[str, Any], str]:
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    report_rel = f"artifacts/reports/remote_preflight_{session_id}_{ts}.json"
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "remote_preflight.py"),
        "--host",
        host,
        "--port",
        str(int(port)),
        "--timeout-sec",
        str(float(timeout_sec)),
        "--report",
        report_rel,
    ]
    p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)
    obj: Dict[str, Any] = {}
    if p.stdout.strip():
        try:
            raw = json.loads(p.stdout)
            if isinstance(raw, dict):
                obj = raw
        except Exception:
            obj = {}
    if (not obj) and os.path.exists(os.path.join(ROOT_DIR, report_rel)):
        obj = _read_json_or(os.path.join(ROOT_DIR, report_rel), {})
        if not isinstance(obj, dict):
            obj = {}
    if "report" not in obj:
        obj["report"] = report_rel
    if (not obj.get("ok", False)) and p.stderr.strip() and (not obj.get("dns_error")):
        obj["dns_error"] = p.stderr.strip()[-200:]
    return obj, report_rel


def _run_remote_verify_once(session_id: str, host: str, port: int, timeout_sec: float, report_rel: str) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "verify_local_exp.py"),
        "--state",
        STATE_PATH,
        "--session-id",
        session_id,
        "--run",
        "--run-strict",
        "--run-timeout-sec",
        str(float(timeout_sec)),
        "--remote-host",
        host,
        "--remote-port",
        str(int(port)),
        "--report",
        report_rel,
        "--no-update-state",
    ]
    p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)
    out: Dict[str, Any] = {
        "ok": False,
        "report": report_rel,
        "error": "",
        "target": {"host": host, "port": int(port)},
    }
    if p.stdout.strip():
        try:
            raw = json.loads(p.stdout)
            if isinstance(raw, dict):
                out["ok"] = bool(raw.get("ok", False))
                out["report"] = str(raw.get("report", report_rel)).strip() or report_rel
                out["error"] = str(raw.get("error", "")).strip()
        except Exception:
            pass
    if (not out["error"]) and p.stderr.strip():
        out["error"] = p.stderr.strip()[-200:]
    rep_rel = str(out.get("report", report_rel)).strip() or report_rel
    rep_abs = rep_rel if os.path.isabs(rep_rel) else os.path.join(ROOT_DIR, rep_rel)
    rep_doc = _read_json_or(rep_abs, {})
    run_doc = rep_doc.get("run", {}) if isinstance(rep_doc, dict) and isinstance(rep_doc.get("run", {}), dict) else {}
    stage_ev = run_doc.get("stage_evidence", {}) if isinstance(run_doc.get("stage_evidence", {}), dict) else {}
    if stage_ev:
        out["stage1_metrics"] = {
            "attempts": int(stage_ev.get("stage1_attempts", 0) or 0),
            "eof_attempts": int(stage_ev.get("stage1_eof_attempts", 0) or 0),
            "success_proxy_attempts": int(stage_ev.get("stage1_success_proxy_attempts", 0) or 0),
            "success_proxy_rate": stage_ev.get("stage1_success_proxy_rate", None),
            "post_recv_raw_len_max": int(stage_ev.get("stage1_post_recv_raw_len_max", 0) or 0),
            "last_stage": str(stage_ev.get("last_stage", "")).strip(),
            "leak_values_hex_tail": (
                stage_ev.get("leak_values_hex_tail", [])
                if isinstance(stage_ev.get("leak_values_hex_tail", []), list)
                else []
            ),
        }
    else:
        out["stage1_metrics"] = {
            "attempts": 0,
            "eof_attempts": 0,
            "success_proxy_attempts": 0,
            "success_proxy_rate": None,
            "post_recv_raw_len_max": 0,
            "last_stage": "",
            "leak_values_hex_tail": [],
        }
    return out


def cmd_remote_prompt(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py remote-prompt", description="show pending remote connect prompt")
    sp.add_argument("session_id")
    args = sp.parse_args(argv)

    sid = str(args.session_id).strip()
    req_path = _remote_request_path(sid)
    req = _read_json_or(req_path, {})
    state = _read_json_or(STATE_PATH, {})
    cur_sid = str(state.get("session", {}).get("session_id", "")).strip() if isinstance(state.get("session", {}), dict) else ""
    remote = {}
    if cur_sid == sid:
        remote = state.get("session", {}).get("remote", {}) if isinstance(state.get("session", {}).get("remote", {}), dict) else {}
    if not remote:
        meta = _read_json_or(_session_meta_path(sid), {})
        remote = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}

    out = {
        "session_id": sid,
        "pending": bool(remote.get("ask_pending", False)),
        "remote": remote,
        "request_file": os.path.relpath(req_path, ROOT_DIR) if os.path.exists(req_path) else "",
        "request": req if isinstance(req, dict) else {},
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def cmd_remote_answer(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py remote-answer", description="answer remote connect prompt and optional verify")
    sp.add_argument("session_id")
    g = sp.add_mutually_exclusive_group(required=True)
    g.add_argument("--yes", action="store_true")
    g.add_argument("--no", action="store_true")
    sp.add_argument("--host", default="")
    sp.add_argument("--port", type=int, default=0)
    sp.add_argument("--run-verify", action="store_true", help="when --yes, run exp verify against remote")
    sp.add_argument("--timeout-sec", type=float, default=8.0)
    args = sp.parse_args(argv)

    sid = str(args.session_id).strip()
    if not sid:
        print(json.dumps({"ok": False, "error": "empty session_id"}, ensure_ascii=False, indent=2))
        return 2

    state = _read_json_or(STATE_PATH, {})
    if not isinstance(state, dict):
        print(json.dumps({"ok": False, "error": "state unavailable"}, ensure_ascii=False, indent=2))
        return 2
    cur_sid = str(state.get("session", {}).get("session_id", "")).strip() if isinstance(state.get("session", {}), dict) else ""
    if cur_sid != sid:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "remote-answer 仅支持当前活动会话",
                    "session_id": sid,
                    "current_session_id": cur_sid,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 2

    answer = "yes" if bool(args.yes) else "no"
    host = str(args.host or "").strip()
    port = int(args.port or 0)
    if answer == "yes" and ((not host) or port <= 0):
        print(json.dumps({"ok": False, "error": "选择 yes 时必须提供 --host 与 --port"}, ensure_ascii=False, indent=2))
        return 2

    sess = state.setdefault("session", {})
    remote = sess.setdefault("remote", {})
    remote["ask_pending"] = False
    remote["answer"] = answer
    remote["answered_utc"] = utc_now()
    remote["target"] = {"host": host, "port": port}
    remote.setdefault("last_preflight_report", "")

    control_dir = os.path.join(ROOT_DIR, "sessions", sid, "control")
    os.makedirs(control_dir, exist_ok=True)
    ans_doc = {
        "session_id": sid,
        "answered_utc": remote["answered_utc"],
        "answer": answer,
        "target": {"host": host, "port": port},
    }
    ans_path = _remote_answer_path(sid)
    with open(ans_path, "w", encoding="utf-8") as f:
        json.dump(ans_doc, f, ensure_ascii=False, indent=2)

    verify_result: Dict[str, Any] = {
        "attempted": False,
        "ok": False,
        "report": "",
        "error": "",
        "preflight_report": "",
        "preflight_ok": False,
        "blocked": False,
        "blocked_reason": "",
        "targets_tried": [],
    }
    if answer == "yes" and bool(args.run_verify):
        verify_result["attempted"] = True
        preflight, preflight_report_rel = _run_remote_preflight(
            sid,
            host,
            port,
            timeout_sec=min(max(1.0, float(args.timeout_sec) * 0.5), 4.0),
        )
        verify_result["preflight_report"] = str(preflight.get("report", preflight_report_rel)).strip() or preflight_report_rel
        verify_result["preflight_ok"] = bool(preflight.get("ok", False))
        remote["last_preflight_report"] = verify_result["preflight_report"]
        verify_result["blocked"] = bool(preflight.get("network_blocked", False))
        verify_result["blocked_reason"] = str(preflight.get("block_reason", "")).strip()
        dns_fail_only = bool(preflight.get("dns_fail_only", False))

        candidates_raw = preflight.get("candidates", []) if isinstance(preflight.get("candidates", []), list) else []
        candidates = [host] + [str(x).strip() for x in candidates_raw if str(x).strip()]
        dedup: List[str] = []
        for c in candidates:
            if c and (c not in dedup):
                dedup.append(c)
        candidates = dedup[:4]

        latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
        latest["remote_preflight_report"] = verify_result["preflight_report"]

        if verify_result["blocked"]:
            verify_result["ok"] = False
            verify_result["report"] = verify_result["preflight_report"]
            verify_result["error"] = (
                f"remote blocked by environment: {verify_result['blocked_reason'] or 'network operation not permitted'}"
            )
        elif dns_fail_only:
            verify_result["ok"] = False
            verify_result["report"] = verify_result["preflight_report"]
            verify_result["error"] = verify_result["blocked_reason"] or "remote dns resolution failed"
        elif (not verify_result["preflight_ok"]) and (not candidates):
            verify_result["ok"] = False
            verify_result["report"] = verify_result["preflight_report"]
            verify_result["error"] = "remote preflight failed and no candidate target"
        else:
            for idx, target_host in enumerate(candidates, start=1):
                _bump_metric(sid, "remote_connect_attempts", 1)
                ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
                report_rel = f"artifacts/reports/exp_remote_verify_{sid}_{ts}_{idx:02d}.json"
                one = _run_remote_verify_once(
                    sid,
                    host=target_host,
                    port=port,
                    timeout_sec=float(args.timeout_sec),
                    report_rel=report_rel,
                )
                verify_result["targets_tried"].append(
                    {
                        "host": target_host,
                        "ok": bool(one.get("ok", False)),
                        "report": str(one.get("report", report_rel)),
                        "error": str(one.get("error", "")),
                        "stage1_metrics": (
                            one.get("stage1_metrics", {})
                            if isinstance(one.get("stage1_metrics", {}), dict)
                            else {}
                        ),
                    }
                )
                if one.get("ok", False):
                    verify_result["ok"] = True
                    verify_result["report"] = str(one.get("report", report_rel)).strip() or report_rel
                    verify_result["error"] = ""
                    break
                verify_result["report"] = str(one.get("report", report_rel)).strip() or report_rel
                verify_result["error"] = str(one.get("error", "")).strip()

        remote["last_remote_report"] = verify_result["report"]
        remote["last_remote_ok"] = bool(verify_result["ok"])
        latest["remote_exp_verify_report"] = verify_result["report"]
        if verify_result["ok"]:
            caps = state.setdefault("capabilities", {})
            caps["exploit_success"] = True
            sess["status"] = "remote_verified"
            objectives = state.setdefault("progress", {}).setdefault("objectives", {})
            objectives["competition_target_achieved"] = True
            reasons = objectives.get("competition_reasons", [])
            if not isinstance(reasons, list):
                reasons = []
            if "session.remote.last_remote_ok=true" not in reasons:
                reasons.append("session.remote.last_remote_ok=true")
            objectives["competition_reasons"] = reasons

    save_json(STATE_PATH, state)
    _sync_meta_remote(sid, state)
    _sync_state_meta(sid)

    out = {
        "ok": True,
        "session_id": sid,
        "answer": answer,
        "target": {"host": host, "port": port},
        "answer_file": os.path.relpath(ans_path, ROOT_DIR),
        "verify": verify_result,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


def _is_inside_repo(path: str) -> bool:
    try:
        ap = os.path.abspath(path)
        return os.path.commonpath([ROOT_DIR, ap]) == ROOT_DIR
    except Exception:
        return False


def _contains_sid(obj: Any, sid: str) -> bool:
    if not sid:
        return False
    if isinstance(obj, str):
        return sid in obj
    if isinstance(obj, dict):
        return any(_contains_sid(k, sid) or _contains_sid(v, sid) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_sid(x, sid) for x in obj)
    return False


def _remove_path(path: str, dry_run: bool, removed: List[str]) -> None:
    ap = os.path.abspath(path)
    if not _is_inside_repo(ap):
        return
    if not os.path.exists(ap):
        return
    rel = os.path.relpath(ap, ROOT_DIR)
    if not dry_run:
        if os.path.isdir(ap) and (not os.path.islink(ap)):
            shutil.rmtree(ap, ignore_errors=True)
        else:
            try:
                os.remove(ap)
            except FileNotFoundError:
                pass
    removed.append(rel)


def _collect_artifact_targets(session_id: str) -> List[str]:
    out: List[str] = []
    if not os.path.isdir(ARTIFACTS_DIR):
        return out

    for cur, dirs, files in os.walk(ARTIFACTS_DIR, topdown=False):
        for name in files:
            p = os.path.join(cur, name)
            rel = os.path.relpath(p, ROOT_DIR)
            if session_id in rel:
                out.append(p)
        for name in dirs:
            p = os.path.join(cur, name)
            rel = os.path.relpath(p, ROOT_DIR)
            if session_id in rel:
                out.append(p)
    return out


def _prune_state_for_deleted_session(state: Dict[str, Any], session_id: str) -> Dict[str, Any]:
    stats = {
        "changed": False,
        "removed_runs": 0,
        "removed_latest_paths": 0,
        "removed_inputs": 0,
        "removed_evidence": 0,
        "removed_clusters": 0,
        "reset_current_session": False,
    }

    art = state.get("artifacts_index", {}) if isinstance(state.get("artifacts_index", {}), dict) else {}
    runs = art.get("runs", []) if isinstance(art.get("runs", []), list) else []
    new_runs = [r for r in runs if not _contains_sid(r, session_id)]
    if len(new_runs) != len(runs):
        stats["changed"] = True
        stats["removed_runs"] = len(runs) - len(new_runs)
        art["runs"] = new_runs

    latest = art.get("latest", {}) if isinstance(art.get("latest", {}), dict) else {}
    paths = latest.get("paths", {}) if isinstance(latest.get("paths", {}), dict) else {}
    for k in list(paths.keys()):
        v = paths.get(k)
        if _contains_sid(k, session_id) or _contains_sid(v, session_id):
            paths.pop(k, None)
            stats["removed_latest_paths"] += 1
            stats["changed"] = True
    if _contains_sid(latest.get("run_id", ""), session_id):
        latest["run_id"] = ""
        stats["changed"] = True
    latest["paths"] = paths
    art["latest"] = latest
    state["artifacts_index"] = art

    dynamic = state.get("dynamic_evidence", {}) if isinstance(state.get("dynamic_evidence", {}), dict) else {}
    inputs = dynamic.get("inputs", []) if isinstance(dynamic.get("inputs", []), list) else []
    evidence = dynamic.get("evidence", []) if isinstance(dynamic.get("evidence", []), list) else []
    clusters = dynamic.get("clusters", []) if isinstance(dynamic.get("clusters", []), list) else []

    new_inputs = [x for x in inputs if not _contains_sid(x, session_id)]
    new_evidence = [x for x in evidence if not _contains_sid(x, session_id)]
    new_clusters = [x for x in clusters if not _contains_sid(x, session_id)]
    if len(new_inputs) != len(inputs):
        stats["removed_inputs"] = len(inputs) - len(new_inputs)
        stats["changed"] = True
    if len(new_evidence) != len(evidence):
        stats["removed_evidence"] = len(evidence) - len(new_evidence)
        stats["changed"] = True
    if len(new_clusters) != len(clusters):
        stats["removed_clusters"] = len(clusters) - len(new_clusters)
        stats["changed"] = True
    dynamic["inputs"] = new_inputs
    dynamic["evidence"] = new_evidence
    dynamic["clusters"] = new_clusters
    state["dynamic_evidence"] = dynamic

    session = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    is_current = str(session.get("session_id", "")).strip() == session_id
    if is_current:
        stats["reset_current_session"] = True
        stats["changed"] = True
        state["challenge"] = {"name": "", "binary_path": "", "workdir": ".", "notes": "", "import_meta": {}}
        state["capabilities"] = {
            "has_crash": False,
            "crash_stable": False,
            "rip_control": "unknown",
            "stack_smash_suspected": False,
            "has_leak": "unknown",
            "write_primitive": "unknown",
            "notes": "",
            "control_rip": False,
            "offset_to_rip": 0,
            "ret2win_path_verified": False,
            "system_call_observed": False,
            "exploit_success": False,
        }
        state["latest_bases"] = {"pie_base": "", "libc_base": ""}
        state["static_analysis"] = {"entrypoints": [], "suspects": [], "hypotheses": []}
        state["hypotheses"] = {"active": [], "dead": []}
        state["summary"] = {"current_best_guess": "", "blockers": [], "next_actions": []}
        state["progress"] = {
            "stage": "init",
            "run_seq": 0,
            "loop_seq": 0,
            "decision": {
                "adaptive_stage_order": True,
                "no_progress_loops": 0,
                "last_stage_plan": [],
                "last_decision_report": "",
                "last_active_hypothesis_ids": [],
                "last_loop_had_progress": False,
            },
            "objectives": {
                "score": 0,
                "target_achieved": False,
                "required_stages": [],
                "missing_stages": [],
                "blockers": [],
                "last_objective_report": "",
                "last_eval_utc": "",
            },
            "counters": {
                "total_runs": 0,
                "recon_runs": 0,
                "ida_calls": 0,
                "gdb_runs": 0,
                "exploit_runs": 0,
            },
            "last_updated_utc": "",
        }
        state["session"] = {
            "session_id": "",
            "created_utc": "",
            "status": "init",
            "codex_enabled": False,
            "codex_pid": None,
            "challenge_source_dir": "",
            "challenge_work_dir": "",
            "conversation_log": "",
            "prompt_file": "",
            "exp": {
                "path": "",
                "status": "enabled",
                "generated_utc": "",
                "strategy": "",
                "plan_report": "",
                "local_verify_passed": False,
            },
            "remote": {
                "ask_pending": False,
                "request_file": "",
                "requested_utc": "",
                "answer": "",
                "answered_utc": "",
                "target": {"host": "", "port": 0},
                "last_preflight_report": "",
                "last_remote_report": "",
                "last_remote_ok": False,
            },
        }
    else:
        ch = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
        for k in ["name", "binary_path", "workdir", "notes"]:
            v = ch.get(k, "")
            if isinstance(v, str) and session_id in v:
                ch[k] = ""
                stats["changed"] = True
        state["challenge"] = ch

        for k in ["challenge_source_dir", "challenge_work_dir", "conversation_log", "prompt_file"]:
            v = session.get(k, "")
            if isinstance(v, str) and session_id in v:
                session[k] = ""
                stats["changed"] = True
        exp = session.get("exp", {}) if isinstance(session.get("exp", {}), dict) else {}
        for k in ["path", "plan_report", "generated_utc", "strategy", "last_error"]:
            v = exp.get(k, "")
            if isinstance(v, str) and session_id in v:
                exp[k] = ""
                stats["changed"] = True
        session["exp"] = exp
        state["session"] = session

        progress = state.get("progress", {}) if isinstance(state.get("progress", {}), dict) else {}
        decision = progress.get("decision", {}) if isinstance(progress.get("decision", {}), dict) else {}
        objectives = progress.get("objectives", {}) if isinstance(progress.get("objectives", {}), dict) else {}
        for k in ["last_decision_report"]:
            v = decision.get(k, "")
            if isinstance(v, str) and session_id in v:
                decision[k] = ""
                stats["changed"] = True
        for k in ["last_objective_report"]:
            v = objectives.get(k, "")
            if isinstance(v, str) and session_id in v:
                objectives[k] = ""
                stats["changed"] = True
        progress["decision"] = decision
        progress["objectives"] = objectives
        state["progress"] = progress

    return stats


def _prune_state_file(session_id: str, dry_run: bool) -> Dict[str, Any]:
    info = {"updated": False}
    if not os.path.exists(STATE_PATH):
        return info
    try:
        state = load_json(STATE_PATH)
    except Exception as e:
        return {"updated": False, "error": str(e)}
    before = json.dumps(state, ensure_ascii=False, sort_keys=True)
    stats = _prune_state_for_deleted_session(state, session_id)
    after = json.dumps(state, ensure_ascii=False, sort_keys=True)
    changed = before != after
    info.update(stats)
    info["updated"] = bool(changed)
    if changed and (not dry_run):
        save_json(STATE_PATH, state)
    return info


def _prune_kpi_file(session_id: str, dry_run: bool) -> Dict[str, Any]:
    if not os.path.exists(KPI_PATH):
        return {"updated": False, "removed_sessions": 0}
    try:
        doc = load_json(KPI_PATH)
    except Exception as e:
        return {"updated": False, "removed_sessions": 0, "error": str(e)}

    sessions = doc.get("sessions", []) if isinstance(doc.get("sessions", []), list) else []
    new_sessions = [x for x in sessions if str(x.get("session_id", "")).strip() != session_id] if sessions else []
    removed = len(sessions) - len(new_sessions)

    old_summary = doc.get("summary", {}) if isinstance(doc.get("summary", {}), dict) else {}
    new_summary: Dict[str, Any] = {"sessions": len(new_sessions)}
    for k, v in old_summary.items():
        if k == "sessions":
            continue
        if not isinstance(v, (int, float)):
            continue
        total = 0
        for s in new_sessions:
            sv = s.get(k, 0)
            if isinstance(sv, (int, float)):
                total += sv
        new_summary[k] = int(total)

    changed = (removed > 0) or (old_summary != new_summary)
    if changed and (not dry_run):
        doc["sessions"] = new_sessions
        doc["summary"] = new_summary
        save_json(KPI_PATH, doc)

    return {"updated": bool(changed), "removed_sessions": removed}


def _remove_empty_dirs(root: str, dry_run: bool) -> int:
    if not os.path.isdir(root):
        return 0
    removed = 0
    for cur, dirs, files in os.walk(root, topdown=False):
        if files:
            continue
        if dirs:
            continue
        if os.path.abspath(cur) == os.path.abspath(root):
            continue
        if not _is_inside_repo(cur):
            continue
        if dry_run:
            removed += 1
            continue
        try:
            os.rmdir(cur)
            removed += 1
        except OSError:
            pass
    return removed


def _stop_for_delete(session_id: str, timeout_sec: float = 2.0, force: bool = True) -> Dict[str, Any]:
    info: Dict[str, Any] = {"pid": 0, "stopped": False, "was_running": False, "signal": ""}
    pid = find_session_pid(session_id)
    info["pid"] = pid
    if pid <= 0:
        return info
    if not process_exists(pid):
        return info

    info["was_running"] = True
    try:
        os.kill(pid, signal.SIGTERM)
        info["signal"] = "SIGTERM"
    except Exception as e:
        info["error"] = f"SIGTERM failed: {e}"
        return info

    deadline = time.time() + max(1.0, float(timeout_sec))
    while time.time() < deadline:
        if not process_exists(pid):
            info["stopped"] = True
            return info
        time.sleep(0.1)

    if force and process_exists(pid):
        try:
            os.kill(pid, signal.SIGKILL)
            info["signal"] = "SIGKILL"
            time.sleep(0.1)
            info["stopped"] = not process_exists(pid)
        except Exception as e:
            info["error"] = f"SIGKILL failed: {e}"
    return info


def cmd_delete(argv: List[str]) -> int:
    sp = argparse.ArgumentParser(prog="session_api.py delete", description="delete session data (supports deep cleanup)")
    sp.add_argument("session_id")
    sp.add_argument("--shallow", action="store_true", help="only delete sessions/challenge directories")
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--stop-timeout-sec", type=float, default=2.0)
    args = sp.parse_args(argv)

    sid = str(args.session_id).strip()
    if not sid:
        print(json.dumps({"ok": False, "error": "empty session_id"}, ensure_ascii=False, indent=2))
        return 2

    deep = not bool(args.shallow)
    removed: List[str] = []
    errors: List[str] = []

    stop_info = _stop_for_delete(sid, timeout_sec=float(args.stop_timeout_sec), force=True)

    targets = [
        os.path.join(ROOT_DIR, "sessions", sid),
        os.path.join(ROOT_DIR, "challenge", sid),
        os.path.join(ROOT_DIR, "sessions_trash", sid),
    ]
    if deep:
        targets.extend(_collect_artifact_targets(sid))
    targets = sorted({os.path.abspath(x) for x in targets}, key=lambda p: len(p), reverse=True)

    for p in targets:
        try:
            _remove_path(p, dry_run=bool(args.dry_run), removed=removed)
        except Exception as e:
            errors.append(f"{os.path.relpath(p, ROOT_DIR)}: {e}")

    state_info: Dict[str, Any] = {"updated": False}
    kpi_info: Dict[str, Any] = {"updated": False, "removed_sessions": 0}
    empty_dirs_removed = 0
    if deep:
        state_info = _prune_state_file(sid, dry_run=bool(args.dry_run))
        kpi_info = _prune_kpi_file(sid, dry_run=bool(args.dry_run))
        empty_dirs_removed = _remove_empty_dirs(ARTIFACTS_DIR, dry_run=bool(args.dry_run))

    out = {
        "ok": len(errors) == 0,
        "session_id": sid,
        "deep": deep,
        "dry_run": bool(args.dry_run),
        "stop": stop_info,
        "removed_count": len(removed),
        "removed_paths": removed[:200],
        "state": state_info,
        "kpi": kpi_info,
        "empty_dirs_removed": empty_dirs_removed,
        "errors": errors,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if len(errors) == 0 else 1


def usage() -> str:
    return (
        "Usage:\n"
        "  scripts/session_api.py start <start_session args...>\n"
        "  scripts/session_api.py solve [run_session args...]\n"
        "  scripts/session_api.py list [list_sessions args...]\n"
        "  scripts/session_api.py get <session_id>\n"
        "  scripts/session_api.py inspect <session_id> [--tail N]\n"
        "  scripts/session_api.py overview [--limit N] [--tail N]\n"
        "  scripts/session_api.py timeline <session_id> [--limit N]\n"
        "  scripts/session_api.py artifacts <session_id>\n"
        "  scripts/session_api.py remote-prompt <session_id>\n"
        "  scripts/session_api.py remote-answer <session_id> (--yes --host H --port P [--run-verify] | --no)\n"
        "  scripts/session_api.py remote-preflight [remote_preflight args...]\n"
        "  scripts/session_api.py health [health_check_mcp args...]\n"
        "  scripts/session_api.py sync-meta [sync_state_meta args...]\n"
        "  scripts/session_api.py run <run_session args...>\n"
        "  scripts/session_api.py cleanup [cleanup_artifacts args...]\n"
        "  scripts/session_api.py repair-state [repair_state args...]\n"
        "  scripts/session_api.py reset <reset_state args...>\n"
        "  scripts/session_api.py delete <session_id> [--shallow] [--dry-run]\n"
        "  scripts/session_api.py stop <session_id> [--force] [--timeout-sec N]\n"
    )


def cmd_solve(rest: List[str]) -> int:
    cmd = [sys.executable, os.path.join(ROOT_DIR, "scripts", "run_session.py")]
    has_fast_switch = any(x in {"--fast", "--no-fast"} for x in rest)
    if not has_fast_switch:
        cmd.append("--fast")
    cmd.extend(rest)
    return run_cmd(cmd)


def main() -> int:
    if len(sys.argv) < 2:
        print(usage(), file=sys.stderr)
        return 2

    cmd = sys.argv[1]
    rest = sys.argv[2:]

    if cmd == "start":
        passthrough = any(x == "--interactive-codex" for x in rest)
        return run_cmd(
            ["bash", os.path.join(ROOT_DIR, "scripts", "start_session.sh"), *rest],
            passthrough_stdio=passthrough,
        )

    if cmd == "list":
        return run_cmd(["bash", os.path.join(ROOT_DIR, "scripts", "list_sessions.sh"), *rest])

    if cmd == "get":
        if len(rest) != 1:
            print("session_api.py get <session_id>", file=sys.stderr)
            return 2
        return run_cmd(["bash", os.path.join(ROOT_DIR, "scripts", "get_session.sh"), rest[0]])

    if cmd == "inspect":
        return cmd_inspect(rest)

    if cmd == "overview":
        return cmd_overview(rest)

    if cmd == "timeline":
        return cmd_timeline(rest)

    if cmd == "artifacts":
        return cmd_artifacts(rest)

    if cmd == "remote-prompt":
        return cmd_remote_prompt(rest)

    if cmd == "remote-answer":
        return cmd_remote_answer(rest)

    if cmd == "remote-preflight":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "remote_preflight.py"), *rest])

    if cmd == "run":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "run_session.py"), *rest])

    if cmd == "solve":
        return cmd_solve(rest)

    if cmd == "health":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "health_check_mcp.py"), *rest])

    if cmd == "sync-meta":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "sync_state_meta.py"), *rest])

    if cmd == "cleanup":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "cleanup_artifacts.py"), *rest])

    if cmd == "repair-state":
        return run_cmd([sys.executable, os.path.join(ROOT_DIR, "scripts", "repair_state.py"), *rest])

    if cmd == "reset":
        return run_cmd(["bash", os.path.join(ROOT_DIR, "scripts", "reset_state.sh"), *rest])

    if cmd == "delete":
        return cmd_delete(rest)

    if cmd == "stop":
        return cmd_stop(rest)

    print(usage(), file=sys.stderr)
    print(f"unknown cmd: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
