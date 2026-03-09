#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_rel(path: str) -> str:
    try:
        return os.path.relpath(os.path.abspath(path), ROOT_DIR)
    except Exception:
        return path


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


def _session_meta_path(session_id: str) -> str:
    return os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")


def _resolve_exp_path(session_id: str, meta: Dict[str, Any], exp_override: str) -> str:
    raw = str(exp_override or "").strip()
    if raw:
        return raw
    exp = meta.get("exp", {}) if isinstance(meta.get("exp", {}), dict) else {}
    raw = str(exp.get("path", "")).strip()
    if raw:
        return raw
    return f"sessions/{session_id}/exp/exp.py"


def _run_remote_preflight(session_id: str, host: str, port: int, timeout_sec: float) -> Tuple[Dict[str, Any], str]:
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_rel = f"artifacts/reports/remote_preflight_{session_id}_{ts}.json"
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "remote_preflight.py"),
        "--host",
        host,
        "--port",
        str(int(port)),
        "--timeout-sec",
        str(max(0.5, float(timeout_sec))),
        "--report",
        report_rel,
    ]
    p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)
    obj: Dict[str, Any] = {}
    if p.stdout.strip():
        try:
            tmp = json.loads(p.stdout)
            if isinstance(tmp, dict):
                obj = tmp
        except Exception:
            obj = {}
    if (not obj) and os.path.exists(os.path.join(ROOT_DIR, report_rel)):
        tmp = _load_json(os.path.join(ROOT_DIR, report_rel), {})
        if isinstance(tmp, dict):
            obj = tmp
    if "report" not in obj:
        obj["report"] = report_rel
    if (not obj.get("ok", False)) and (not obj.get("dns_error")) and p.stderr.strip():
        obj["dns_error"] = p.stderr.strip()[-240:]
    return obj, report_rel


def _parse_libc_profile_candidates(
    explicit_profile: str,
    raw_candidates: str,
    disable_sweep: bool,
) -> List[str]:
    exp = str(explicit_profile or "").strip()
    if exp:
        return [exp]
    if bool(disable_sweep):
        return ["auto"]
    out: List[str] = []
    seen = set()
    for item in str(raw_candidates or "").split(","):
        s = str(item or "").strip()
        if (not s) or (s in seen):
            continue
        seen.add(s)
        out.append(s)
    if not out:
        # 优先两到三个高置信 profile，避免 remote 盲扫。
        out = ["glibc_2_27", "glibc_2_23", "auto"]
    return out[:3]


def _merge_env_with_profile(base_env: List[str], libc_profile: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in base_env:
        s = str(item or "").strip()
        if (not s) or ("=" not in s):
            continue
        k = s.split("=", 1)[0].strip()
        if not k:
            continue
        if k in seen:
            continue
        seen.add(k)
        out.append(s)
    p = str(libc_profile or "").strip()
    if p:
        out = [x for x in out if x.split("=", 1)[0].strip() != "PWN_LIBC_PROFILE"]
        out.append(f"PWN_LIBC_PROFILE={p}")
    return out


def _get_env_value(env_items: List[str], key: str) -> str:
    target = str(key or "").strip()
    if not target:
        return ""
    for item in env_items:
        s = str(item or "").strip()
        if "=" not in s:
            continue
        k, v = s.split("=", 1)
        if str(k).strip() == target:
            return str(v).strip()
    return ""


def _format_addr_snapshot(snapshot: Any) -> str:
    if not isinstance(snapshot, dict):
        return ""
    parts: List[str] = []
    for key in ("exit", "prog", "libc", "envp", "ret"):
        val = str(snapshot.get(key, "")).strip()
        if val:
            parts.append(f"{key}={val}")
    return ",".join(parts)


def _build_failure_hec(
    *,
    stage1: Dict[str, Any],
    merged_tail: str,
    target_profile: str,
    error_text: str,
    snapshot_text: str,
) -> Dict[str, str]:
    s1_attempts = int(stage1.get("attempts", 0) or 0)
    s1_success = int(stage1.get("success_proxy_attempts", 0) or 0)
    s1_eof = int(stage1.get("eof_attempts", 0) or 0)
    s1_invalid = int(stage1.get("invalid_option_count", 0) or 0)
    s1_wrong = int(stage1.get("wrong_choice_count", 0) or 0)
    s1_selfcheck_ok = stage1.get("single_byte_selfcheck_ok", None)
    eof_rate = (float(s1_eof) / float(s1_attempts)) if s1_attempts > 0 else 0.0
    merged = str(merged_tail or "").lower()

    hypothesis = "远程链路仍未命中正确利用原语，需收缩试探空间"
    conclusion = "保留当前 profile，增加可验证证据后再进入全链路"
    if ("/bin/bash" in merged) and ("not found" in merged):
        hypothesis = "远程 shell 路径与本地假设不一致（/bin/bash 不可用）"
        conclusion = "改用 /bin/sh 与无重定向最小命令进行验证"
    elif s1_selfcheck_ok is False:
        hypothesis = "stage1 字节自检失败，泄露窗口/缓冲区边界未对齐"
        conclusion = "强制执行 send->drain->clear_buf->leak，再回归"
    elif (s1_invalid + s1_wrong) > 0 and s1_success <= 0:
        hypothesis = "菜单/提示符边界漂移，导致命令落点错误"
        conclusion = "统一提示符判定为 [$,#] 并复核 sendlineafter 边界"
    elif s1_attempts > 0 and eof_rate >= 0.75:
        hypothesis = "当前 payload 路径触发远程快速断连（EOF-heavy）"
        conclusion = "停止盲扫，优先基于高置信 profile 与证据链重构 payload"

    evidence_parts = [
        f"profile={target_profile or 'auto'}",
        f"stage1={s1_success}/{s1_attempts}",
        f"eof={s1_eof}",
        f"invalid={s1_invalid}",
        f"wrong={s1_wrong}",
    ]
    if error_text:
        evidence_parts.append(f"error={error_text[:120]}")
    if snapshot_text:
        evidence_parts.append(f"snapshot={snapshot_text}")
    return {
        "hypothesis": hypothesis,
        "evidence": "; ".join(evidence_parts),
        "conclusion": conclusion,
    }


def _run_verify_once(
    *,
    state_path: str,
    session_id: str,
    exp_path: str,
    host: str,
    port: int,
    timeout_sec: float,
    verify_mode: str,
    python_bin: str,
    report_rel: str,
    extra_env: List[str],
) -> Dict[str, Any]:
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "verify_local_exp.py"),
        "--state",
        state_path,
        "--session-id",
        session_id,
        "--exp",
        exp_path,
        "--run",
        "--run-strict",
        "--run-timeout-sec",
        str(max(1.0, float(timeout_sec))),
        "--verify-mode",
        verify_mode,
        "--quick-then-full",
        "--remote-host",
        host,
        "--remote-port",
        str(int(port)),
        "--report",
        report_rel,
        "--no-update-state",
    ]
    if python_bin.strip():
        cmd.extend(["--python", python_bin.strip()])
    for env_item in extra_env:
        s = str(env_item or "").strip()
        if s and "=" in s:
            cmd.extend(["--env", s])

    p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)
    out: Dict[str, Any] = {
        "ok": False,
        "report": report_rel,
        "error": "",
        "rc": int(p.returncode),
        "host": host,
        "port": int(port),
        "stdout_tail": (p.stdout or "")[-800:],
        "stderr_tail": (p.stderr or "")[-800:],
    }
    if p.stdout.strip():
        try:
            raw = json.loads(p.stdout)
            if isinstance(raw, dict):
                out["ok"] = bool(raw.get("ok", False))
                out["report"] = str(raw.get("report", report_rel)).strip() or report_rel
        except Exception:
            pass
    if (not out["ok"]) and (not out["error"]):
        out["error"] = (p.stderr or "").strip()[-240:] or f"verify failed (rc={int(p.returncode)})"
    rep_rel = str(out.get("report", report_rel)).strip() or report_rel
    rep_abs = rep_rel if os.path.isabs(rep_rel) else os.path.join(ROOT_DIR, rep_rel)
    rep_doc = _load_json(rep_abs, {})
    if isinstance(rep_doc, dict):
        run_doc = rep_doc.get("run", {}) if isinstance(rep_doc.get("run", {}), dict) else {}
        stage_ev = run_doc.get("stage_evidence", {}) if isinstance(run_doc.get("stage_evidence", {}), dict) else {}
        if stage_ev:
            out["stage1_metrics"] = {
                "attempts": int(stage_ev.get("stage1_attempts", 0) or 0),
                "eof_attempts": int(stage_ev.get("stage1_eof_attempts", 0) or 0),
                "success_proxy_attempts": int(stage_ev.get("stage1_success_proxy_attempts", 0) or 0),
                "success_proxy_rate": stage_ev.get("stage1_success_proxy_rate", None),
                "post_recv_raw_len_max": int(stage_ev.get("stage1_post_recv_raw_len_max", 0) or 0),
                "invalid_option_count": int(stage_ev.get("invalid_option_count", 0) or 0),
                "wrong_choice_count": int(stage_ev.get("wrong_choice_count", 0) or 0),
                "menu_prompt_hits": int(stage_ev.get("menu_prompt_hits", 0) or 0),
                "last_stage": str(stage_ev.get("last_stage", "")).strip(),
                "leak_values_hex_tail": (
                    stage_ev.get("leak_values_hex_tail", [])
                    if isinstance(stage_ev.get("leak_values_hex_tail", []), list)
                    else []
                ),
                "single_byte_selfcheck_ok": stage_ev.get("single_byte_selfcheck_ok", None),
                "failure_addr_snapshot_tail": (
                    stage_ev.get("failure_addr_snapshot_tail", {})
                    if isinstance(stage_ev.get("failure_addr_snapshot_tail", {}), dict)
                    else {}
                ),
            }
        else:
            out["stage1_metrics"] = {
                "attempts": 0,
                "eof_attempts": 0,
                "success_proxy_attempts": 0,
                "success_proxy_rate": None,
                "post_recv_raw_len_max": 0,
                "invalid_option_count": 0,
                "wrong_choice_count": 0,
                "menu_prompt_hits": 0,
                "last_stage": "",
                "leak_values_hex_tail": [],
                "single_byte_selfcheck_ok": None,
                "failure_addr_snapshot_tail": {},
            }
    else:
        out["stage1_metrics"] = {
                "attempts": 0,
                "eof_attempts": 0,
                "success_proxy_attempts": 0,
                "success_proxy_rate": None,
                "post_recv_raw_len_max": 0,
                "invalid_option_count": 0,
                "wrong_choice_count": 0,
                "menu_prompt_hits": 0,
                "last_stage": "",
                "leak_values_hex_tail": [],
                "single_byte_selfcheck_ok": None,
                "failure_addr_snapshot_tail": {},
            }
    return out


def _sync_meta(session_id: str) -> None:
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "sync_state_meta.py"),
        "--state",
        DEFAULT_STATE,
        "--session-id",
        session_id,
    ]
    subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False)


def _update_state_and_meta(
    *,
    state_path: str,
    session_id: str,
    host: str,
    port: int,
    preflight_report_rel: str,
    remote_report_rel: str,
    remote_ok: bool,
    remote_error: str,
) -> Dict[str, Any]:
    state = _load_json(state_path, {})
    if not isinstance(state, dict):
        state = {}
    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    current_sid = str(sess.get("session_id", "")).strip()
    same_sid = current_sid == session_id

    if same_sid:
        remote = sess.setdefault("remote", {})
        remote["ask_pending"] = False
        remote["answer"] = "yes"
        remote["answered_utc"] = utc_now()
        remote["target"] = {"host": host, "port": int(port)}
        remote["last_preflight_report"] = preflight_report_rel
        remote["last_remote_report"] = remote_report_rel
        remote["last_remote_ok"] = bool(remote_ok)
        if remote_ok:
            remote["last_remote_ok_utc"] = utc_now()
            remote["remote_verified_utc"] = remote.get("last_remote_ok_utc")
        if remote_error:
            sess["last_error"] = remote_error
        state["session"] = sess
        latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
        latest["remote_preflight_report"] = preflight_report_rel
        latest["remote_exp_verify_report"] = remote_report_rel
        latest["remote_run_report"] = remote_report_rel
        if remote_ok:
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
        _save_json(state_path, state)
        _sync_meta(session_id)

    meta_path = _session_meta_path(session_id)
    meta = _load_json(meta_path, {})
    if isinstance(meta, dict) and meta:
        remote_meta = meta.get("remote", {}) if isinstance(meta.get("remote", {}), dict) else {}
        remote_meta["ask_pending"] = False
        remote_meta["answer"] = "yes"
        remote_meta["answered_utc"] = utc_now()
        remote_meta["target"] = {"host": host, "port": int(port)}
        remote_meta["last_preflight_report"] = preflight_report_rel
        remote_meta["last_remote_report"] = remote_report_rel
        remote_meta["last_remote_ok"] = bool(remote_ok)
        if remote_ok:
            remote_meta["last_remote_ok_utc"] = utc_now()
            remote_meta["remote_verified_utc"] = remote_meta.get("last_remote_ok_utc")
        meta["remote"] = remote_meta
        latest_art = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
        latest_art["remote_preflight_report"] = preflight_report_rel
        latest_art["remote_exp_verify_report"] = remote_report_rel
        latest_art["remote_run_report"] = remote_report_rel
        meta["latest_artifacts"] = latest_art
        if remote_ok:
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
        _save_json(meta_path, meta)

    return {"same_session_in_state": same_sid, "current_session_id": current_sid}


def main() -> int:
    ap = argparse.ArgumentParser(description="统一远程 exp 执行入口（强制 host/port）")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--session-id", required=True)
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--exp-path", default="", help="默认使用 sessions/<sid>/exp/exp.py")
    ap.add_argument("--verify-mode", choices=["quick", "full", "auto"], default="auto")
    ap.add_argument("--timeout-sec", type=float, default=6.0)
    ap.add_argument("--preflight-timeout-sec", type=float, default=2.5)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--retry-delay-sec", type=float, default=0.25)
    ap.add_argument("--retry-backoff", type=float, default=1.5)
    ap.add_argument("--retry-jitter-sec", type=float, default=0.12)
    ap.add_argument("--retry-max-delay-sec", type=float, default=1.8)
    ap.add_argument("--python", default="", help="verify_local_exp.py 运行 exp 时使用的 python")
    ap.add_argument("--env", action="append", default=[], help="透传给 verify_local_exp.py 的 PWN_* 环境变量")
    ap.add_argument("--libc-profile", default="", help="快捷设置 PWN_LIBC_PROFILE")
    ap.add_argument(
        "--libc-profile-candidates",
        default="glibc_2_27,glibc_2_23,auto",
        help="当未显式指定 --libc-profile 时，按候选列表轮询 PWN_LIBC_PROFILE",
    )
    ap.add_argument("--disable-libc-profile-sweep", action="store_true")
    ap.add_argument("--puts-off", default="", help="快捷设置 PWN_PUTS_OFF")
    ap.add_argument("--read-off", default="", help="快捷设置 PWN_READ_OFF")
    ap.add_argument("--system-off", default="", help="快捷设置 PWN_SYSTEM_OFF")
    ap.add_argument("--binsh-off", default="", help="快捷设置 PWN_BINSH_OFF")
    ap.add_argument("--stage1-baseline-tries", type=int, default=4)
    ap.add_argument("--stage1-min-success-rate", type=float, default=0.35)
    ap.add_argument("--stage1-min-successes", type=int, default=1)
    ap.add_argument("--disable-stage1-baseline-gate", action="store_true")
    ap.add_argument("--stage1-eof-heavy-threshold", type=float, default=0.75)
    ap.add_argument("--stage1-eof-heavy-stop-streak", type=int, default=3)
    ap.add_argument("--menu-sync-min-hits", type=int, default=1)
    ap.add_argument("--menu-sync-stop-streak", type=int, default=2)
    ap.add_argument("--allow-silent-service", action="store_true", help="preflight 服务无菜单输出时仍继续尝试")
    ap.add_argument("--report", default="", help="结果摘要报告路径")
    args = ap.parse_args()

    sid = str(args.session_id or "").strip()
    host = str(args.host or "").strip()
    port = int(args.port or 0)
    if not sid or (not host) or port <= 0:
        print(json.dumps({"ok": False, "error": "invalid session-id/host/port"}, ensure_ascii=False, indent=2))
        return 2

    meta_path = _session_meta_path(sid)
    meta = _load_json(meta_path, {})
    if not isinstance(meta, dict) or (not meta):
        print(json.dumps({"ok": False, "error": f"session meta not found: {_repo_rel(meta_path)}"}, ensure_ascii=False, indent=2))
        return 2

    exp_rel = _resolve_exp_path(sid, meta, args.exp_path)
    exp_abs = exp_rel if os.path.isabs(exp_rel) else os.path.join(ROOT_DIR, exp_rel)
    if not os.path.isfile(exp_abs):
        print(json.dumps({"ok": False, "error": f"exp file not found: {exp_rel}"}, ensure_ascii=False, indent=2))
        return 2

    preflight, preflight_report_rel = _run_remote_preflight(
        sid,
        host=host,
        port=port,
        timeout_sec=float(args.preflight_timeout_sec),
    )
    preflight_report_rel = str(preflight.get("report", preflight_report_rel)).strip() or preflight_report_rel
    blocked = bool(preflight.get("network_blocked", False))
    dns_fail_only = bool(preflight.get("dns_fail_only", False))
    service_silent = bool(preflight.get("service_silent", False))
    service_live = bool(preflight.get("service_live", False))
    prompt_dual_hint_seen = bool(preflight.get("prompt_dual_hint_seen", False))
    if service_silent and prompt_dual_hint_seen:
        service_silent = False
    block_reason = str(preflight.get("block_reason", "")).strip()

    candidates_raw = preflight.get("candidates", []) if isinstance(preflight.get("candidates", []), list) else []
    candidates = [host] + [str(x).strip() for x in candidates_raw if str(x).strip()]
    dedup: List[str] = []
    for c in candidates:
        if c and (c not in dedup):
            dedup.append(c)
    candidates = dedup[:4] if dedup else [host]

    attempts: List[Dict[str, Any]] = []
    final_ok = False
    final_report_rel = ""
    final_error = ""
    baseline_samples: List[Dict[str, Any]] = []
    baseline_stage1_attempts = 0
    baseline_stage1_success = 0
    baseline_stage1_eof = 0
    baseline_invalid_option = 0
    baseline_wrong_choice = 0
    baseline_gate_triggered = False
    baseline_gate_reason = ""
    profile_candidates = _parse_libc_profile_candidates(
        explicit_profile=str(args.libc_profile or "").strip(),
        raw_candidates=str(args.libc_profile_candidates or ""),
        disable_sweep=bool(args.disable_libc_profile_sweep),
    )
    profile_used: List[str] = []
    base_env: List[str] = [str(x).strip() for x in (args.env or []) if str(x).strip()]
    if str(args.puts_off or "").strip():
        base_env.append(f"PWN_PUTS_OFF={str(args.puts_off).strip()}")
    if str(args.read_off or "").strip():
        base_env.append(f"PWN_READ_OFF={str(args.read_off).strip()}")
    if str(args.system_off or "").strip():
        base_env.append(f"PWN_SYSTEM_OFF={str(args.system_off).strip()}")
    if str(args.binsh_off or "").strip():
        base_env.append(f"PWN_BINSH_OFF={str(args.binsh_off).strip()}")
    if not _get_env_value(base_env, "PWN_FLAG_SCAN_LONG"):
        base_env.append("PWN_FLAG_SCAN_LONG=0")
    if not _get_env_value(base_env, "PWN_MENU_NOISE_FILTER"):
        base_env.append("PWN_MENU_NOISE_FILTER=1")
    if not _get_env_value(base_env, "PWN_REMOTE_PREFLIGHT"):
        base_env.append("PWN_REMOTE_PREFLIGHT=1")
    if not _get_env_value(base_env, "PWN_REMOTE_MENU_SYNC"):
        base_env.append("PWN_REMOTE_MENU_SYNC=1")
    if not _get_env_value(base_env, "PWN_STRICT_MENU_SYNC_FAILFAST"):
        base_env.append("PWN_STRICT_MENU_SYNC_FAILFAST=1")
    if not _get_env_value(base_env, "PWN_EXPECT_HINTS"):
        base_env.append("PWN_EXPECT_HINTS=$,#")
    if not _get_env_value(base_env, "PWN_STAGE1_DRAIN_RECV_SEC"):
        base_env.append("PWN_STAGE1_DRAIN_RECV_SEC=0.08")
    if not _get_env_value(base_env, "PWN_STAGE1_CLEAR_BUF_RECV_SEC"):
        base_env.append("PWN_STAGE1_CLEAR_BUF_RECV_SEC=0.06")
    if not _get_env_value(base_env, "PWN_STAGE1_CLEAR_BUF_ROUNDS"):
        base_env.append("PWN_STAGE1_CLEAR_BUF_ROUNDS=2")
    if not _get_env_value(base_env, "PWN_STAGE1_SELFCHECK_STRICT"):
        base_env.append("PWN_STAGE1_SELFCHECK_STRICT=1")
    if not _get_env_value(base_env, "PWN_PAYLOAD_ASSERT_LEN"):
        base_env.append("PWN_PAYLOAD_ASSERT_LEN=1")
    if not _get_env_value(base_env, "PWN_LEAK_SKIP_ASCII_WINDOWS"):
        base_env.append("PWN_LEAK_SKIP_ASCII_WINDOWS=1")
    if not _get_env_value(base_env, "PWN_EXEC_SCOPE"):
        base_env.append("PWN_EXEC_SCOPE=remote")
    preflight_attempts = preflight.get("attempts", []) if isinstance(preflight.get("attempts", []), list) else []
    suggested_env: Dict[str, str] = {}
    segmented_prompt_seen = False
    for rec in preflight_attempts:
        if not isinstance(rec, dict):
            continue
        probe = rec.get("service_probe", {}) if isinstance(rec.get("service_probe", {}), dict) else {}
        if bool(probe.get("segmented_prompt", False)):
            segmented_prompt_seen = True
        env_doc = probe.get("suggested_env", {}) if isinstance(probe.get("suggested_env", {}), dict) else {}
        for k, v in env_doc.items():
            key = str(k or "").strip()
            val = str(v or "").strip()
            if (not key.startswith("PWN_")) or (not val):
                continue
            suggested_env.setdefault(key, val)
    for k, v in suggested_env.items():
        if not _get_env_value(base_env, k):
            base_env.append(f"{k}={v}")
    if segmented_prompt_seen and (not _get_env_value(base_env, "PWN_REMOTE_MENU_SYNC")):
        base_env.append("PWN_REMOTE_MENU_SYNC=1")
    adaptive_delay_mult = 1.0
    adaptive_jitter_bonus = 0.0
    eof_heavy_streak = 0
    menu_drift_streak = 0
    shell_path_mismatch_detected = False
    stack_smash_detected = False
    eof_heavy_threshold = max(0.1, min(1.0, float(args.stage1_eof_heavy_threshold)))
    eof_heavy_stop_streak = max(1, int(args.stage1_eof_heavy_stop_streak or 1))
    menu_sync_min_hits = max(0, int(args.menu_sync_min_hits or 0))
    menu_sync_stop_streak = max(1, int(args.menu_sync_stop_streak or 1))
    menu_sync_miss_streak = 0

    if blocked:
        final_error = f"remote blocked by environment: {block_reason or 'network operation not permitted'}"
    elif dns_fail_only and (not bool(preflight.get("ok", False))):
        final_error = block_reason or "remote dns resolution failed"
    elif service_silent and (not bool(args.allow_silent_service)):
        final_error = (
            "remote reachable but service output is silent (no menu/banner bytes observed); "
            "check host/port or pass --allow-silent-service to continue"
        )
    else:
        max_attempts = max(1, int(args.retries or 1))
        for i in range(max_attempts):
            target_host = candidates[i % len(candidates)]
            target_profile = profile_candidates[i % len(profile_candidates)]
            attempt_env = _merge_env_with_profile(base_env, target_profile)
            ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            report_rel = f"artifacts/reports/exp_remote_verify_{sid}_{ts}_{i + 1:02d}.json"
            one = _run_verify_once(
                state_path=args.state,
                session_id=sid,
                exp_path=_repo_rel(exp_abs),
                host=target_host,
                port=port,
                timeout_sec=float(args.timeout_sec),
                verify_mode=str(args.verify_mode).strip(),
                python_bin=str(args.python or "").strip(),
                report_rel=report_rel,
                extra_env=attempt_env,
            )
            one["libc_profile"] = target_profile
            if target_profile and (target_profile not in profile_used):
                profile_used.append(target_profile)
            attempts.append(one)
            stage1 = one.get("stage1_metrics", {}) if isinstance(one.get("stage1_metrics", {}), dict) else {}
            s1_attempts = int(stage1.get("attempts", 0) or 0)
            s1_success = int(stage1.get("success_proxy_attempts", 0) or 0)
            s1_eof = int(stage1.get("eof_attempts", 0) or 0)
            s1_invalid = int(stage1.get("invalid_option_count", 0) or 0)
            s1_wrong = int(stage1.get("wrong_choice_count", 0) or 0)
            s1_menu_hits = int(stage1.get("menu_prompt_hits", 0) or 0)
            s1_post_raw = int(stage1.get("post_recv_raw_len_max", 0) or 0)
            s1_selfcheck_ok = stage1.get("single_byte_selfcheck_ok", None)
            s1_snapshot = (
                stage1.get("failure_addr_snapshot_tail", {})
                if isinstance(stage1.get("failure_addr_snapshot_tail", {}), dict)
                else {}
            )
            s1_snapshot_text = _format_addr_snapshot(s1_snapshot)
            s1_eof_rate = (float(s1_eof) / float(s1_attempts)) if s1_attempts > 0 else 0.0
            baseline_stage1_attempts += max(0, s1_attempts)
            baseline_stage1_success += max(0, min(s1_success, s1_attempts))
            baseline_stage1_eof += max(0, min(s1_eof, s1_attempts))
            baseline_invalid_option += max(0, s1_invalid)
            baseline_wrong_choice += max(0, s1_wrong)
            baseline_samples.append(
                {
                    "attempt": int(i + 1),
                    "host": target_host,
                    "libc_profile": target_profile,
                    "report": str(one.get("report", report_rel)).strip() or report_rel,
                    "stage1_attempts": s1_attempts,
                    "stage1_success_proxy_attempts": s1_success,
                    "stage1_eof_attempts": s1_eof,
                    "stage1_success_proxy_rate": stage1.get("success_proxy_rate", None),
                    "stage1_post_recv_raw_len_max": int(stage1.get("post_recv_raw_len_max", 0) or 0),
                    "invalid_option_count": s1_invalid,
                    "wrong_choice_count": s1_wrong,
                    "menu_prompt_hits": s1_menu_hits,
                    "last_stage": str(stage1.get("last_stage", "")).strip(),
                    "leak_values_hex_tail": (
                        stage1.get("leak_values_hex_tail", [])
                        if isinstance(stage1.get("leak_values_hex_tail", []), list)
                        else []
                    ),
                    "single_byte_selfcheck_ok": s1_selfcheck_ok,
                    "failure_addr_snapshot_tail": s1_snapshot,
                }
            )
            final_report_rel = str(one.get("report", report_rel)).strip() or report_rel
            if bool(one.get("ok", False)):
                final_ok = True
                final_error = ""
                break
            final_error = str(one.get("error", "")).strip()
            if s1_snapshot_text:
                final_error = (
                    f"{final_error}; addr_snapshot[{s1_snapshot_text}]"
                    if final_error
                    else f"addr_snapshot[{s1_snapshot_text}]"
                )
            stdout_tail = str(one.get("stdout_tail", "")).strip()
            stderr_tail = str(one.get("stderr_tail", "")).strip()
            merged_tail = f"{stdout_tail}\n{stderr_tail}".lower()
            hec_note = _build_failure_hec(
                stage1=stage1,
                merged_tail=merged_tail,
                target_profile=target_profile,
                error_text=final_error,
                snapshot_text=s1_snapshot_text,
            )
            one["hec"] = hec_note
            if baseline_samples:
                baseline_samples[-1]["hec"] = hec_note
            if ("/bin/bash" in merged_tail) and ("not found" in merged_tail):
                shell_path_mismatch_detected = True
                baseline_gate_triggered = True
                baseline_gate_reason = (
                    "remote shell path mismatch detected (/bin/bash not found); "
                    "switch exploit command path to /bin/sh or ret2libc('/bin/sh')"
                )
                final_error = baseline_gate_reason
                break
            if "*** stack smashing detected ***" in merged_tail or "stack smashing detected" in merged_tail:
                stack_smash_detected = True
                adaptive_delay_mult = min(4.0, max(adaptive_delay_mult, 1.6))
                adaptive_jitter_bonus = max(adaptive_jitter_bonus, 0.2)
            is_eof_heavy = bool(s1_attempts > 0 and s1_eof_rate >= eof_heavy_threshold)
            if is_eof_heavy:
                eof_heavy_streak += 1
                adaptive_delay_mult = min(4.0, max(adaptive_delay_mult, 1.45 + 0.35 * float(eof_heavy_streak)))
                adaptive_jitter_bonus = max(adaptive_jitter_bonus, 0.18)
            else:
                eof_heavy_streak = 0
            is_menu_drift = bool((s1_invalid + s1_wrong) > 0 and s1_success <= 0)
            if is_menu_drift:
                menu_drift_streak += 1
                adaptive_delay_mult = min(4.0, max(adaptive_delay_mult, 1.35))
                adaptive_jitter_bonus = max(adaptive_jitter_bonus, 0.14)
            else:
                menu_drift_streak = 0
            menu_sync_ok = bool(s1_menu_hits >= menu_sync_min_hits or s1_post_raw > 0)
            if (s1_attempts > 0) and (not menu_sync_ok):
                menu_sync_miss_streak += 1
            else:
                menu_sync_miss_streak = 0
            gate_enabled = not bool(args.disable_stage1_baseline_gate)
            gate_min_tries = max(1, int(args.stage1_baseline_tries or 1))
            gate_min_success = max(0, int(args.stage1_min_successes or 0))
            gate_min_rate = max(0.0, min(1.0, float(args.stage1_min_success_rate)))
            if gate_enabled and s1_attempts > 0 and (s1_selfcheck_ok is False):
                baseline_gate_triggered = True
                baseline_gate_reason = (
                    "stage1 single-byte selfcheck failed; enforce send->drain->clear_buf->leak first "
                    f"(profile={target_profile}, stage1_attempts={s1_attempts})"
                )
                final_error = baseline_gate_reason
                if s1_snapshot_text:
                    final_error = final_error + f"; addr_snapshot[{s1_snapshot_text}]"
                break
            if (
                gate_enabled
                and baseline_stage1_attempts >= gate_min_tries
                and baseline_stage1_attempts > 0
            ):
                cur_rate = float(baseline_stage1_success) / float(baseline_stage1_attempts)
                if (baseline_stage1_success < gate_min_success) or (cur_rate < gate_min_rate):
                    baseline_gate_triggered = True
                    baseline_gate_reason = (
                        "stage1 baseline too low; pause full-chain retries and request hint "
                        f"(success_proxy_rate={cur_rate:.2f}, success={baseline_stage1_success}/{baseline_stage1_attempts}, "
                        f"eof={baseline_stage1_eof}, invalid_option={baseline_invalid_option}, wrong_choice={baseline_wrong_choice})"
                    )
                    final_error = baseline_gate_reason
                    break
                if (baseline_invalid_option + baseline_wrong_choice) >= 2 and cur_rate < max(0.5, gate_min_rate):
                    baseline_gate_triggered = True
                    baseline_gate_reason = (
                        "menu sync drift suspected; pause retries and fix recvuntil/sendlineafter boundaries "
                        f"(invalid_option={baseline_invalid_option}, wrong_choice={baseline_wrong_choice}, "
                        f"success_proxy_rate={cur_rate:.2f})"
                    )
                    final_error = baseline_gate_reason
                    break
            if gate_enabled and eof_heavy_streak >= eof_heavy_stop_streak:
                baseline_gate_triggered = True
                baseline_gate_reason = (
                    "stage1 remained EOF-heavy; pause retries and tune remote pacing/profile first "
                    f"(threshold={eof_heavy_threshold:.2f}, streak={eof_heavy_streak}, profile={target_profile})"
                )
                final_error = baseline_gate_reason
                break
            if gate_enabled and (menu_sync_miss_streak >= menu_sync_stop_streak):
                baseline_gate_triggered = True
                baseline_gate_reason = (
                    "menu sync baseline not met; pause retries and fix service/menu synchronization first "
                    f"(required_hits>={menu_sync_min_hits}, streak={menu_sync_miss_streak}, "
                    f"menu_hits={s1_menu_hits}, post_recv_raw_len_max={s1_post_raw})"
                )
                final_error = baseline_gate_reason
                break
            if i < (max_attempts - 1):
                delay_base = max(0.0, float(args.retry_delay_sec))
                delay_backoff = max(1.0, float(args.retry_backoff))
                delay_jitter = max(0.0, float(args.retry_jitter_sec)) + adaptive_jitter_bonus
                delay_cap = max(delay_base, float(args.retry_max_delay_sec)) * max(1.0, adaptive_delay_mult)
                delay_sec = delay_base * (delay_backoff ** i) * adaptive_delay_mult
                if delay_sec > delay_cap:
                    delay_sec = delay_cap
                if delay_jitter > 0:
                    delay_sec += random.uniform(0.0, delay_jitter)
                if delay_sec > 0:
                    time.sleep(delay_sec)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.report:
        summary_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        summary_abs = os.path.join(ROOT_DIR, "artifacts", "reports", f"remote_exploit_{sid}_{ts}.json")
    summary_rel = _repo_rel(summary_abs)
    if not final_report_rel:
        final_report_rel = summary_rel

    if (not final_ok) and final_error:
        low_final = str(final_error).lower()
        net_sig = (
            "connection refused",
            "name or service not known",
            "temporary failure in name resolution",
            "timed out",
            "service output is silent",
            "no menu/banner",
        )
        if any(x in low_final for x in net_sig) and ("update target" not in low_final):
            final_error = str(final_error).rstrip() + "; check remote host/port and update target if service changed"

    summary = {
        "generated_utc": utc_now(),
        "session_id": sid,
        "target": {"host": host, "port": int(port)},
        "ok": bool(final_ok),
        "error": final_error,
        "exp_path": _repo_rel(exp_abs),
        "preflight_report": preflight_report_rel,
        "preflight": preflight,
        "preflight_service": {
            "service_live": bool(service_live),
            "service_silent": bool(service_silent),
            "prompt_dual_hint_seen": bool(prompt_dual_hint_seen),
            "allow_silent_service": bool(args.allow_silent_service),
        },
        "retry_strategy": {
            "retries": max(1, int(args.retries or 1)),
            "delay_sec": max(0.0, float(args.retry_delay_sec)),
            "backoff": max(1.0, float(args.retry_backoff)),
            "jitter_sec": max(0.0, float(args.retry_jitter_sec)),
            "max_delay_sec": max(max(0.0, float(args.retry_delay_sec)), float(args.retry_max_delay_sec)),
            "adaptive_delay_mult_final": round(float(adaptive_delay_mult), 3),
            "adaptive_jitter_bonus_final": round(float(adaptive_jitter_bonus), 3),
            "eof_heavy_streak_final": int(eof_heavy_streak),
            "menu_drift_streak_final": int(menu_drift_streak),
            "menu_sync_miss_streak_final": int(menu_sync_miss_streak),
        },
        "offset_params": {
            "libc_profile": str(args.libc_profile or "").strip(),
            "libc_profile_candidates": profile_candidates,
            "puts_off": str(args.puts_off or "").strip(),
            "read_off": str(args.read_off or "").strip(),
            "system_off": str(args.system_off or "").strip(),
            "binsh_off": str(args.binsh_off or "").strip(),
        },
        "profile_sweep": {
            "enabled": (not bool(args.disable_libc_profile_sweep)),
            "requested": profile_candidates,
            "used": profile_used,
        },
        "env_defaults_applied": {
            "PWN_FLAG_SCAN_LONG": _get_env_value(base_env, "PWN_FLAG_SCAN_LONG"),
            "PWN_MENU_NOISE_FILTER": _get_env_value(base_env, "PWN_MENU_NOISE_FILTER"),
            "PWN_REMOTE_PREFLIGHT": _get_env_value(base_env, "PWN_REMOTE_PREFLIGHT"),
            "PWN_REMOTE_MENU_SYNC": _get_env_value(base_env, "PWN_REMOTE_MENU_SYNC"),
            "PWN_EXPECT_HINTS": _get_env_value(base_env, "PWN_EXPECT_HINTS"),
            "PWN_STAGE1_DRAIN_RECV_SEC": _get_env_value(base_env, "PWN_STAGE1_DRAIN_RECV_SEC"),
            "PWN_STAGE1_CLEAR_BUF_RECV_SEC": _get_env_value(base_env, "PWN_STAGE1_CLEAR_BUF_RECV_SEC"),
            "PWN_STAGE1_CLEAR_BUF_ROUNDS": _get_env_value(base_env, "PWN_STAGE1_CLEAR_BUF_ROUNDS"),
            "PWN_STAGE1_SELFCHECK_STRICT": _get_env_value(base_env, "PWN_STAGE1_SELFCHECK_STRICT"),
            "PWN_LEAK_SKIP_ASCII_WINDOWS": _get_env_value(base_env, "PWN_LEAK_SKIP_ASCII_WINDOWS"),
            "PWN_EXEC_SCOPE": _get_env_value(base_env, "PWN_EXEC_SCOPE"),
        },
        "runtime_signals": {
            "shell_path_mismatch_detected": bool(shell_path_mismatch_detected),
            "stack_smash_detected": bool(stack_smash_detected),
        },
        "failure_hec_tail": [
            x.get("hec", {})
            for x in attempts
            if isinstance(x, dict) and isinstance(x.get("hec", {}), dict)
        ][-10:],
        "attempts": attempts,
        "stage1_baseline": {
            "enabled": (not bool(args.disable_stage1_baseline_gate)),
            "gate_triggered": bool(baseline_gate_triggered),
            "gate_reason": baseline_gate_reason,
            "tries_threshold": max(1, int(args.stage1_baseline_tries or 1)),
            "min_success_rate": max(0.0, min(1.0, float(args.stage1_min_success_rate))),
            "min_successes": max(0, int(args.stage1_min_successes or 0)),
            "eof_heavy_threshold": float(eof_heavy_threshold),
            "eof_heavy_stop_streak": int(eof_heavy_stop_streak),
            "menu_sync_min_hits": int(menu_sync_min_hits),
            "menu_sync_stop_streak": int(menu_sync_stop_streak),
            "attempts_total": int(baseline_stage1_attempts),
            "success_proxy_total": int(baseline_stage1_success),
            "eof_total": int(baseline_stage1_eof),
            "invalid_option_total": int(baseline_invalid_option),
            "wrong_choice_total": int(baseline_wrong_choice),
            "success_proxy_rate": (
                round(float(baseline_stage1_success) / float(baseline_stage1_attempts), 4)
                if baseline_stage1_attempts > 0
                else None
            ),
            "samples": baseline_samples[-12:],
        },
        "final_report": final_report_rel,
        "verify_mode": str(args.verify_mode).strip(),
    }
    _save_json(summary_abs, summary)

    sync_info = _update_state_and_meta(
        state_path=args.state,
        session_id=sid,
        host=host,
        port=port,
        preflight_report_rel=preflight_report_rel,
        remote_report_rel=final_report_rel if final_report_rel else summary_rel,
        remote_ok=bool(final_ok),
        remote_error=final_error,
    )

    out = {
        "ok": bool(final_ok),
        "session_id": sid,
        "target": {"host": host, "port": int(port)},
        "summary_report": summary_rel,
        "preflight_report": preflight_report_rel,
        "remote_report": final_report_rel if final_report_rel else summary_rel,
        "error": final_error,
        "stage1_baseline_gate_triggered": bool(baseline_gate_triggered),
        "libc_profiles_used": profile_used,
        "shell_path_mismatch_detected": bool(shell_path_mismatch_detected),
        "stack_smash_detected": bool(stack_smash_detected),
        "service_silent": bool(service_silent),
        "sync": sync_info,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if final_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
