#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def repo_rel(path: str) -> str:
    return os.path.relpath(os.path.abspath(path), ROOT_DIR)


def _try_load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = yaml.safe_load(f) or {}
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _normalize_verify_env(raw: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        key = str(k).strip()
        if not key.startswith("PWN_"):
            continue
        val = str(v).strip()
        if not val:
            continue
        out[key] = val
    return out


def _load_policy_verify_env_defaults() -> Dict[str, str]:
    policy = _try_load_yaml(os.path.join(ROOT_DIR, "policy", "agent.yaml"))
    automation = policy.get("automation", {}) if isinstance(policy.get("automation", {}), dict) else {}
    verify = automation.get("exploit_verify", {}) if isinstance(automation.get("exploit_verify", {}), dict) else {}
    return _normalize_verify_env(verify.get("run_env_defaults", {}))


def _load_state_verify_env_defaults(state: Dict[str, Any]) -> Dict[str, str]:
    session = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = session.get("exp", {}) if isinstance(session.get("exp", {}), dict) else {}
    remote = session.get("remote", {}) if isinstance(session.get("remote", {}), dict) else {}
    out: Dict[str, str] = {}
    out.update(_normalize_verify_env(exp.get("verify_env_defaults", {})))
    out.update(_normalize_verify_env(remote.get("verify_env_defaults", {})))
    return out


def _parse_cli_env(env_items: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in env_items:
        s = str(item or "").strip()
        if not s or "=" not in s:
            continue
        k, v = s.split("=", 1)
        key = k.strip()
        val = v.strip()
        if (not key.startswith("PWN_")) or (not val):
            continue
        out[key] = val
    return out


def _session_default_exp_rel(session_id: str) -> str:
    sid = str(session_id or "").strip()
    if not sid or sid == "unknown":
        return ""
    return os.path.join("sessions", sid, "exp", "exp.py")


def _resolve_exp_path(state: Dict[str, Any], exp_arg: str, session_id: str = "") -> Tuple[str, str]:
    raw = exp_arg.strip() if exp_arg else ""
    if not raw:
        state_raw = str(state.get("session", {}).get("exp", {}).get("path", "")).strip()
        sid = str(session_id or "").strip()
        sess_rel = _session_default_exp_rel(sid)
        if state_raw:
            state_norm = state_raw.replace("\\", "/")
            sess_norm = sess_rel.replace("\\", "/") if sess_rel else ""
            if (not sess_norm) or state_norm == sess_norm or state_norm.startswith(f"sessions/{sid}/"):
                raw = state_raw
        if (not raw) and sess_rel:
            raw = sess_rel
        if (not raw):
            raw = state_raw
    if not raw:
        return "", ""
    abs_path = raw if os.path.isabs(raw) else os.path.join(ROOT_DIR, raw)
    return raw, os.path.abspath(abs_path)


def _inside_repo(path: str) -> bool:
    try:
        return os.path.commonpath([ROOT_DIR, path]) == ROOT_DIR
    except Exception:
        return False


def _py_compile_ok(path: str) -> Tuple[bool, int, str]:
    p = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        cwd=ROOT_DIR,
        text=True,
        capture_output=True,
        check=False,
    )
    stderr = (p.stderr or "").strip()
    if not stderr and p.stdout:
        stderr = p.stdout.strip()
    return (p.returncode == 0), int(p.returncode), stderr


def _resolve_python_bin(candidate: str) -> str:
    raw = str(candidate or "").strip()
    if not raw:
        return ""
    raw = os.path.expanduser(raw)
    if os.path.isabs(raw) or ("/" in raw):
        ap = os.path.abspath(raw)
        if os.path.isfile(ap) and os.access(ap, os.X_OK):
            return ap
        return ""
    return shutil.which(raw) or ""


def _python_has_pwntools(python_bin: str) -> bool:
    if not python_bin:
        return False
    try:
        p = subprocess.run(
            [python_bin, "-c", "import pwn"],  # noqa: S607
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            check=False,
            timeout=3.0,
        )
        return int(p.returncode) == 0
    except Exception:
        return False


def _choose_run_python(exp_uses_pwntools: bool, override_python: str = "") -> str:
    candidates = [
        override_python,
        os.environ.get("PWN_PYTHON_BIN", ""),
        sys.executable,
        "~/.venvs/pwn-env/bin/python3",
        "~/.venvs/pwn-env/bin/python",
        os.path.join(ROOT_DIR, ".venv", "bin", "python3"),
        os.path.join(ROOT_DIR, ".venv", "bin", "python"),
        "python3",
        "python",
    ]
    resolved: list[str] = []
    seen = set()
    for c in candidates:
        p = _resolve_python_bin(c)
        if not p or p in seen:
            continue
        seen.add(p)
        resolved.append(p)
    if not resolved:
        return ""
    if not exp_uses_pwntools:
        return resolved[0]
    for p in resolved:
        if _python_has_pwntools(p):
            return p
    return ""


def _run_exp(
    path: str,
    timeout_sec: float,
    python_bin: str,
    remote_host: str = "",
    remote_port: int = 0,
    extra_env_defaults: Dict[str, str] | None = None,
) -> Dict[str, Any]:
    env = os.environ.copy()
    env.setdefault("PWNLIB_NOTERM", "1")
    env.setdefault("TERM", "dumb")
    env.setdefault("PWN_VERIFY", "1")
    env.setdefault("PWN_LOG_LEVEL", "error")
    env.setdefault("PWN_EXEC_SCOPE", "local")
    if isinstance(extra_env_defaults, dict):
        for k, v in extra_env_defaults.items():
            key = str(k).strip()
            val = str(v).strip()
            if (not key.startswith("PWN_")) or (not val):
                continue
            env.setdefault(key, val)
    if remote_host.strip():
        env["PWN_REMOTE_HOST"] = remote_host.strip()
        env["PWN_EXEC_SCOPE"] = "remote"
        env.setdefault("PWN_STRICT_MENU_SYNC", "1")
        env.setdefault("PWN_STRICT_MENU_SYNC_FAILFAST", "1")
        env.setdefault("PWN_MENU_SYNC_TIMEOUT_SEC", "0.55")
    if int(remote_port or 0) > 0:
        env["PWN_REMOTE_PORT"] = str(int(remote_port))
    cmd = [python_bin, path]
    def _decode_mixed(raw: Any) -> str:
        if raw is None:
            return ""
        if isinstance(raw, str):
            return raw
        if isinstance(raw, bytes):
            data = raw
        else:
            try:
                data = bytes(raw)
            except Exception:
                return str(raw)
        # binary-safe decode for exploit output; keep run alive on arbitrary bytes.
        try:
            txt = data.decode("utf-8", errors="ignore")
            if txt:
                return txt
        except Exception:
            pass
        try:
            return data.decode("latin-1", errors="ignore")
        except Exception:
            return ""

    try:
        p = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            text=False,
            capture_output=True,
            check=False,
            timeout=max(1.0, float(timeout_sec)),
            env=env,
        )
        stderr_tail = _decode_mixed(p.stderr)[-1500:]
        stdout_tail = _decode_mixed(p.stdout)[-1500:]
        if int(p.returncode) != 0 and (not stderr_tail.strip()) and (not stdout_tail.strip()):
            stderr_tail = f"process exited with rc={int(p.returncode)} (no output)"
        return {
            "attempted": True,
            "ok": p.returncode == 0,
            "timeout": False,
            "rc": int(p.returncode),
            "stderr_tail": stderr_tail,
            "stdout_tail": stdout_tail,
            "cmd": " ".join(cmd),
        }
    except subprocess.TimeoutExpired as e:
        return {
            "attempted": True,
            "ok": False,
            "timeout": True,
            "rc": 124,
            "stderr_tail": _decode_mixed(getattr(e, "stderr", b""))[-1500:] or str(e),
            "stdout_tail": _decode_mixed(getattr(e, "stdout", b""))[-1500:],
            "cmd": " ".join(cmd),
        }


def _split_markers(raw: str) -> List[str]:
    return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def _extract_auto_offset_hit(run_detail: Dict[str, Any]) -> Dict[str, int]:
    merged = f"{run_detail.get('stdout_tail','')}\n{run_detail.get('stderr_tail','')}"
    matches = re.findall(r"\[auto-offset\]\s+hit=(0x[0-9a-fA-F]+|\d+)\s+align=(0x[0-9a-fA-F]+|\d+)", merged)
    if not matches:
        return {}
    hit_raw, align_raw = matches[-1]
    try:
        hit = int(str(hit_raw), 0)
    except Exception:
        hit = 0
    try:
        align = int(str(align_raw), 0)
    except Exception:
        align = 0
    out: Dict[str, int] = {}
    if hit > 0:
        out["offset_to_rip"] = int(hit)
    out["align_ret"] = 1 if align else 0
    return out


def _sync_state_meta(session_id: str, state_path: str) -> Dict[str, Any]:
    sid = str(session_id or "").strip()
    if not sid or sid == "unknown":
        return {"attempted": False, "ok": False, "reason": "empty_session_id"}
    script = os.path.join(ROOT_DIR, "scripts", "sync_state_meta.py")
    if not os.path.exists(script):
        return {"attempted": False, "ok": False, "reason": "sync_script_missing"}
    try:
        p = subprocess.run(
            [sys.executable, script, "--state", os.path.abspath(state_path), "--session-id", sid],
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            check=False,
            timeout=4.0,
        )
    except Exception as exc:
        return {"attempted": True, "ok": False, "error": str(exc)}
    stdout = (p.stdout or "").strip()
    stderr = (p.stderr or "").strip()
    payload: Dict[str, Any] = {}
    if stdout:
        try:
            obj = json.loads(stdout)
            if isinstance(obj, dict):
                payload = obj
        except Exception:
            payload = {}
    if not payload:
        payload = {
            "attempted": True,
            "ok": int(p.returncode) == 0,
            "stdout_tail": stdout[-800:],
        }
    if stderr:
        payload["stderr_tail"] = stderr[-800:]
    payload["rc"] = int(p.returncode)
    payload.setdefault("attempted", True)
    payload.setdefault("ok", int(p.returncode) == 0)
    return payload


def _analyze_static_findings(source_text: str) -> List[str]:
    findings: List[str] = []
    src = str(source_text or "")
    low = src.lower()
    if (
        re.search(r"bin_loader\s*=\s*os\.environ\.get\(\s*['\"]pwn_loader['\"]\s*,\s*['\"][^'\"]*libc[^'\"]*['\"]\s*\)", low)
        and re.search(r"subprocess\.popen\(\s*\[\s*bin_loader\s*,\s*bin_prog\s*\]", low)
    ):
        findings.append("local default start uses loader+libc; may diverge from official process(binary) stack layout")
    if (
        ("def recvuntil" in low)
        and re.search(r"def\s+recvuntil[\s\S]{0,1200}?out\s*=\s*self\.buf[\s\S]{0,200}?self\.buf\s*=\s*b[\"']{2}", low)
    ):
        findings.append("recvuntil timeout branch clears internal buffer; leak bytes may be consumed accidentally")
    if (
        ("recvuntil(b\"mem: \"" in low or "recvuntil(b'mem: '" in low)
        and ("recvline(" in low)
        and ("\\x01\\n" not in low)
    ):
        findings.append("secret read path lacks explicit terminator read (e.g. recvuntil(b'\\\\x01\\\\n', drop=False))")
    if (
        ("leak" in low or "find_leak_word" in low)
        and (("int.from_bytes" in low) or ("int(" in low and ", 16" in low))
    ):
        has_ansi_sanitize = ("\\x1b" in low) or ("ansi" in low and "strip" in low)
        has_low_byte_guard = ("endswith('0a'" in low) or ("endswith(\"0a\"" in low) or ("& 0xfff" in low)
        if (not has_ansi_sanitize) or (not has_low_byte_guard):
            findings.append("leak parser may accept ANSI/control-byte polluted addresses; add sanitization and low-byte guard")
    if ("/proc/" in src) and ("/maps" in low or "/mem" in low):
        findings.append("exploit relies on /proc pid memory/maps; likely incompatible with pure remote socket target")
    if ("2>/dev/null" in low) or (">/dev/null" in low):
        findings.append("remote shell may forbid /dev/null redirection; prefer probe commands without /dev/null dependency")
    if re.search(r"(sendline|send|sendafter|sendlineafter)\s*\([^)]{0,120}(?:b['\"]id['\"]|['\"]id['\"])", low):
        findings.append("verify path uses `id`; prefer marker/flag-based success checks to avoid remote shell variance")
    if ("syscall" in low) and ("syscall_ret" in low):
        has_sig_validation = ("0f05c3" in low) or ("_pick_syscall_ret_gadget" in low) or ("_find_gadget_sig" in low)
        if not has_sig_validation:
            findings.append("syscall gadget selected without byte-signature validation; verify raw 0f 05 c3 bytes instead of nearby disassembly text")

    has_payload_send = ("_send_payload(" in low) or ("send_stage(" in low) or ("send_payload(" in low)
    has_read_cap_hint = any(k in low for k in ("read_size", "read_len", "pwn_read_len", "payload_max", "payload_cap"))
    has_len_guard = (
        ("payload_oversize" in low)
        or bool(re.search(r"len\([^)]*(payload|data|chain|rop)[^)]*\)\s*(<=|<)\s*[^:\n]{0,80}(read|size|max|cap)", low))
        or ("assert len(" in low and has_read_cap_hint)
    )
    if has_payload_send and has_read_cap_hint and (not has_len_guard):
        findings.append("payload length guard missing; enforce len(payload)<=read_size before each send")

    has_csu = ("ret2csu" in low) or ("__libc_csu_init" in low) or ("csu_pop" in low and "csu_call" in low)
    if has_csu:
        has_csu_layout_check = any(
            k in low
            for k in (
                "ret2csu_selfcheck",
                "tail_qwords",
                "chain_qwords",
                "add rsp, 8",
            )
        )
        if not has_csu_layout_check:
            findings.append("ret2csu path detected without layout self-check; verify rbx/rbp and 7-slot return tail before send")
    has_saved_rbp_pivot = any(
        k in low
        for k in (
            "saved_rbp",
            "saved rbp",
            "leave_ret",
            "leave; ret",
            "stack_pivot",
            "pivot_off",
            "pivot offset",
        )
    )
    if has_saved_rbp_pivot:
        has_phase_sync = any(k in low for k in ("_send_phase(", "_recv_until_any(", "recvuntil(", "recv_until("))
        has_leave_chain = any(k in low for k in ("leave_ret", "_pick_leave_ret_gadget", "pop_rbp", "\"rbp\""))
        if not has_leave_chain:
            findings.append("saved-rbp pivot path detected without explicit pop rbp + leave; ret chain closure")
        if ("remote" in low or "socket" in low) and (not has_phase_sync):
            findings.append("saved-rbp/menu pivot path detected without phased prompt-sync send; avoid one-shot remote stdin flattening")

    has_got_token = ("@got" in low) or bool(re.search(r"\bgot(?:\.plt)?\b", low))
    has_atoi = ("atoi" in low)
    has_system = ("system" in low)
    if has_got_token and (has_atoi or has_system):
        has_closure_probe = any(
            k in low
            for k in (
                "got write ok",
                "got overwrite ok",
                "verify got",
                "probe got",
                "wrote atoi@got",
                "atoi->system",
                "hooked atoi",
            )
        )
        if not has_closure_probe:
            findings.append(
                "got-overwrite path detected; add explicit closure milestone: writable GOT -> controllable call before libc offset solving"
            )

    if has_got_token and has_atoi:
        signed_patterns = [
            r"ctypes\.c_int32\s*\(",
            r"struct\.pack\(\s*['\"]<i['\"]",
            r"to_signed32\s*\(",
            r"\bint32_signed\s*\(",
            r"-\s*0x100000000",
            r"1\s*<<\s*31",
            r"0x80000000",
        ]
        has_signed_i32 = any(re.search(pat, low) for pat in signed_patterns)
        writes_decimal = bool(
            re.search(r"send(?:line|after)?\s*\(\s*str\s*\((?:[^)]*system|[^)]*got|[^)]*addr|[^)]*target)", low)
            or re.search(r"\bstr\s*\(\s*(?:system|got|addr|target)[a-z0-9_]*\s*\)", low)
        )
        if writes_decimal and (not has_signed_i32):
            findings.append("atoi@got overwrite may need signed int32 decimal semantics; add explicit int32 conversion before send")

    has_reconnect_retry = any(
        k in low
        for k in (
            "remote_retries",
            "remote-retry",
            "reconnect",
            "retry",
            "attempt",
        )
    )
    has_retry_backoff = ("retry_backoff" in low) or bool(re.search(r"delay\s*\*\s*\(", low))
    has_retry_jitter = ("jitter" in low) or ("random.uniform" in low)
    if has_reconnect_retry and ((not has_retry_backoff) or (not has_retry_jitter)):
        findings.append("remote retry loop detected without explicit backoff+jitter; may trigger rate-limit and unstable EOF")
    has_leak_math = ("leak" in low) and any(k in low for k in ("libc_base", "system_off", "system_offset", "puts_off"))
    has_conn_scope_guard = any(
        k in low
        for k in (
            "same_conn",
            "same connection",
            "conn_id",
            "connection_id",
            "single_connection",
            "single_conn",
            "one connection",
        )
    )
    if has_reconnect_retry and has_leak_math and (not has_conn_scope_guard):
        findings.append("leak math appears with reconnect/retry flow; ensure libc base/offset uses leaks from the same connection only")

    has_offset_candidate_loop = bool(
        re.search(r"for\s+\w+\s+in\s+[^:\n]{0,120}(?:offset|off|candidate|system)", low)
        and any(k in low for k in ("system_off", "system_offset", "libc"))
    )
    has_dynamic_table_evidence = any(
        k in low for k in ("dt_hash", "gnu_hash", "elf dynamic", "dynelf", "readelf", "elf(")
    )
    if has_offset_candidate_loop and (not has_dynamic_table_evidence):
        findings.append(
            "libc/system offset resolution looks brute-force heavy; prefer same-connection multi-leak or ELF dynamic-table evidence"
        )

    if ("0x2333" in low or "2333" in low):
        has_menu_prompt_sync = (
            ("recvuntil" in low and ("choose" in low or "menu" in low or "option" in low))
            or ("expect_hint" in low)
        )
        has_send_timing_guard = ("send_delay" in low) or ("post_delay" in low) or ("time.sleep(" in low)
        if (not has_menu_prompt_sync) or (not has_send_timing_guard):
            findings.append(
                "hidden branch token 0x2333 detected; enforce menu-boundary recv sync and short send delay to avoid Invalid option drift"
            )
    return findings


def _apply_marker_gate(
    run_detail: Dict[str, Any],
    *,
    marker_check_enabled: bool,
    markers: List[str],
    regexes: List[str],
) -> Dict[str, Any]:
    merged = f"{run_detail.get('stdout_tail','')}\n{run_detail.get('stderr_tail','')}"
    merged_low = merged.lower()
    normalized_markers = [str(m).strip() for m in markers if str(m).strip()]
    normalized_regexes = [str(p).strip() for p in regexes if str(p).strip()]
    marker_hit_plain = (not normalized_markers) or any(str(m).lower() in merged_low for m in normalized_markers)
    regex_matches: List[str] = []
    regex_hit = False
    if normalized_regexes:
        for pat in normalized_regexes:
            try:
                if re.search(pat, merged, flags=re.IGNORECASE):
                    regex_hit = True
                    regex_matches.append(pat)
            except re.error:
                continue
    marker_hit = bool(marker_hit_plain or regex_hit)
    run_detail["marker_check_enabled"] = bool(marker_check_enabled)
    run_detail["markers"] = normalized_markers
    run_detail["regexes"] = normalized_regexes
    run_detail["regex_hit"] = bool(regex_hit)
    run_detail["regex_matches"] = regex_matches[:4]
    run_detail["marker_hit"] = bool(marker_hit)
    return run_detail


def _extract_stage_evidence(stdout_tail: str, stderr_tail: str) -> Dict[str, Any]:
    merged = f"{str(stdout_tail or '')}\n{str(stderr_tail or '')}"
    lines = merged.splitlines()
    events: List[Dict[str, Any]] = []
    for line in lines:
        if "[stage-evidence]" not in line:
            continue
        tail = line.split("[stage-evidence]", 1)[-1].strip()
        if not tail:
            continue
        try:
            obj = json.loads(tail)
        except Exception:
            continue
        if isinstance(obj, dict):
            events.append(obj)

    stage1_send_attempts = set()
    stage1_eof_attempts = set()
    stage1_post_raw_max = 0
    stage_breakpoints: List[str] = []
    single_byte_selfcheck_ok: Optional[bool] = None
    single_byte_selfcheck_count = 0
    failure_addr_snapshots: List[Dict[str, str]] = []

    for ev in events:
        stage = str(ev.get("stage", "")).strip().lower()
        event = str(ev.get("event", "")).strip().lower()
        try:
            attempt = int(ev.get("attempt", 0) or 0)
        except Exception:
            attempt = 0
        if stage:
            stage_breakpoints.append(stage)
        if stage == "stage1" and event == "send" and attempt > 0:
            stage1_send_attempts.add(attempt)
        if stage == "stage1" and bool(ev.get("eof", False)) and attempt > 0:
            stage1_eof_attempts.add(attempt)
        if stage == "stage1" and event == "post_recv":
            try:
                stage1_post_raw_max = max(stage1_post_raw_max, int(ev.get("raw_len", 0) or 0))
            except Exception:
                pass
        if stage == "stage1" and event == "single_byte_selfcheck":
            single_byte_selfcheck_count += 1
            if "ok" in ev:
                single_byte_selfcheck_ok = bool(ev.get("ok", False))
        if event == "addr_snapshot":
            snap: Dict[str, str] = {}
            for k in ("exit", "prog", "libc", "envp", "ret"):
                v = str(ev.get(k, "")).strip()
                if v:
                    snap[k] = v
            if snap:
                failure_addr_snapshots.append(snap)

    stage1_attempts_n = len(stage1_send_attempts)
    stage1_eof_n = len(stage1_eof_attempts)
    stage1_ok_proxy = max(0, stage1_attempts_n - stage1_eof_n)
    stage1_rate = (float(stage1_ok_proxy) / float(stage1_attempts_n)) if stage1_attempts_n > 0 else None

    merged_low = merged.lower()
    leak_vals = re.findall(r"\bleak\s+[a-z0-9_]+=0x([0-9a-f]+)", merged_low)
    leak_vals = leak_vals[:8]
    invalid_option_count = len(re.findall(r"\binvalid\s+(?:option|choice)\b", merged_low))
    wrong_choice_count = len(re.findall(r"\bwrong\s+choice\b", merged_low))
    menu_prompt_hits = len(re.findall(r"(?:choose|choice|menu|option)[^\n:>]{0,12}[:>]", merged_low))

    return {
        "event_count": len(events),
        "events_tail": events[-12:],
        "stage1_attempts": stage1_attempts_n,
        "stage1_eof_attempts": stage1_eof_n,
        "stage1_success_proxy_attempts": stage1_ok_proxy,
        "stage1_success_proxy_rate": (round(stage1_rate, 4) if stage1_rate is not None else None),
        "stage1_post_recv_raw_len_max": int(stage1_post_raw_max),
        "invalid_option_count": int(invalid_option_count),
        "wrong_choice_count": int(wrong_choice_count),
        "menu_prompt_hits": int(menu_prompt_hits),
        "last_stage": (stage_breakpoints[-1] if stage_breakpoints else ""),
        "leak_values_hex_tail": leak_vals,
        "single_byte_selfcheck_ok": single_byte_selfcheck_ok,
        "single_byte_selfcheck_count": int(single_byte_selfcheck_count),
        "failure_addr_snapshot_count": int(len(failure_addr_snapshots)),
        "failure_addr_snapshot_tail": (failure_addr_snapshots[-1] if failure_addr_snapshots else {}),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify local exp file (L3)")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--session-id", default="")
    ap.add_argument("--loop", type=int, default=0)
    ap.add_argument("--exp", default="", help="exp path override")
    ap.add_argument("--run", action="store_true", help="attempt to execute exp with timeout")
    ap.add_argument("--run-timeout-sec", type=float, default=4.0)
    ap.add_argument(
        "--run-strict",
        action="store_true",
        help="legacy compatibility flag (runtime check now always contributes to top-level ok when --run is set)",
    )
    ap.add_argument(
        "--verify-mode",
        choices=["quick", "full", "auto"],
        default="full",
        help="quick=marker only, full=marker/flag markers, auto=quick then fallback full",
    )
    ap.add_argument(
        "--quick-then-full",
        action="store_true",
        help="when verify-mode=auto and quick fails, run one full verify fallback",
    )
    ap.add_argument(
        "--success-markers",
        default="__PWN_VERIFY_OK__,flag{,you pwned me,remember you forever",
        help="comma-separated markers expected in runtime output when --run is enabled",
    )
    ap.add_argument(
        "--success-regexes",
        default=r"flag\{[^\n}]{1,200}\},ctf\{[^\n}]{1,200}\},cyberpeace\{[^\n}]{1,200}\}",
        help="comma-separated regexes expected in runtime output when --run is enabled",
    )
    ap.add_argument("--no-success-marker-check", action="store_true")
    ap.add_argument("--python", default="", help="python binary used for --run")
    ap.add_argument("--remote-host", default="", help="remote target host for runtime check")
    ap.add_argument("--remote-port", type=int, default=0, help="remote target port for runtime check")
    ap.add_argument(
        "--env",
        action="append",
        default=[],
        help="extra runtime env in KEY=VALUE form (only PWN_* accepted); can repeat",
    )
    ap.add_argument("--report", default="")
    ap.add_argument("--no-update-state", action="store_true")
    args = ap.parse_args()

    if str(args.remote_host or "").strip() and int(args.remote_port or 0) <= 0:
        print(json.dumps({"ok": False, "error": "remote host set but remote port invalid"}, ensure_ascii=False, indent=2))
        return 2

    if not os.path.exists(args.state):
        print(json.dumps({"ok": False, "error": f"state not found: {args.state}"}, ensure_ascii=False, indent=2))
        return 2

    state = load_json(args.state)
    run_env_defaults: Dict[str, str] = {}
    run_env_defaults.update(_load_policy_verify_env_defaults())
    run_env_defaults.update(_load_state_verify_env_defaults(state))
    run_env_defaults.update(_parse_cli_env(args.env))
    sid = args.session_id.strip() or str(state.get("session", {}).get("session_id", "")).strip() or "unknown"
    raw_exp, exp_abs = _resolve_exp_path(state, args.exp, sid)

    checks: Dict[str, Any] = {
        "exists": False,
        "inside_repo": False,
        "non_empty": False,
        "py_compile_ok": False,
        "has_pwntools_import": False,
    }
    py_compile = {"ok": False, "rc": 2, "stderr": "skipped"}
    run_detail = {
        "attempted": False,
        "ok": True,
        "timeout": False,
        "rc": 0,
        "stderr_tail": "",
        "stdout_tail": "",
        "cmd": "",
        "marker_check_enabled": False,
        "marker_hit": False,
        "markers": [],
        "regex_hit": False,
        "regexes": [],
        "regex_matches": [],
        "stage_evidence": {},
    }
    static_findings: List[str] = []

    if exp_abs:
        checks["exists"] = os.path.isfile(exp_abs)
        checks["inside_repo"] = _inside_repo(exp_abs)
        if checks["exists"]:
            try:
                checks["non_empty"] = os.path.getsize(exp_abs) > 0
                with open(exp_abs, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
                checks["has_pwntools_import"] = ("from pwn import" in text) or ("import pwn" in text)
                static_findings = _analyze_static_findings(text)
            except Exception:
                checks["non_empty"] = False
        if checks["exists"]:
            ok_compile, rc_compile, stderr_compile = _py_compile_ok(exp_abs)
            checks["py_compile_ok"] = ok_compile
            py_compile = {"ok": ok_compile, "rc": rc_compile, "stderr": stderr_compile[-1500:]}
            if args.run and ok_compile:
                run_python = _choose_run_python(bool(checks.get("has_pwntools_import", False)), args.python)
                if not run_python:
                    run_detail = {
                        "attempted": True,
                        "ok": False,
                        "timeout": False,
                        "rc": 127,
                        "stderr_tail": "no suitable python found for runtime check (pwntools unavailable)",
                        "stdout_tail": "",
                        "cmd": "",
                        "marker_check_enabled": False,
                        "marker_hit": False,
                        "markers": [],
                        "regex_hit": False,
                        "regexes": [],
                        "regex_matches": [],
                    }
                else:
                    marker_check_enabled = bool(args.run) and (not bool(args.no_success_marker_check))
                    full_markers = _split_markers(args.success_markers)
                    full_regexes = _split_markers(args.success_regexes)
                    quick_markers = ["__PWN_VERIFY_OK__"] if marker_check_enabled else []
                    quick_regexes = full_regexes if marker_check_enabled else []
                    verify_mode = str(args.verify_mode or "full").strip().lower()
                    if verify_mode not in {"quick", "full", "auto"}:
                        verify_mode = "full"

                    steps: List[Dict[str, Any]] = []

                    def _run_step(
                        step_mode: str,
                        step_markers: List[str],
                        step_regexes: List[str],
                        timeout_sec: float,
                    ) -> Dict[str, Any]:
                        rd = _run_exp(
                            exp_abs,
                            timeout_sec,
                            run_python,
                            remote_host=str(args.remote_host or "").strip(),
                            remote_port=int(args.remote_port or 0),
                            extra_env_defaults=run_env_defaults,
                        )
                        _apply_marker_gate(
                            rd,
                            marker_check_enabled=marker_check_enabled,
                            markers=(step_markers if marker_check_enabled else []),
                            regexes=(step_regexes if marker_check_enabled else []),
                        )
                        rd["stage_evidence"] = _extract_stage_evidence(
                            str(rd.get("stdout_tail", "")).strip(),
                            str(rd.get("stderr_tail", "")).strip(),
                        )
                        rd["verify_mode"] = step_mode
                        return rd

                    if verify_mode == "quick":
                        rd = _run_step("quick", quick_markers, quick_regexes, float(args.run_timeout_sec))
                        steps.append(rd)
                    elif verify_mode == "full":
                        rd = _run_step("full", full_markers, full_regexes, float(args.run_timeout_sec))
                        steps.append(rd)
                    else:
                        rd_quick = _run_step("quick", quick_markers, quick_regexes, float(args.run_timeout_sec))
                        steps.append(rd_quick)
                        quick_ok = bool(rd_quick.get("ok", False))
                        quick_marker = bool(rd_quick.get("marker_hit", False)) if marker_check_enabled else True
                        if (not quick_ok or not quick_marker) and bool(args.quick_then_full):
                            # Reuse quick output first: some challenges succeed without shell marker
                            # (e.g., format-string branch markers like "you pwned me").
                            rd_quick_full = dict(rd_quick)
                            _apply_marker_gate(
                                rd_quick_full,
                                marker_check_enabled=marker_check_enabled,
                                markers=(full_markers if marker_check_enabled else []),
                                regexes=(full_regexes if marker_check_enabled else []),
                            )
                            quick_full_marker = (
                                bool(rd_quick_full.get("marker_hit", False)) if marker_check_enabled else True
                            )
                            if quick_ok and quick_full_marker:
                                rd_quick_full["verify_mode"] = "quick_as_full"
                                steps.append(rd_quick_full)
                            else:
                                rd_full = _run_step("full", full_markers, full_regexes, float(args.run_timeout_sec))
                                steps.append(rd_full)

                    run_detail = dict(steps[-1]) if steps else run_detail
                    run_detail["run_steps"] = steps
                    run_detail["verify_mode"] = verify_mode
                    run_detail.setdefault("marker_check_enabled", False)
                    run_detail.setdefault("marker_hit", False)
                    run_detail.setdefault("markers", [])
                    run_detail.setdefault("regex_hit", False)
                    run_detail.setdefault("regexes", [])
                    run_detail.setdefault("regex_matches", [])
    else:
        py_compile = {"ok": False, "rc": 2, "stderr": "exp path missing"}

    must_pass = ["exists", "inside_repo", "non_empty", "py_compile_ok"]
    ok = all(bool(checks.get(k, False)) for k in must_pass)
    run_result_ok = True
    marker_gate = True
    marker_override = False
    if args.run:
        if bool(run_detail.get("marker_check_enabled", False)):
            marker_gate = bool(run_detail.get("marker_hit", False))
        has_marker_expectation = bool(
            run_detail.get("markers", []) or run_detail.get("regexes", [])
        )
        marker_override = bool(
            bool(run_detail.get("marker_check_enabled", False))
            and has_marker_expectation
            and bool(marker_gate)
            and (not bool(run_detail.get("ok", False)))
        )
        run_detail["ok_by_marker_override"] = bool(marker_override)
        run_result_ok = bool(marker_gate and (bool(run_detail.get("ok", False)) or marker_override))
        # When --run is requested, runtime result always participates in top-level ok.
        # This avoids misleading "ok=true while run timed out/failed".
        ok = ok and run_result_ok

    loop_suffix = f"{int(args.loop):02d}" if int(args.loop) >= 0 else "00"
    if args.report:
        report_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        report_abs = os.path.join(ROOT_DIR, "artifacts", "reports", f"exp_verify_{sid}_{loop_suffix}.json")
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)

    auto_offset_hit = _extract_auto_offset_hit(run_detail) if args.run else {}
    if auto_offset_hit:
        run_detail["auto_offset_hit"] = auto_offset_hit

    report = {
        "generated_utc": utc_now(),
        "session_id": sid,
        "loop": int(args.loop),
        "ok": ok,
        "ok_semantics": "static+runtime" if args.run else "static-only",
        "run_result_ok": bool(run_result_ok) if args.run else None,
        "run_marker_override": bool(marker_override) if args.run else None,
        "remote_target": {
            "host": str(args.remote_host or "").strip(),
            "port": int(args.remote_port or 0),
        },
        "exp_path": repo_rel(exp_abs) if exp_abs and _inside_repo(exp_abs) else raw_exp,
        "checks": checks,
        "py_compile": py_compile,
        "static_findings": static_findings,
        "run": run_detail,
        "run_env_defaults": run_env_defaults,
        "auto_offset_hit": auto_offset_hit,
    }
    state_meta_sync: Dict[str, Any] = {"attempted": False, "ok": False}
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    if not args.no_update_state:
        sess = state.setdefault("session", {})
        exp = sess.setdefault("exp", {})
        exp["local_verify_passed"] = bool(ok)
        exp["verify_report"] = repo_rel(report_abs)
        if bool(ok):
            exp["local_verified_utc"] = utc_now()
            cur_status = str(sess.get("status", "")).strip()
            if cur_status not in {"remote_verified", "finished", "finished_with_errors"}:
                sess["status"] = "local_verified"
            if args.run and bool(run_result_ok):
                caps = state.setdefault("capabilities", {})
                caps["exploit_success"] = True
                hit_off = int(auto_offset_hit.get("offset_to_rip", 0) or 0)
                if hit_off > 0:
                    caps["control_rip"] = True
                    caps["offset_to_rip"] = int(hit_off)
                    exp["selected_offset"] = int(hit_off)
                if "align_ret" in auto_offset_hit:
                    exp["selected_align_ret"] = int(auto_offset_hit.get("align_ret", 0) or 0)
        latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
        latest["exp_verify_report"] = repo_rel(report_abs)
        save_json(args.state, state)
        state_meta_sync = _sync_state_meta(sid, args.state)
        report["state_meta_sync"] = state_meta_sync
        with open(report_abs, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    out = {
        "ok": ok,
        "ok_semantics": report.get("ok_semantics"),
        "run_result_ok": report.get("run_result_ok"),
        "session_id": sid,
        "exp_path": report["exp_path"],
        "report": repo_rel(report_abs),
        "checks": checks,
        "state_meta_sync": state_meta_sync,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
