#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_REPORT_DIR = os.path.join(ROOT_DIR, "artifacts", "reports")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_ps() -> List[Tuple[int, str]]:
    try:
        p = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
            check=False,
            timeout=2.5,
        )
    except Exception:
        return []
    out: List[Tuple[int, str]] = []
    for line in (p.stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        parts = s.split(maxsplit=1)
        if not parts:
            continue
        try:
            pid = int(parts[0])
        except Exception:
            continue
        cmd = parts[1].strip() if len(parts) > 1 else ""
        out.append((pid, cmd))
    return out


def _match_stale_mcp(
    items: List[Tuple[int, str]],
    *,
    project_path: str,
    runtime_root: str,
    include_gdb: bool,
) -> List[Tuple[int, str]]:
    out: List[Tuple[int, str]] = []
    cur = os.getpid()
    for pid, cmd in items:
        if pid <= 1 or pid == cur:
            continue
        low = cmd.lower()
        is_pyghidra = ("pyghidra-mcp" in low) or ("mcp_jsonline_bridge.py" in low)
        is_gdb = include_gdb and ("gdb-mcp" in low or "server.py" in low and "mcp" in low)
        if not (is_pyghidra or is_gdb):
            continue
        if project_path and project_path in cmd:
            out.append((pid, cmd))
            continue
        if runtime_root and runtime_root in cmd:
            out.append((pid, cmd))
            continue
        if is_pyghidra and ("project_dirge_ghidra" in low or "my_project" in low):
            out.append((pid, cmd))
    dedup: Dict[int, str] = {}
    for pid, cmd in out:
        dedup[pid] = cmd
    return sorted(dedup.items(), key=lambda x: x[0])


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _stop_pids(pids: List[int], timeout_sec: float = 1.2) -> Dict[str, Any]:
    terminated: List[int] = []
    killed: List[int] = []
    errors: List[str] = []

    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
            terminated.append(pid)
        except Exception as e:
            errors.append(f"SIGTERM {pid}: {e}")

    deadline = time.monotonic() + max(0.1, float(timeout_sec))
    alive = [pid for pid in pids if _pid_exists(pid)]
    while alive and time.monotonic() < deadline:
        time.sleep(0.08)
        alive = [pid for pid in alive if _pid_exists(pid)]

    for pid in alive:
        try:
            os.kill(pid, signal.SIGKILL)
            killed.append(pid)
        except Exception as e:
            errors.append(f"SIGKILL {pid}: {e}")

    return {
        "term_sent": terminated,
        "kill_sent": killed,
        "errors": errors,
    }


def _remove_locks(project_path: str, project_name: str, has_live_pyghidra: bool) -> List[str]:
    removed: List[str] = []
    if has_live_pyghidra:
        return removed
    if not project_path or not project_name:
        return removed
    cands = [
        os.path.join(project_path, f"{project_name}.lock"),
        os.path.join(project_path, f"{project_name}.lock~"),
    ]
    for p in cands:
        try:
            if os.path.exists(p):
                os.unlink(p)
                removed.append(os.path.relpath(p, ROOT_DIR))
        except Exception:
            continue
    return removed


def _warmup_health(codex_bin: str, require_servers: List[str], timeout_sec: float) -> Dict[str, Any]:
    report_rel = f"artifacts/reports/mcp_health_warmup_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    cmd = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "health_check_mcp.py"),
        "--codex-bin",
        codex_bin,
        "--timeout-sec",
        str(max(1.0, float(timeout_sec))),
        "--require",
        ",".join(require_servers),
        "--authority",
        "codex_registry",
        "--functional-probe",
        "--probe-timeout-sec",
        str(max(3.0, float(timeout_sec))),
        "--report",
        report_rel,
        "--json",
    ]
    try:
        p = subprocess.run(cmd, cwd=ROOT_DIR, text=True, capture_output=True, check=False, timeout=max(2.0, timeout_sec + 2.0))
    except Exception as e:
        return {"ok": False, "error": str(e), "report": report_rel}
    out_obj: Dict[str, Any] = {}
    try:
        obj = json.loads((p.stdout or "").strip() or "{}")
        if isinstance(obj, dict):
            out_obj = obj
    except Exception:
        out_obj = {}
    return {
        "ok": int(p.returncode) == 0,
        "rc": int(p.returncode),
        "report": report_rel,
        "stdout_tail": (p.stdout or "")[-800:],
        "stderr_tail": (p.stderr or "")[-800:],
        "result": out_obj,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP self-heal for pyghidra/gdb startup instability")
    ap.add_argument("--session-id", default="")
    ap.add_argument("--loop", type=int, default=0)
    ap.add_argument("--stage", default="")
    ap.add_argument("--reason", default="")
    ap.add_argument("--codex-bin", default="scripts/codex_with_mcp.sh")
    ap.add_argument("--project-path", default=os.environ.get("GHIDRA_MCP_PROJECT_PATH", "/tmp/project_dirge_ghidra/project"))
    ap.add_argument("--project-name", default=os.environ.get("GHIDRA_MCP_PROJECT_NAME", "my_project"))
    ap.add_argument("--runtime-root", default=os.environ.get("GHIDRA_RUNTIME_ROOT", "/tmp/project_dirge_ghidra"))
    ap.add_argument("--include-gdb", action="store_true")
    ap.add_argument("--warmup-health", action="store_true")
    ap.add_argument("--warmup-timeout-sec", type=float, default=4.0)
    ap.add_argument("--post-stop-wait-sec", type=float, default=0.25)
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    os.makedirs(DEFAULT_REPORT_DIR, exist_ok=True)
    if args.report:
        report_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        sid = str(args.session_id or "na").strip() or "na"
        stg = str(args.stage or "na").strip() or "na"
        lp = max(0, int(args.loop or 0))
        report_abs = os.path.join(DEFAULT_REPORT_DIR, f"mcp_self_heal_{sid}_{lp:02d}_{stg}.json")

    project_path = str(args.project_path or "").strip()
    project_name = str(args.project_name or "").strip()
    runtime_root = str(args.runtime_root or "").strip()
    post_stop_wait_sec = max(0.0, float(args.post_stop_wait_sec or 0.0))

    def _live_pyghidra(items: List[Tuple[int, str]]) -> List[Tuple[int, str]]:
        rows = _match_stale_mcp(items, project_path=project_path, runtime_root=runtime_root, include_gdb=False)
        return [(pid, cmd) for pid, cmd in rows if ("pyghidra-mcp" in cmd.lower() or "mcp_jsonline_bridge.py" in cmd.lower())]

    ps_items = _run_ps()
    stale = _match_stale_mcp(
        ps_items,
        project_path=project_path,
        runtime_root=runtime_root,
        include_gdb=bool(args.include_gdb),
    )
    stale_pids = [pid for pid, _ in stale]
    stop_doc = _stop_pids(stale_pids, timeout_sec=1.2) if stale_pids else {"term_sent": [], "kill_sent": [], "errors": []}

    if post_stop_wait_sec > 0:
        time.sleep(min(1.2, post_stop_wait_sec))

    ps_after = _run_ps()
    live_pyghidra = _live_pyghidra(ps_after)

    second_stop_doc: Dict[str, Any] = {"term_sent": [], "kill_sent": [], "errors": []}
    if live_pyghidra:
        second_stop_doc = _stop_pids([pid for pid, _ in live_pyghidra], timeout_sec=0.8)
        if post_stop_wait_sec > 0:
            time.sleep(min(1.0, post_stop_wait_sec))
        ps_after = _run_ps()
        live_pyghidra = _live_pyghidra(ps_after)

    has_live_pyghidra = bool(live_pyghidra)
    removed_locks = _remove_locks(
        project_path=project_path,
        project_name=project_name,
        has_live_pyghidra=has_live_pyghidra,
    )

    warmup = {}
    if bool(args.warmup_health):
        warmup = _warmup_health(
            codex_bin=str(args.codex_bin or "scripts/codex_with_mcp.sh").strip(),
            require_servers=["pyghidra-mcp", "gdb"],
            timeout_sec=float(args.warmup_timeout_sec or 4.0),
        )

    doc = {
        "generated_utc": utc_now(),
        "session_id": str(args.session_id or "").strip(),
        "loop": int(args.loop or 0),
        "stage": str(args.stage or "").strip(),
        "reason": str(args.reason or "").strip(),
        "project_path": project_path,
        "project_name": project_name,
        "runtime_root": runtime_root,
        "post_stop_wait_sec": post_stop_wait_sec,
        "stale_processes": [{"pid": pid, "cmd": cmd} for pid, cmd in stale],
        "stop": stop_doc,
        "second_stop": second_stop_doc,
        "live_pyghidra_after": [{"pid": pid, "cmd": cmd} for pid, cmd in live_pyghidra],
        "removed_locks": removed_locks,
        "warmup": warmup,
    }
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)

    out = {
        "ok": True,
        "report": os.path.relpath(report_abs, ROOT_DIR),
        "stale_count": len(stale),
        "removed_locks": len(removed_locks),
        "live_pyghidra_after": len(live_pyghidra),
        "warmup_ok": bool(warmup.get("ok", True)) if isinstance(warmup, dict) and warmup else None,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
