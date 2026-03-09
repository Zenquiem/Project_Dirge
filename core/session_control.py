#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except PermissionError:
        # EPERM means process exists but current user cannot signal it.
        return True
    except Exception:
        return False


def control_dir(root_dir: str, session_id: str) -> str:
    return os.path.join(root_dir, "sessions", session_id, "control")


def stop_flag_path(root_dir: str, session_id: str) -> str:
    return os.path.join(control_dir(root_dir, session_id), "stop.requested.json")


def lock_file_path(root_dir: str, session_id: str) -> str:
    return os.path.join(control_dir(root_dir, session_id), "run.lock")


def self_stop_blocked_by_env() -> bool:
    v = str(os.environ.get("DIRGE_BLOCK_SELF_STOP", "")).strip().lower()
    return v in {"1", "true", "yes", "on"}


@dataclass
class RunLock:
    acquired: bool
    path: str
    error: str = ""
    owner_pid: int = 0
    stale_reclaimed: bool = False


def acquire_run_lock(root_dir: str, session_id: str) -> RunLock:
    cdir = control_dir(root_dir, session_id)
    os.makedirs(cdir, exist_ok=True)
    lpath = lock_file_path(root_dir, session_id)
    payload = {"pid": os.getpid(), "session_id": session_id, "created_utc": utc_now()}

    reclaimed = False
    for _ in range(2):
        try:
            fd = os.open(lpath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            try:
                os.write(fd, json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8"))
            finally:
                os.close(fd)
            return RunLock(acquired=True, path=lpath, stale_reclaimed=reclaimed)
        except FileExistsError:
            owner_pid = 0
            try:
                with open(lpath, "r", encoding="utf-8") as f:
                    info = json.load(f)
                owner_pid = int(info.get("pid", 0) or 0)
            except Exception:
                owner_pid = 0

            if owner_pid > 0 and _pid_alive(owner_pid):
                return RunLock(
                    acquired=False,
                    path=lpath,
                    error=f"session already running (pid={owner_pid})",
                    owner_pid=owner_pid,
                )

            try:
                os.remove(lpath)
                reclaimed = True
                continue
            except Exception as e:
                return RunLock(
                    acquired=False,
                    path=lpath,
                    error=f"stale lock exists but cannot remove: {e}",
                    owner_pid=owner_pid,
                )
    return RunLock(acquired=False, path=lpath, error="failed to acquire run lock")


def release_run_lock(lock: RunLock) -> None:
    if not lock.path:
        return
    try:
        os.remove(lock.path)
    except FileNotFoundError:
        return
    except Exception:
        return


def write_stop_request(root_dir: str, session_id: str, reason: str) -> str:
    if self_stop_blocked_by_env():
        raise PermissionError("stop request blocked in autorun context (DIRGE_BLOCK_SELF_STOP=1)")
    cdir = control_dir(root_dir, session_id)
    os.makedirs(cdir, exist_ok=True)
    path = stop_flag_path(root_dir, session_id)
    doc = {
        "requested_utc": utc_now(),
        "requested_by_pid": os.getpid(),
        "reason": reason.strip() if isinstance(reason, str) else "",
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
    return path


def read_stop_request(root_dir: str, session_id: str) -> dict:
    path = stop_flag_path(root_dir, session_id)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return {}
    return {}


def clear_stop_request(root_dir: str, session_id: str) -> None:
    path = stop_flag_path(root_dir, session_id)
    try:
        os.remove(path)
    except Exception:
        return
