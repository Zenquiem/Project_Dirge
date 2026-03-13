#!/usr/bin/env python3
"""Bridge MCP stdio framing between Content-Length and JSONL transports."""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import threading
from typing import BinaryIO, Dict, List, Optional

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

_LOG_LOCK = threading.Lock()


def _repo_anchor_path(raw: str) -> str:
    s = str(raw or "").strip()
    if not s or os.path.isabs(s) or "://" in s:
        return s
    return os.path.abspath(os.path.join(ROOT_DIR, s))


def _anchor_pathlike_value(raw: str, base_dir: str | None = None) -> str:
    s = str(raw or "").strip()
    if not s or os.path.isabs(s) or "://" in s:
        return s
    return os.path.abspath(os.path.join(base_dir or ROOT_DIR, s))


def _normalize_command_string(raw: str) -> str:
    parts = shlex.split(str(raw or ""))
    if not parts:
        return ""
    out: List[str] = []
    flag_takes_value = {"-W", "-X", "--check-hash-based-pycs", "-O"}
    i = 0
    while i < len(parts):
        cur = parts[i]
        out.append(cur)
        if i == 0:
            i += 1
            continue
        prev = parts[i - 1] if i > 0 else ""
        if prev in flag_takes_value:
            i += 1
            continue
        if cur in flag_takes_value and (i + 1) < len(parts):
            out.append(parts[i + 1])
            i += 2
            continue
        if cur == "-m" and (i + 1) < len(parts):
            out.append(parts[i + 1])
            i += 2
            continue
        if cur == "-S" and (i + 1) < len(parts):
            payload_parts = shlex.split(parts[i + 1])
            out.append(
                " ".join(
                    _anchor_pathlike_value(tok, ROOT_DIR)
                    if ((tok.startswith("./") or tok.startswith("../") or "/" in tok) and not os.path.isabs(tok))
                    else tok
                    for tok in payload_parts
                )
            )
            i += 2
            continue
        if (cur.startswith("./") or cur.startswith("../") or "/" in cur) and not os.path.isabs(cur):
            out[-1] = _anchor_pathlike_value(cur, ROOT_DIR)
        i += 1
    return " ".join(out)


def _normalize_child_env(env: Dict[str, str] | None) -> Dict[str, str]:
    normalized = dict(env or {})
    pathlike_keys = {
        "JAVA_HOME", "JDK_HOME", "CODEX_BIN", "CODEX_BIN_REAL", "CODEX_HOME", "CODEX_RUNTIME_HOME", "HOME",
        "PWN_LOADER", "PWN_LIBC_PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
        "GHIDRA_MCP_HOME", "GHIDRA_MCP_XDG_CONFIG_HOME", "GHIDRA_MCP_XDG_CACHE_HOME", "GHIDRA_MCP_XDG_DATA_HOME",
        "GDB_LAUNCHER_SCRIPT", "PYGHIDRA_LAUNCHER_SCRIPT", "DIRGE_GDB_EXTRA_SITE", "DIRGE_PYGHIDRA_EXTRA_SITE",
        "GHIDRA_INSTALL_DIR", "GHIDRA_MCP_PROJECT_PATH", "GHIDRA_MCP_BIN", "GHIDRA_RUNTIME_ROOT", "GHIDRA_SESSION_ROOT",
        "PYTHON_BIN", "MCP_JSONLINE_BRIDGE", "MCP_JSONLINE_BRIDGE_LOG", "PYGHIDRA_HOTFIX_DIR",
    }
    pathlist_keys = {"LD_LIBRARY_PATH", "PWN_LD_LIBRARY_PATH", "PYTHONPATH", "PYGHIDRA_MCP_PYTHONPATH", "PATH"}
    command_keys = {"DIRGE_GDB_MCP_CMD", "DIRGE_PYGHIDRA_MCP_CMD"}
    for key, value in list(normalized.items()):
        norm_key = str(key or "").strip()
        raw = str(value)
        if norm_key in pathlike_keys:
            normalized[key] = _anchor_pathlike_value(raw, ROOT_DIR)
        elif norm_key in pathlist_keys:
            normalized[key] = os.pathsep.join(
                _anchor_pathlike_value(part, ROOT_DIR) if (part and ("/" in part or part.startswith("."))) else part
                for part in raw.split(os.pathsep)
            )
        elif norm_key in command_keys:
            normalized[key] = _normalize_command_string(raw)
    return normalized


_LOG_PATH = _normalize_child_env({"MCP_JSONLINE_BRIDGE_LOG": os.environ.get("MCP_JSONLINE_BRIDGE_LOG", "")}).get("MCP_JSONLINE_BRIDGE_LOG", "").strip() or "/tmp/project_dirge_pyghidra_bridge_fallback.log"


def _log(msg: str) -> None:
    if not _LOG_PATH:
        return
    try:
        with _LOG_LOCK:
            with open(_LOG_PATH, "a", encoding="utf-8", errors="replace") as f:
                f.write(msg.rstrip("\n") + "\n")
    except Exception:
        pass


def _read_non_empty_line(inp: BinaryIO) -> Optional[bytes]:
    while True:
        line = inp.readline()
        if line == b"":
            return None
        if line.strip(b"\r\n") == b"":
            continue
        return line


def _read_framed_message(inp: BinaryIO, first_line: bytes) -> Optional[bytes]:
    headers: Dict[bytes, bytes] = {}
    pending: Optional[bytes] = first_line

    while True:
        line = pending if pending is not None else inp.readline()
        pending = None
        if line == b"":
            return None

        stripped = line.strip(b"\r\n")
        if stripped == b"":
            break

        if b":" not in stripped:
            continue
        k, v = stripped.split(b":", 1)
        headers[k.strip().lower()] = v.strip()

    raw_len = headers.get(b"content-length")
    if raw_len is None:
        return b""

    try:
        content_len = int(raw_len.decode("ascii", errors="ignore"))
    except ValueError:
        return b""

    if content_len < 0:
        return b""

    body = inp.read(content_len)
    if len(body) != content_len:
        return b""
    return body


def _forward_jsonl_to_child(
    parent_in: BinaryIO,
    child_in: BinaryIO,
    first_line: bytes,
) -> None:
    payload = first_line.strip()
    if payload:
        _log(f"parent->child jsonl bytes={len(payload)}")
        child_in.write(payload)
        child_in.write(b"\n")
        child_in.flush()

    for line in parent_in:
        payload = line.strip()
        if not payload:
            continue
        _log(f"parent->child jsonl bytes={len(payload)}")
        child_in.write(payload)
        child_in.write(b"\n")
        child_in.flush()


def _forward_framed_to_child(
    parent_in: BinaryIO,
    child_in: BinaryIO,
    first_line: bytes,
) -> None:
    line: Optional[bytes] = first_line
    while True:
        if line is None:
            break
        msg = _read_framed_message(parent_in, line)
        if msg is None:
            break
        if msg == b"":
            line = _read_non_empty_line(parent_in)
            continue
        _log(f"parent->child framed bytes={len(msg)}")
        child_in.write(msg)
        child_in.write(b"\n")
        child_in.flush()
        line = _read_non_empty_line(parent_in)


def _detect_parent_mode(first_line: bytes) -> str:
    stripped = first_line.lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "jsonl"
    return "framed"


def _parent_to_child(
    parent_in: BinaryIO,
    child_in: BinaryIO,
    mode_box: Dict[str, str],
    mode_ready: threading.Event,
) -> None:
    try:
        first_line = _read_non_empty_line(parent_in)
        if first_line is None:
            mode_box["mode"] = "framed"
            mode_ready.set()
            try:
                child_in.close()
            except Exception:
                pass
            return

        mode = _detect_parent_mode(first_line)
        mode_box["mode"] = mode
        _log(f"detected parent mode={mode}")
        mode_ready.set()

        if mode == "jsonl":
            _forward_jsonl_to_child(parent_in, child_in, first_line)
        else:
            _forward_framed_to_child(parent_in, child_in, first_line)
    except Exception as e:
        _log(f"parent_to_child exception: {type(e).__name__}: {e}")
    finally:
        try:
            child_in.close()
        except Exception:
            pass


def _child_to_parent(
    child_out: BinaryIO,
    parent_out: BinaryIO,
    mode_box: Dict[str, str],
    mode_ready: threading.Event,
) -> None:
    try:
        mode_ready.wait(timeout=30)
        mode = mode_box.get("mode", "framed")
        _log(f"child_to_parent mode={mode}")

        for line in child_out:
            payload = line.strip()
            if not payload:
                continue
            _log(f"child->parent bytes={len(payload)}")
            if mode == "jsonl":
                parent_out.write(payload)
                parent_out.write(b"\n")
            else:
                header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
                parent_out.write(header)
                parent_out.write(payload)
            parent_out.flush()
    except Exception as e:
        _log(f"child_to_parent exception: {type(e).__name__}: {e}")
    finally:
        try:
            parent_out.flush()
        except Exception:
            pass


def _child_stderr_to_parent(stderr_in: BinaryIO, parent_err: BinaryIO) -> None:
    while True:
        chunk = stderr_in.read(4096)
        if not chunk:
            break
        _log("child_stderr: " + chunk.decode("utf-8", errors="replace").rstrip())
        try:
            parent_err.write(chunk)
            parent_err.flush()
        except Exception:
            break


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Bridge Content-Length framed MCP stdio to JSONL stdio backend."
    )
    ap.add_argument(
        "cmd",
        nargs=argparse.REMAINDER,
        help="Backend command after '--', e.g. -- pyghidra-mcp -t stdio",
    )
    args = ap.parse_args()

    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("[mcp_jsonline_bridge] missing backend command", file=sys.stderr)
        return 2

    child_env = _normalize_child_env(dict(os.environ))
    _log("bridge start cmd=" + " ".join(cmd))
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=child_env,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    mode_box: Dict[str, str] = {}
    mode_ready = threading.Event()

    t_in = threading.Thread(
        target=_parent_to_child,
        args=(sys.stdin.buffer, proc.stdin, mode_box, mode_ready),
        daemon=True,
    )
    t_out = threading.Thread(
        target=_child_to_parent,
        args=(proc.stdout, sys.stdout.buffer, mode_box, mode_ready),
        daemon=True,
    )
    t_err = threading.Thread(
        target=_child_stderr_to_parent,
        args=(proc.stderr, sys.stderr.buffer),
        daemon=True,
    )

    t_in.start()
    t_out.start()
    t_err.start()

    t_in.join()
    t_out.join()
    try:
        proc.wait(timeout=2)
    except Exception:
        proc.terminate()
        proc.wait(timeout=5)
    _log(f"bridge exit rc={proc.returncode}")
    t_err.join(timeout=1)
    return int(proc.returncode or 0)


if __name__ == "__main__":
    raise SystemExit(main())
