#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict


def _send(obj: Dict[str, Any]) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _text_response(req_id: Any, text: str) -> Dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "content": [
                {"type": "text", "text": text},
            ]
        },
    }


def _mapping_text(binary_abs: str) -> str:
    base = int(str(os.environ.get("DIRGE_FAKE_GDB_MAP_BASE", "0x400000") or "0x400000"), 16)
    text_start = base
    text_end = base + 0x1000
    exec_start = base + 0x1000
    exec_end = base + 0x2000
    return (
        "Mapped address spaces:\n\n"
        "          Start Addr           End Addr       Size     Offset  Perms  objfile\n"
        f"            {hex(text_start)}           {hex(text_end)}     0x1000        0x0  r--p   {binary_abs}\n"
        f"            {hex(exec_start)}           {hex(exec_end)}     0x1000     0x1000  r-xp   {binary_abs}\n"
    )


def _stack_text() -> str:
    raw = str(os.environ.get("DIRGE_FAKE_GDB_STACK_TEXT", "")).strip()
    if raw:
        return raw.replace("\\n", "\n") + ("\n" if not raw.endswith("\\n") else "")
    return (
        "0x7fffffffdc20: 0x0000000000000000 0x3144613044613943\n"
        "0x7fffffffdc30: 0x6144336144326144 0x4436614435614434\n"
    )


def _env_multiline(name: str, default: str) -> str:
    raw = str(os.environ.get(name, "")).strip()
    if raw:
        text = raw.replace("\\n", "\n")
        return text if text.endswith("\n") else text + "\n"
    return default


def main() -> int:
    fake_session = os.environ.get("DIRGE_FAKE_GDB_SESSION_ID", "fake-session")
    binary_raw = os.environ.get("DIRGE_FAKE_GDB_BINARY", "")
    binary_abs = os.path.abspath(binary_raw) if binary_raw else ""
    boot_rip = os.environ.get("DIRGE_FAKE_GDB_BOOT_RIP", "0x401040")
    crash_rip = os.environ.get("DIRGE_FAKE_GDB_CRASH_RIP", "0x401170")
    signal_text = os.environ.get("DIRGE_FAKE_GDB_SIGNAL", "SIGSEGV")

    for raw in sys.stdin:
        line = str(raw or "").strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        method = req.get("method")
        req_id = req.get("id")

        if method == "initialize":
            _send(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {},
                        "serverInfo": {"name": "fake-gdb-mcp", "version": "0.1"},
                    },
                }
            )
            continue

        if method == "notifications/initialized":
            continue

        if method != "tools/call":
            _send(_text_response(req_id, ""))
            continue

        params = req.get("params", {}) if isinstance(req.get("params", {}), dict) else {}
        name = str(params.get("name", ""))
        arguments = params.get("arguments", {}) if isinstance(params.get("arguments", {}), dict) else {}
        command = str(arguments.get("command", ""))

        if name == "gdb_start":
            _send(_text_response(req_id, f"Session ID: {fake_session}"))
            continue

        if name == "gdb_terminate":
            _send(_text_response(req_id, "terminated"))
            continue

        if name != "gdb_command":
            _send(_text_response(req_id, ""))
            continue

        if command == "info proc mappings":
            _send(_text_response(req_id, _mapping_text(binary_abs)))
        elif command == "info registers":
            _send(
                _text_response(
                    req_id,
                    _env_multiline("DIRGE_FAKE_GDB_BOOT_REGS_TEXT", f"rip            {boot_rip}            {boot_rip} <_start>\n"),
                )
            )
        elif command.startswith("run < "):
            _send(
                _text_response(
                    req_id,
                    _env_multiline(
                        "DIRGE_FAKE_GDB_RUN_TEXT",
                        f"Program received signal {signal_text}, Segmentation fault.\n",
                    ),
                )
            )
        elif command == "info registers rip eip pc":
            _send(
                _text_response(
                    req_id,
                    _env_multiline(
                        "DIRGE_FAKE_GDB_CRASH_REGS_TEXT",
                        f"rip            {crash_rip}            {crash_rip} <main+58>\n",
                    ),
                )
            )
        elif command.startswith("bt"):
            _send(_text_response(req_id, _env_multiline("DIRGE_FAKE_GDB_BT_TEXT", f"#0  {crash_rip} in main ()\n")))
        elif command.startswith("x/"):
            _send(_text_response(req_id, _stack_text()))
        else:
            _send(_text_response(req_id, "ok"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
