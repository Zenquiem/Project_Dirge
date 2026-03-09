#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import select
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
GDB_MCP_CMD = [
    "/home/zenduk/桌面/mcp/GDB-MCP/.venv/bin/python",
    "server.py",
]
GDB_MCP_CWD = "/home/zenduk/桌面/mcp/GDB-MCP"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


class MCPStdioClient:
    def __init__(self, cmd: List[str], cwd: str):
        self._cmd = list(cmd)
        self._cwd = cwd
        self._proc: subprocess.Popen[str] | None = None
        self._rid = 1

    def start(self) -> None:
        self._proc = subprocess.Popen(
            self._cmd,
            cwd=self._cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        init_req = {
            "jsonrpc": "2.0",
            "id": self._rid,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "dirge-gdb-direct", "version": "0.1"},
            },
        }
        self._send(init_req)
        _ = self._recv_for_id(self._rid, timeout_sec=20.0)
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

    def close(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2.0)
        except Exception:
            try:
                self._proc.kill()
            except Exception:
                pass
        self._proc = None

    def tool_call(self, name: str, arguments: Dict[str, Any], timeout_sec: float = 20.0) -> Dict[str, Any]:
        self._rid += 1
        req = {
            "jsonrpc": "2.0",
            "id": self._rid,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        self._send(req)
        return self._recv_for_id(self._rid, timeout_sec=timeout_sec)

    def _send(self, obj: Dict[str, Any]) -> None:
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("mcp process not started")
        self._proc.stdin.write(json.dumps(obj, ensure_ascii=False) + "\n")
        self._proc.stdin.flush()

    def _recv_for_id(self, req_id: int, timeout_sec: float) -> Dict[str, Any]:
        if self._proc is None or self._proc.stdout is None:
            raise RuntimeError("mcp process not started")
        fd = self._proc.stdout.fileno()
        deadline = time.time() + max(1.0, float(timeout_sec))
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError("mcp process exited unexpectedly")
            ready, _, _ = select.select([fd], [], [], 0.2)
            if not ready:
                continue
            line = self._proc.stdout.readline()
            if not line:
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if int(obj.get("id", -1)) == int(req_id):
                return obj
        raise TimeoutError(f"mcp response timeout for id={req_id}")


def mcp_text(resp: Dict[str, Any]) -> str:
    result = resp.get("result", {}) if isinstance(resp.get("result", {}), dict) else {}
    content = result.get("content", []) if isinstance(result.get("content", []), list) else []
    out: List[str] = []
    for it in content:
        if not isinstance(it, dict):
            continue
        if str(it.get("type", "")).strip() != "text":
            continue
        txt = str(it.get("text", "") or "")
        if txt:
            out.append(txt)
    return "\n".join(out)


def parse_session_id(text: str) -> str:
    m = re.search(r"Session ID:\s*([a-zA-Z0-9\-]+)", text)
    return m.group(1).strip() if m else ""


def parse_pie_base(mappings_text: str, binary_abs: str) -> str:
    pat = re.compile(r"0x[0-9a-fA-F]+")
    for line in mappings_text.splitlines():
        if binary_abs in line and "r-x" in line:
            m = pat.search(line)
            if m:
                return m.group(0)
    for line in mappings_text.splitlines():
        if binary_abs in line:
            m = pat.search(line)
            if m:
                return m.group(0)
    return ""


def parse_rip(reg_text: str) -> str:
    m = re.search(r"\brip\s+0x([0-9a-fA-F]+)", reg_text)
    if m:
        return "0x" + m.group(1)
    return ""


def parse_signal(text: str) -> str:
    m = re.search(r"Program received signal\s+([A-Z0-9_]+)", text)
    if m:
        return m.group(1).strip()
    m = re.search(r"\b(SIGHUP|SIGINT|SIGQUIT|SIGILL|SIGTRAP|SIGABRT|SIGBUS|SIGFPE|SIGKILL|SIGSEGV|SIGPIPE|SIGALRM|SIGTERM)\b", text)
    if m:
        return m.group(1).strip()
    return ""


def parse_stack_top_qword(stack_text: str) -> str:
    for line in stack_text.splitlines():
        # Prefer the qword value after "<addr>:"; avoid matching "Console: <addr>" prefix.
        m = re.search(r"0x[0-9a-fA-F]+:\s*0x([0-9a-fA-F]+)", line)
        if m:
            return "0x" + m.group(1)
    for line in stack_text.splitlines():
        m = re.search(r":\s*(0x[0-9a-fA-F]+)", line)
        if m:
            return m.group(1)
    return ""


def _cyclic_bytes(length: int) -> bytes:
    length = max(1, int(length))
    set1 = b"abcdefghijklmnopqrstuvwxyz"
    set2 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    set3 = b"0123456789"
    out = bytearray()
    for a in set1:
        for b in set2:
            for c in set3:
                out.extend((a, b, c))
                if len(out) >= length:
                    return bytes(out[:length])
    # 理论上不会走到这里（26*26*10*3 > 20K）
    while len(out) < length:
        out.extend(b"Aa0")
    return bytes(out[:length])


def _cyclic_find_offset(value_hex: str, max_len: int) -> int:
    v = hex_to_int(value_hex)
    if v <= 0:
        return -1
    pat = _cyclic_bytes(max_len + 16)
    b8 = int(v).to_bytes(8, byteorder="little", signed=False)
    idx = pat.find(b8)
    if idx >= 0:
        return int(idx)
    b4 = b8[:4]
    idx = pat.find(b4)
    if idx >= 0:
        return int(idx)
    return -1


def compute_pc_offset(rip: str, pie_base: str) -> str:
    rv = hex_to_int(rip)
    pv = hex_to_int(pie_base)
    if rv <= 0 or pv <= 0:
        return ""
    if rv < pv:
        return ""
    off = rv - pv
    # 限制到可执行映射内的合理偏移，避免 ld.so 起始点误判。
    if off <= 0 or off > 0x2000000:
        return ""
    return hex(off)


def hex_to_int(x: str) -> int:
    try:
        return int(str(x).strip(), 16)
    except Exception:
        return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Direct GDB MCP probe for gdb_evidence stage")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--session-id", required=True)
    ap.add_argument("--loop", type=int, required=True)
    ap.add_argument("--timeout-sec", type=float, default=15.0)
    args = ap.parse_args()

    state = load_json(args.state)
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge", {}), dict) else {}
    binary_rel = str(challenge.get("binary_path", "")).strip()
    if not binary_rel:
        print("[gdb_direct_probe] missing challenge.binary_path", file=sys.stderr)
        return 2
    binary_abs = binary_rel if os.path.isabs(binary_rel) else os.path.abspath(os.path.join(ROOT_DIR, binary_rel))
    if not os.path.exists(binary_abs):
        print(f"[gdb_direct_probe] binary not found: {binary_abs}", file=sys.stderr)
        return 2

    sid = str(args.session_id).strip()
    loop_idx = max(1, int(args.loop))
    timeout_sec = max(3.0, float(args.timeout_sec))

    raw_rel = f"artifacts/gdb/gdb_raw_{sid}_{loop_idx:02d}_direct.json"
    summary_rel = f"artifacts/gdb/gdb_summary_{sid}_{loop_idx:02d}_direct.json"
    clusters_rel = f"artifacts/gdb/gdb_clusters_{sid}_{loop_idx:02d}_direct.json"
    raw_abs = os.path.join(ROOT_DIR, raw_rel)
    summary_abs = os.path.join(ROOT_DIR, summary_rel)
    clusters_abs = os.path.join(ROOT_DIR, clusters_rel)
    os.makedirs(os.path.dirname(raw_abs), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, "artifacts", "inputs"), exist_ok=True)

    cyclic_len = 320
    cyclic_bytes = _cyclic_bytes(cyclic_len)
    input_rel = f"artifacts/inputs/{sid}_l{loop_idx:02d}_gdb_cyclic.bin"
    input_abs = os.path.join(ROOT_DIR, input_rel)
    with open(input_abs, "wb") as f:
        f.write(cyclic_bytes)

    client = MCPStdioClient(GDB_MCP_CMD, GDB_MCP_CWD)
    session_id = ""
    cmd_outputs: List[Dict[str, Any]] = []

    try:
        client.start()
        r = client.tool_call("gdb_start", {}, timeout_sec=timeout_sec)
        t = mcp_text(r)
        session_id = parse_session_id(t)
        cmd_outputs.append({"tool": "gdb_start", "args": {}, "text": t})
        if not session_id:
            raise RuntimeError("failed to get gdb session_id")

        boot_commands = [
            "set pagination off",
            "set confirm off",
            f"file {binary_abs}",
            "starti",
            "info proc mappings",
            "info registers",
        ]
        for c in boot_commands:
            rr = client.tool_call("gdb_command", {"session_id": session_id, "command": c}, timeout_sec=timeout_sec)
            cmd_outputs.append({"tool": "gdb_command", "args": {"command": c}, "text": mcp_text(rr)})

        probe_commands = [
            f"run < {input_abs}",
            "info registers",
            "bt 8",
            "x/24gx $rsp",
        ]
        for c in probe_commands:
            rr = client.tool_call("gdb_command", {"session_id": session_id, "command": c}, timeout_sec=timeout_sec)
            cmd_outputs.append({"tool": "gdb_command", "args": {"command": c}, "text": mcp_text(rr)})

        _ = client.tool_call("gdb_terminate", {"session_id": session_id}, timeout_sec=8.0)
    except Exception as e:
        cmd_outputs.append({"tool": "error", "args": {}, "text": str(e)})
    finally:
        client.close()

    mappings_txt = ""
    run_txt = ""
    regs_txt = ""
    bt_txt = ""
    stack_txt = ""
    for it in cmd_outputs:
        if it.get("tool") != "gdb_command":
            continue
        c = str(it.get("args", {}).get("command", ""))
        t = str(it.get("text", ""))
        if c == "info proc mappings":
            mappings_txt = t
        elif c.startswith("run < "):
            run_txt = t
        elif c == "info registers":
            if parse_rip(t):
                regs_txt = t
            elif (not regs_txt) and t.strip():
                regs_txt = t
        elif c.startswith("bt"):
            bt_txt = t
        elif c.startswith("x/"):
            stack_txt = t

    pie_base = parse_pie_base(mappings_txt, binary_abs)
    rip = parse_rip(regs_txt)
    stack_top = parse_stack_top_qword(stack_txt)
    signal = parse_signal(run_txt) or parse_signal(bt_txt) or parse_signal(regs_txt) or "UNKNOWN"
    pc_offset = compute_pc_offset(rip, pie_base)
    if not pc_offset:
        pc_offset = "0x0"
    offset_to_rip = _cyclic_find_offset(rip, cyclic_len)
    offset_source = "rip"
    if offset_to_rip < 0:
        offset_to_rip = _cyclic_find_offset(stack_top, cyclic_len)
        offset_source = "rsp"
    control_rip = bool(offset_to_rip >= 0)
    if not control_rip:
        offset_to_rip = 0

    input_id = f"input_{loop_idx:02d}_cyclic"
    evidence_id = f"evidence_{loop_idx:02d}_cyclic"

    raw_doc = {
        "generated_utc": utc_now(),
        "session_id": sid,
        "loop": loop_idx,
        "binary_path": binary_rel,
        "cyclic_input_path": input_rel,
        "cyclic_len": cyclic_len,
        "gdb_session_id": session_id,
        "commands": cmd_outputs,
    }
    with open(raw_abs, "w", encoding="utf-8") as f:
        json.dump(raw_doc, f, ensure_ascii=False, indent=2)

    summary_doc = {
        "generated_utc": utc_now(),
        "session_id": sid,
        "loop": loop_idx,
        "binary_path": binary_rel,
        "evidence_id": evidence_id,
        "input_id": input_id,
        "gdb": {
            "rip": rip,
            "signal": signal,
            "pc_offset": pc_offset,
            "control_rip": control_rip,
            "offset_to_rip": offset_to_rip,
            "offset_source": offset_source if control_rip else "",
            "stack_top_qword": stack_top,
            "backtrace": bt_txt,
            "registers": regs_txt,
            "stack": stack_txt,
            "run_output": run_txt,
        },
        "mappings": {
            "pie_base": pie_base,
            "raw": mappings_txt,
        },
    }
    with open(summary_abs, "w", encoding="utf-8") as f:
        json.dump(summary_doc, f, ensure_ascii=False, indent=2)

    clusters_doc = {
        "generated_utc": utc_now(),
        "session_id": sid,
        "loop": loop_idx,
        "clusters": [
            {
                "cluster_id": f"cluster_{signal.lower()}" if signal else "cluster_unknown",
                "size": 1,
                "signals": [signal],
                "evidence_ids": [evidence_id],
            }
        ],
    }
    with open(clusters_abs, "w", encoding="utf-8") as f:
        json.dump(clusters_doc, f, ensure_ascii=False, indent=2)

    if not pie_base:
        print("[gdb_direct_probe] missing pie_base", file=sys.stderr)
        return 1

    state = load_json(args.state)
    dynamic = state.setdefault("dynamic_evidence", {})
    inputs = dynamic.setdefault("inputs", [])
    if not isinstance(inputs, list):
        inputs = []
        dynamic["inputs"] = inputs
    evidence = dynamic.setdefault("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
        dynamic["evidence"] = evidence
    clusters = dynamic.setdefault("clusters", [])
    if not isinstance(clusters, list):
        clusters = []
        dynamic["clusters"] = clusters

    inputs.append(
        {
            "input_id": input_id,
            "kind": "auto_cyclic",
            "path": input_rel,
            "size": cyclic_len,
            "source": "gdb_direct_probe",
            "created_utc": utc_now(),
        }
    )
    evidence.append(
        {
            "evidence_id": evidence_id,
            "input_id": input_id,
            "gdb": {
                "rip": rip,
                "signal": signal,
                "pc_offset": pc_offset,
                "control_rip": control_rip,
                "offset_to_rip": offset_to_rip,
                "offset_source": offset_source if control_rip else "",
                "stack_top_qword": stack_top,
                "backtrace": bt_txt,
                "registers": regs_txt,
                "stack": stack_txt,
            },
            "mappings": {
                "pie_base": pie_base,
            },
            "source": "gdb_direct_probe",
            "created_utc": utc_now(),
        }
    )
    clusters.append(clusters_doc["clusters"][0])

    state.setdefault("latest_bases", {})["pie_base"] = pie_base
    caps = state.setdefault("capabilities", {})
    if control_rip:
        caps["control_rip"] = True
        caps["rip_control"] = "yes"
        caps["offset_to_rip"] = int(offset_to_rip)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["gdb_raw"] = raw_rel
    latest["gdb_summary"] = summary_rel
    latest["gdb_clusters"] = clusters_rel
    latest["gdb_input"] = input_rel

    summary = state.setdefault("summary", {})
    summary["next_actions"] = [
        "进入 exploit_l4：基于已确认偏移与基址更新本地 exp",
        "本地 verify 后按 remote_prompt 决策是否远程验证",
    ]

    save_json(args.state, state)
    print(
        json.dumps(
            {
                "ok": True,
                "pie_base": pie_base,
                "rip": rip,
                "pc_offset": pc_offset,
                "signal": signal,
                "control_rip": control_rip,
                "offset_to_rip": offset_to_rip,
                "raw": raw_rel,
                "summary": summary_rel,
                "clusters": clusters_rel,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
