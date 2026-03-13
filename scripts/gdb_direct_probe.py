#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import select
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.capability_engine import infer_capabilities, write_capability_report
from core.gdb_evidence_utils import (
    abi_info as _abi_info,
    compute_pc_offset,
    cyclic_bytes as _cyclic_bytes,
    cyclic_find_offset as _cyclic_find_offset,
    infer_static_stack_smash_offset,
    parse_fault_address,
    parse_pie_base,
    parse_rip,
    parse_signal,
    parse_stack_top_qword,
    parse_stack_words,
    recover_offset_hints,
    stack_probe_command as _stack_probe_command,
)
from core.stdin_seed_utils import detect_cyclic_window, select_seed_input

DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
LEGACY_GDB_MCP_CMD = ["/home/zenduk/桌面/mcp/GDB-MCP/.venv/bin/python", "server.py"]
LEGACY_GDB_MCP_CWD = "/home/zenduk/桌面/mcp/GDB-MCP"

_PYTHON_FLAGS_WITH_VALUE = {
    "-W",
    "-X",
    "--check-hash-based-pycs",
    "--help-env",
    "--help-xoptions",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _state_load_retries() -> int:
    return 3


def load_json(path: str) -> Dict[str, Any]:
    last_err: Exception | None = None
    for _ in range(_state_load_retries()):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            last_err = e
            time.sleep(0.05)
        except Exception:
            raise
    if last_err is not None:
        raise last_err
    return {}


def save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp-{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


class MCPStdioClient:
    def __init__(self, cmd: List[str], cwd: str):
        self._cmd = list(cmd)
        self._cwd = str(cwd or "").strip()
        self._proc: subprocess.Popen[str] | None = None
        self._rid = 1

    def start(self) -> None:
        self._proc = subprocess.Popen(
            self._cmd,
            cwd=self._cwd or None,
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

    def tools_list(self, timeout_sec: float = 20.0) -> Dict[str, Any]:
        self._rid += 1
        req = {"jsonrpc": "2.0", "id": self._rid, "method": "tools/list", "params": {}}
        self._send(req)
        return self._recv_for_id(self._rid, timeout_sec=timeout_sec)

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


def _repo_anchor(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        return ""
    if os.path.isabs(raw):
        return os.path.abspath(raw)
    return os.path.abspath(os.path.join(ROOT_DIR, raw))


def _looks_like_python(cmd0: str) -> bool:
    name = os.path.basename(str(cmd0 or "").strip()).lower()
    return name.startswith("python") or name in {"py", "pypy", "pypy3"}


def _normalize_command_tokens(tokens: List[str]) -> List[str]:
    if not tokens:
        return []
    out = list(tokens)
    start_idx = 0
    if out[0] in {"env", "/usr/bin/env"}:
        if len(out) >= 3 and out[1] == "-S":
            split_tokens = shlex.split(out[2])
            norm = _normalize_command_tokens(split_tokens)
            joined = " ".join(shlex.quote(x) if any(c.isspace() for c in x) else x for x in norm)
            return [out[0], "-S", joined]
        start_idx = 1
    if len(out) <= start_idx:
        return out
    if _looks_like_python(out[start_idx]):
        idx = start_idx + 1
        while idx < len(out):
            tok = out[idx]
            if tok == "-m":
                return out
            if tok.startswith("-"):
                if tok in _PYTHON_FLAGS_WITH_VALUE:
                    idx += 2
                else:
                    idx += 1
                continue
            out[idx] = _repo_anchor(tok)
            return out
    for idx in range(start_idx + 1, len(out)):
        tok = out[idx]
        if tok.startswith("-"):
            continue
        out[idx] = _repo_anchor(tok)
        return out
    return out


def _legacy_gdb_mcp_available() -> bool:
    cmd0 = str((LEGACY_GDB_MCP_CMD or [""])[0]).strip()
    cwd = str(LEGACY_GDB_MCP_CWD or "").strip()
    return bool(cmd0 and cwd and os.path.isfile(cmd0) and os.access(cmd0, os.X_OK) and os.path.isdir(cwd))


def gdb_mcp_cmd() -> List[str]:
    override = str(os.environ.get("DIRGE_GDB_MCP_CMD", "")).strip()
    if override:
        return _normalize_command_tokens(shlex.split(override))
    path_bin = shutil.which("gdb-mcp")
    if path_bin:
        return [path_bin]
    home = str(os.environ.get("HOME", "~")).strip() or "~"
    user_local = os.path.expanduser(os.path.join(home, ".local", "bin", "gdb-mcp"))
    if os.path.isfile(user_local) and os.access(user_local, os.X_OK):
        return [user_local]
    if _legacy_gdb_mcp_available():
        return list(LEGACY_GDB_MCP_CMD)
    return []


def gdb_mcp_cwd() -> str:
    override = str(os.environ.get("DIRGE_GDB_MCP_CWD", "")).strip()
    if override:
        return _repo_anchor(override)
    cmd = gdb_mcp_cmd()
    if len(cmd) == 1:
        return ""
    if _legacy_gdb_mcp_available() and cmd == list(LEGACY_GDB_MCP_CMD):
        return LEGACY_GDB_MCP_CWD
    return ""


def _cyclic_window_from_input(stdin_bytes: bytes) -> Dict[str, Any]:
    return detect_cyclic_window(stdin_bytes, cyclic_factory=_cyclic_bytes, pattern_span=8192, min_window=4)


def _select_direct_gdb_stdin(search_dirs: Iterable[str] | None = None) -> Tuple[bytes, str, str, int]:
    return select_seed_input(
        file_env="DIRGE_GDB_DIRECT_STDIN_FILE",
        hex_env="DIRGE_GDB_DIRECT_STDIN_HEX",
        text_env="DIRGE_GDB_DIRECT_STDIN_TEXT",
        auto_len_env="DIRGE_GDB_DIRECT_CYCLIC_LEN",
        cyclic_factory=_cyclic_bytes,
        root_dir=ROOT_DIR,
        search_dirs=search_dirs,
        error_prefix="gdb_direct_stdin",
        auto_len_default=320,
        auto_len_min=32,
        auto_len_max=8192,
    )


def _response_text(resp: Dict[str, Any]) -> str:
    result = resp.get("result", {}) if isinstance(resp.get("result"), dict) else {}
    content = result.get("content", []) if isinstance(result.get("content"), list) else []
    out: List[str] = []
    for it in content:
        if not isinstance(it, dict) or str(it.get("type", "")).strip() != "text":
            continue
        txt = str(it.get("text", "") or "")
        if not txt:
            continue
        stripped = txt.strip()
        if stripped.startswith("{"):
            try:
                obj = json.loads(stripped)
                if isinstance(obj, dict):
                    if isinstance(obj.get("output"), str):
                        txt = obj["output"]
                    elif isinstance(obj.get("session_id"), str):
                        txt = obj["session_id"]
            except Exception:
                pass
        out.append(txt)
    return "\n".join(out)


def parse_session_id(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return ""
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            if isinstance(obj, dict):
                sid = str(obj.get("session_id", "") or "").strip()
                if sid:
                    return sid
                session = obj.get("session", {}) if isinstance(obj.get("session"), dict) else {}
                sid = str(session.get("id", "") or "").strip()
                if sid:
                    return sid
        except Exception:
            pass
    marker = "Session ID:"
    if marker in raw:
        return raw.split(marker, 1)[1].strip().split()[0]
    return ""


def _resolve_state_path(raw: str) -> str:
    path = str(raw or "").strip()
    if not path:
        return DEFAULT_STATE
    if os.path.isabs(path):
        return path
    cwd_candidate = os.path.abspath(path)
    if os.path.exists(cwd_candidate):
        return cwd_candidate
    return _repo_anchor(path)


def _safe_tools_list(client: MCPStdioClient, timeout_sec: float) -> List[str]:
    try:
        resp = client.tools_list(timeout_sec=timeout_sec)
    except Exception:
        return []
    result = resp.get("result", {}) if isinstance(resp.get("result"), dict) else {}
    tools = result.get("tools", []) if isinstance(result.get("tools"), list) else []
    out: List[str] = []
    for tool in tools:
        if isinstance(tool, dict):
            name = str(tool.get("name", "")).strip()
            if name:
                out.append(name)
    return out


def _clear_stale_offset(state: Dict[str, Any], evidence_doc: Dict[str, Any]) -> None:
    caps = state.setdefault("capabilities", {})
    caps["control_rip"] = False
    caps["rip_control"] = "no"
    caps.pop("offset_to_rip", None)
    state.setdefault("latest_bases", {}).pop("offset_to_rip", None)
    state.setdefault("io_profile", {}).pop("offset_to_rip", None)
    if isinstance(evidence_doc.get("gdb"), dict):
        evidence_doc["gdb"].pop("offset_to_rip", None)
        evidence_doc["gdb"].pop("offset_source", None)


def main() -> int:
    ap = argparse.ArgumentParser(description="Direct GDB MCP probe for gdb_evidence stage")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--session-id", required=True)
    ap.add_argument("--loop", type=int, required=True)
    ap.add_argument("--timeout-sec", type=float, default=15.0)
    args = ap.parse_args()

    state_path = _resolve_state_path(args.state)
    state = load_json(state_path)
    challenge = state.get("challenge", {}) if isinstance(state.get("challenge"), dict) else {}
    binary_rel = str(challenge.get("binary_path", "")).strip()
    if not binary_rel:
        print("[gdb_direct_probe] missing challenge.binary_path", file=sys.stderr)
        return 2
    binary_abs = binary_rel if os.path.isabs(binary_rel) else _repo_anchor(binary_rel)
    if not os.path.exists(binary_abs):
        print(f"[gdb_direct_probe] binary not found: {binary_abs}", file=sys.stderr)
        return 2

    cmd = gdb_mcp_cmd()
    cwd = gdb_mcp_cwd()
    if not cmd:
        print("[gdb_direct_probe] gdb-mcp unavailable; install `gdb-mcp` on PATH or set DIRGE_GDB_MCP_CMD", file=sys.stderr)
        return 2

    sid = str(args.session_id).strip()
    loop_idx = max(1, int(args.loop))
    timeout_sec = max(3.0, float(args.timeout_sec))
    challenge_dir = os.path.dirname(binary_abs) or ROOT_DIR
    abi = _abi_info(binary_abs)
    stack_cmd, _stack_word_size = _stack_probe_command(abi)

    raw_rel = f"artifacts/gdb/gdb_raw_{sid}_{loop_idx:02d}_direct.json"
    summary_rel = f"artifacts/gdb/gdb_summary_{sid}_{loop_idx:02d}_direct.json"
    clusters_rel = f"artifacts/gdb/gdb_clusters_{sid}_{loop_idx:02d}_direct.json"
    raw_abs = os.path.join(ROOT_DIR, raw_rel)
    summary_abs = os.path.join(ROOT_DIR, summary_rel)
    clusters_abs = os.path.join(ROOT_DIR, clusters_rel)
    os.makedirs(os.path.dirname(raw_abs), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, "artifacts", "inputs"), exist_ok=True)

    stdin_bytes, stdin_source, stdin_kind, stdin_size = _select_direct_gdb_stdin(search_dirs=[challenge_dir])
    cyclic_info = _cyclic_window_from_input(stdin_bytes)
    cyclic_len = int(stdin_size)
    input_rel = f"artifacts/inputs/{sid}_l{loop_idx:02d}_gdb_input.bin"
    input_abs = os.path.join(ROOT_DIR, input_rel)
    with open(input_abs, "wb") as f:
        f.write(stdin_bytes)

    client = MCPStdioClient(cmd, cwd)
    gdb_session_id = ""
    cmd_outputs: List[Dict[str, Any]] = []
    start_tool = "gdb_start"
    stop_tool = "gdb_terminate"

    try:
        client.start()
        tool_names = set(_safe_tools_list(client, timeout_sec))
        if {"start_binary", "gdb_command", "stop_session"}.issubset(tool_names):
            start_tool = "start_binary"
            stop_tool = "stop_session"
        start_args = {} if start_tool == "gdb_start" else {"binary_path": binary_abs, "cwd": challenge_dir}
        r = client.tool_call(start_tool, start_args, timeout_sec=timeout_sec)
        start_text = _response_text(r)
        cmd_outputs.append({"tool": start_tool, "args": start_args, "text": start_text})
        if "Unknown tool:" in start_text:
            print(f"[gdb_direct_probe] startup failed: {start_text}", file=sys.stderr)
            return 2
        gdb_session_id = parse_session_id(start_text)
        if not gdb_session_id:
            gdb_session_id = start_text.strip()
        if not gdb_session_id:
            print("[gdb_direct_probe] startup failed: missing session id", file=sys.stderr)
            return 2

        def _call_gdb(command: str) -> str:
            resp = client.tool_call("gdb_command", {"session_id": gdb_session_id, "command": command}, timeout_sec=timeout_sec)
            text = _response_text(resp)
            cmd_outputs.append({"tool": "gdb_command", "args": {"command": command}, "text": text})
            return text

        _call_gdb("set pagination off")
        _call_gdb("set confirm off")
        if start_tool == "gdb_start":
            _call_gdb(f"file {binary_abs}")
            _call_gdb("starti")
        mappings_txt = _call_gdb("info proc mappings")
        pre_regs_txt = _call_gdb("info registers")
        run_txt = _call_gdb(f"run < {input_abs}")
        regs_txt = _call_gdb("info registers rip eip pc") or pre_regs_txt
        bt_txt = _call_gdb("bt 8")
        stack_txt = _call_gdb(stack_cmd)
        _ = client.tool_call(stop_tool, {"session_id": gdb_session_id}, timeout_sec=8.0)
    except Exception as e:
        cmd_outputs.append({"tool": "error", "args": {}, "text": str(e)})
    finally:
        client.close()

    mappings_txt = next((it["text"] for it in cmd_outputs if it.get("args", {}).get("command") == "info proc mappings"), "")
    run_txt = next((it["text"] for it in cmd_outputs if str(it.get("args", {}).get("command", "")).startswith("run < ")), "")
    bt_txt = next((it["text"] for it in cmd_outputs if str(it.get("args", {}).get("command", "")).startswith("bt")), "")
    stack_txt = next((it["text"] for it in cmd_outputs if str(it.get("args", {}).get("command", "")).startswith("x/")), "")
    regs_txt = ""
    for it in cmd_outputs:
        if it.get("args", {}).get("command") == "info registers rip eip pc" and parse_rip(it.get("text", "")):
            regs_txt = it.get("text", "")
            break
    if not regs_txt:
        for it in cmd_outputs:
            if it.get("args", {}).get("command") == "info registers" and parse_rip(it.get("text", "")):
                regs_txt = it.get("text", "")

    is_pie = bool(state.get("protections", {}).get("pie")) if isinstance(state.get("protections"), dict) else False
    pie_base = parse_pie_base(mappings_txt, binary_abs)
    if not pie_base and not is_pie:
        pie_base = "0x0"
    rip = parse_rip(regs_txt)
    signal = parse_signal(run_txt) or parse_signal(bt_txt) or parse_signal(regs_txt) or "UNKNOWN"
    fault_addr = parse_fault_address("\n".join([run_txt, bt_txt, stack_txt, regs_txt]))
    pc_offset = compute_pc_offset(rip, pie_base)
    if not pc_offset and (not is_pie) and rip:
        pc_offset = rip

    allow_offset = bool(cyclic_info.get("cyclic_compatible"))
    stack_words = parse_stack_words(stack_txt, max_lines=16)
    offset_to_rip = 0
    offset_source = ""
    fault_offset_candidate = 0
    static_offset_candidate = 0
    control_rip = False
    if allow_offset:
        offset_hints = recover_offset_hints(
            value_hex=rip,
            stack_words=stack_words,
            cyclic_len=cyclic_len,
            stack_word_size=_stack_word_size,
            fault_addr=fault_addr,
            static_guess=int(infer_static_stack_smash_offset(binary_abs) or 0),
        )
        offset_to_rip = int(offset_hints.get("offset_to_rip", 0) or 0)
        offset_source = str(offset_hints.get("offset_source", "") or "")
        fault_offset_candidate = int(offset_hints.get("fault_offset_candidate", 0) or 0)
        static_offset_candidate = int(offset_hints.get("static_offset_candidate", 0) or 0)
        control_rip = bool(offset_hints.get("control_rip", False))

    raw_doc = {
        "generated_utc": utc_now(),
        "mode": "gdb_direct_probe",
        "source": "gdb_direct_probe",
        "session_id": sid,
        "loop": loop_idx,
        "binary_path": binary_rel,
        "stdin_path": input_rel,
        "stdin_source": stdin_source,
        "stdin_kind": stdin_kind,
        "gdb_session_id": gdb_session_id,
        "commands": cmd_outputs,
    }
    save_json(raw_abs, raw_doc)

    gdb_doc: Dict[str, Any] = {
        "rip": rip,
        "signal": signal,
        "fault_addr": fault_addr,
        "fault_offset_candidate": int(fault_offset_candidate) if fault_offset_candidate > 0 else 0,
        "static_offset_candidate": int(static_offset_candidate) if static_offset_candidate > 0 else 0,
        "pc_offset": pc_offset,
        "control_rip": control_rip,
        "stack_top_qword": parse_stack_top_qword(stack_txt),
        "stack_words": stack_words,
        "registers": regs_txt,
        "backtrace": bt_txt,
        "stack": stack_txt,
        "run_output": run_txt,
        "stdin_source": stdin_source,
        "stdin_kind": stdin_kind,
    }
    if control_rip:
        gdb_doc["offset_to_rip"] = int(offset_to_rip)
        gdb_doc["offset_source"] = offset_source

    summary_doc = {
        "generated_utc": utc_now(),
        "mode": "gdb_direct_probe",
        "source": "gdb_direct_probe",
        "session_id": sid,
        "loop": loop_idx,
        "binary_path": binary_rel,
        "stdin_path": input_rel,
        "stdin_source": stdin_source,
        "stdin_kind": stdin_kind,
        "gdb": gdb_doc,
        "mappings": {"pie_base": pie_base, "raw": mappings_txt},
    }
    save_json(summary_abs, summary_doc)

    clusters_doc = {
        "generated_utc": utc_now(),
        "mode": "gdb_direct_probe",
        "source": "gdb_direct_probe",
        "session_id": sid,
        "loop": loop_idx,
        "clusters": [
            {
                "cluster_id": f"cluster_{signal.lower()}" if signal else "cluster_unknown",
                "size": 1,
                "signals": [signal],
                "evidence_ids": [f"evidence_{loop_idx:02d}_direct"],
            }
        ],
    }
    save_json(clusters_abs, clusters_doc)

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

    input_doc = {
        "input_id": f"input_{loop_idx:02d}_direct",
        "kind": stdin_kind,
        "path": input_rel,
        "size": len(stdin_bytes),
        "source": "gdb_direct_probe",
        "stdin_source": stdin_source,
        "cyclic_compatible": bool(cyclic_info.get("cyclic_compatible")),
        "cyclic_offset_start": int(cyclic_info.get("cyclic_offset_start", 0) or 0),
        "cyclic_span": int(cyclic_info.get("cyclic_span", 0) or 0),
        "cyclic_window_len": int(cyclic_info.get("cyclic_window_len", 0) or 0),
        "created_utc": utc_now(),
    }
    evidence_doc = {
        "evidence_id": f"evidence_{loop_idx:02d}_direct",
        "input_id": input_doc["input_id"],
        "gdb": dict(gdb_doc),
        "mappings": {"pie_base": pie_base},
        "source": "gdb_direct_probe",
        "created_utc": utc_now(),
    }
    inputs.append(input_doc)
    evidence.append(evidence_doc)
    clusters.extend(clusters_doc["clusters"])

    state.setdefault("latest_bases", {})["pie_base"] = pie_base
    state["gdb"] = {
        "mode": "gdb_direct_probe",
        "source": "gdb_direct_probe",
        "report": summary_rel,
        "raw": raw_rel,
        "stdin_source": stdin_source,
        "stdin_kind": stdin_kind,
        "pc_offset": pc_offset,
        "offset_to_rip": int(offset_to_rip),
        "fault_offset_candidate": int(fault_offset_candidate) if fault_offset_candidate > 0 else 0,
        "static_offset_candidate": int(static_offset_candidate) if static_offset_candidate > 0 else 0,
    }
    inf = infer_capabilities(state, {})
    cap_report_rel = write_capability_report(root_dir=ROOT_DIR, session_id=sid, loop_idx=loop_idx, inf=inf)

    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["gdb_raw"] = raw_rel
    latest["gdb_summary"] = summary_rel
    latest["gdb_clusters"] = clusters_rel
    latest["gdb_input"] = input_rel
    latest["capabilities_report"] = cap_report_rel

    caps = state.setdefault("capabilities", {})
    if control_rip:
        caps["control_rip"] = True
        caps["rip_control"] = "yes"
        caps["offset_to_rip"] = int(offset_to_rip)
        state.setdefault("latest_bases", {})["offset_to_rip"] = int(offset_to_rip)
        state.setdefault("io_profile", {})["offset_to_rip"] = int(offset_to_rip)
    else:
        _clear_stale_offset(state, evidence_doc)

    save_json(state_path, state)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
