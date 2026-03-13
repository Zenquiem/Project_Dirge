#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple
import shlex

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CONFIG = os.path.join(ROOT_DIR, ".codex", "config.toml")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_toml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    loader = None
    try:
        import tomllib as loader  # type: ignore[attr-defined]
    except Exception:
        try:
            import tomli as loader  # type: ignore[no-redef]
        except Exception:
            return {}
    with open(path, "rb") as f:
        data = loader.load(f)
    return data if isinstance(data, dict) else {}


def _configured_servers(cfg: Dict[str, Any]) -> List[Dict[str, Any]]:
    mcp = cfg.get("mcp_servers", {})
    if not isinstance(mcp, dict):
        return []
    out: List[Dict[str, Any]] = []
    for name, raw in mcp.items():
        if not isinstance(raw, dict):
            continue
        item = {
            "name": str(name),
            "enabled": bool(raw.get("enabled", True)),
            "command": str(raw.get("command", "")).strip(),
            "args": raw.get("args", []) if isinstance(raw.get("args", []), list) else [],
            "cwd": str(raw.get("cwd", "")).strip(),
            "env": raw.get("env", {}) if isinstance(raw.get("env", {}), dict) else {},
        }
        if "startup_timeout_sec" in raw:
            try:
                item["startup_timeout_sec"] = float(raw.get("startup_timeout_sec", 0) or 0)
            except Exception:
                pass
        out.append(item)
    out.sort(key=lambda x: x["name"])
    return out


def _parse_server_names(stdout: str) -> Tuple[List[str], bool]:
    txt = (stdout or "").strip()
    if not txt:
        return [], False

    try:
        obj = json.loads(txt)
        names: List[str] = []
        if isinstance(obj, list):
            for it in obj:
                if not isinstance(it, dict):
                    continue
                name = str(it.get("name") or it.get("id") or it.get("server") or "").strip()
                if name:
                    names.append(name)
            return sorted(set(names)), True

        if isinstance(obj, dict):
            srv = obj.get("servers")
            if isinstance(srv, list):
                for it in srv:
                    if not isinstance(it, dict):
                        continue
                    name = str(it.get("name") or it.get("id") or it.get("server") or "").strip()
                    if name:
                        names.append(name)
                return sorted(set(names)), True
            if isinstance(srv, dict):
                return sorted(str(k) for k in srv.keys()), True
            if "name" in obj:
                name = str(obj.get("name", "")).strip()
                if name:
                    return [name], True
    except Exception:
        pass

    names = []
    for line in txt.splitlines():
        s = line.strip().strip("-*").strip()
        if not s:
            continue
        low = s.lower()
        if low.startswith("no mcp servers configured yet"):
            continue
        head = s.split()[0]
        if head and head[0].isalnum():
            names.append(head)
    return sorted(set(names)), False


def _parse_server_entries(stdout: str) -> List[Dict[str, Any]]:
    txt = (stdout or "").strip()
    if not txt:
        return []

    try:
        obj = json.loads(txt)
    except Exception:
        return []

    items: List[Dict[str, Any]] = []
    if isinstance(obj, list):
        items = [x for x in obj if isinstance(x, dict)]
    elif isinstance(obj, dict):
        srv = obj.get("servers")
        if isinstance(srv, list):
            items = [x for x in srv if isinstance(x, dict)]
        elif isinstance(srv, dict):
            for k, v in srv.items():
                if isinstance(v, dict):
                    entry = dict(v)
                    entry.setdefault("name", str(k))
                    items.append(entry)
        elif isinstance(obj.get("name"), str):
            items = [obj]

    out: List[Dict[str, Any]] = []
    for it in items:
        cfg_candidates: List[Dict[str, Any]] = [it]
        for key in ("configured_params", "config", "resolved", "params", "server_config"):
            v = it.get(key)
            if isinstance(v, dict):
                cfg_candidates.append(v)

        cfg = it
        for cand in cfg_candidates:
            if any(k in cand for k in ("command", "args", "cwd", "env")):
                cfg = cand
                break

        name = str(it.get("name") or it.get("id") or it.get("server") or cfg.get("name") or "").strip()
        if not name:
            continue
        args = cfg.get("args", []) if isinstance(cfg.get("args", []), list) else []
        env = cfg.get("env", {}) if isinstance(cfg.get("env", {}), dict) else {}
        enabled_raw = it.get("enabled", cfg.get("enabled", True))
        enabled = bool(enabled_raw)
        out.append(
            {
                "name": name,
                "enabled": enabled,
                "command": str(cfg.get("command", "")).strip(),
                "args": args,
                "cwd": str(cfg.get("cwd", "")).strip(),
                "env": env,
                "source": "codex_registry",
            }
        )

    dedup: Dict[str, Dict[str, Any]] = {}
    for it in out:
        key = str(it.get("name", "")).strip().lower()
        if not key:
            continue
        prev = dedup.get(key)
        if prev is None:
            dedup[key] = it
            continue
        prev_score = 1 if str(prev.get("command", "")).strip() else 0
        cur_score = 1 if str(it.get("command", "")).strip() else 0
        if cur_score >= prev_score:
            dedup[key] = it
    return [dedup[k] for k in sorted(dedup.keys())]


def _merge_server_cfg(configured: List[Dict[str, Any]], runtime: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}

    for srv in configured:
        if not isinstance(srv, dict):
            continue
        name = str(srv.get("name", "")).strip()
        if not name:
            continue
        merged[name.lower()] = dict(srv)

    for srv in runtime:
        if not isinstance(srv, dict):
            continue
        name = str(srv.get("name", "")).strip()
        if not name:
            continue
        key = name.lower()
        base = merged.get(key)
        if base is None:
            base = {
                "name": name,
                "enabled": bool(srv.get("enabled", True)),
                "command": str(srv.get("command", "")).strip(),
                "args": srv.get("args", []) if isinstance(srv.get("args", []), list) else [],
                "cwd": str(srv.get("cwd", "")).strip(),
                "env": srv.get("env", {}) if isinstance(srv.get("env", {}), dict) else {},
                "source": "runtime_only",
            }
            merged[key] = base
            continue

        cmd = str(srv.get("command", "")).strip()
        if cmd:
            base["command"] = cmd
        args = srv.get("args", [])
        if isinstance(args, list) and args:
            base["args"] = args
        cwd = str(srv.get("cwd", "")).strip()
        if cwd:
            base["cwd"] = cwd
        env = srv.get("env", {})
        if isinstance(env, dict) and env:
            base["env"] = env
        base["enabled"] = bool(srv.get("enabled", base.get("enabled", True)))
        base["source"] = "merged_runtime"

    out = list(merged.values())
    out.sort(key=lambda x: str(x.get("name", "")))
    return out


def _run_cmd(cmd: List[str], timeout_sec: float) -> Dict[str, Any]:
    p = subprocess.run(
        cmd,
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        check=False,
        timeout=max(1.0, float(timeout_sec)),
    )
    return {
        "cmd": cmd,
        "rc": int(p.returncode),
        "stdout": p.stdout or "",
        "stderr": p.stderr or "",
    }


def _repo_anchor_path(raw: str) -> str:
    s = str(raw or "").strip()
    if not s:
        return ""
    if os.path.isabs(s) or "://" in s:
        return s
    return os.path.abspath(os.path.join(ROOT_DIR, s))


def _resolve_command(cmd: str) -> Tuple[bool, str]:
    if not cmd:
        return False, ""
    if os.path.isabs(cmd):
        return os.path.exists(cmd) and os.access(cmd, os.X_OK), cmd
    if any(sep in cmd for sep in (os.sep, "/")):
        anchored = _repo_anchor_path(cmd)
        return os.path.exists(anchored) and os.access(anchored, os.X_OK), anchored
    found = shutil.which(cmd)
    if found:
        return True, found
    if cmd in {"codex", "gdb-mcp", "pyghidra-mcp"}:
        for fb in [
            os.path.expanduser(f"~/.npm-global/bin/{cmd}"),
            os.path.expanduser(f"~/.local/bin/{cmd}"),
        ]:
            if os.path.exists(fb) and os.access(fb, os.X_OK):
                return True, fb
    return False, ""


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
            out.append(" ".join(_anchor_pathlike_value(tok, ROOT_DIR) if ((tok.startswith('./') or tok.startswith('../') or '/' in tok) and not os.path.isabs(tok)) else tok for tok in payload_parts))
            i += 2
            continue
        if (cur.startswith("./") or cur.startswith("../") or "/" in cur) and not os.path.isabs(cur):
            out[-1] = _anchor_pathlike_value(cur, ROOT_DIR)
        i += 1
    return " ".join(out)


def _normalize_repo_relative_env_value(key: str, value: str) -> str:
    pathlike_keys = {
        "JAVA_HOME", "JDK_HOME", "CODEX_BIN", "CODEX_BIN_REAL", "CODEX_HOME", "CODEX_RUNTIME_HOME", "HOME",
        "PWN_LOADER", "PWN_LIBC_PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
        "GHIDRA_MCP_HOME", "GHIDRA_MCP_XDG_CONFIG_HOME", "GHIDRA_MCP_XDG_CACHE_HOME", "GHIDRA_MCP_XDG_DATA_HOME",
        "GDB_LAUNCHER_SCRIPT", "PYGHIDRA_LAUNCHER_SCRIPT", "DIRGE_GDB_EXTRA_SITE", "DIRGE_PYGHIDRA_EXTRA_SITE",
        "GHIDRA_INSTALL_DIR", "GHIDRA_MCP_PROJECT_PATH", "GHIDRA_MCP_BIN", "GHIDRA_RUNTIME_ROOT", "GHIDRA_SESSION_ROOT",
        "PYTHON_BIN", "MCP_JSONLINE_BRIDGE", "MCP_JSONLINE_BRIDGE_LOG", "PYGHIDRA_HOTFIX_DIR",
    }
    pathlist_keys = {"LD_LIBRARY_PATH", "PWN_LD_LIBRARY_PATH", "PYTHONPATH", "PYGHIDRA_MCP_PYTHONPATH", "PATH"}
    norm_key = str(key or "").strip()
    raw = str(value)
    if norm_key in pathlike_keys:
        return _anchor_pathlike_value(raw, ROOT_DIR)
    if norm_key in pathlist_keys:
        return os.pathsep.join(_anchor_pathlike_value(part, ROOT_DIR) if (part and ('/' in part or part.startswith('.'))) else part for part in raw.split(os.pathsep))
    if norm_key in {"DIRGE_GDB_MCP_CMD", "DIRGE_PYGHIDRA_MCP_CMD"}:
        return _normalize_command_string(raw)
    return raw


def _normalize_launcher_argv(command: str, args: List[Any]) -> tuple[str, List[str]]:
    cmd = str(command or "").strip()
    argv = [str(x) for x in (args or [])]
    if not cmd:
        return "", []
    if any(sep in cmd for sep in (os.sep, "/")) and not os.path.isabs(cmd):
        cmd = _repo_anchor_path(cmd)

    script_flags = {"-W", "-X", "--check-hash-based-pycs", "-O"}
    i = 0
    while i < len(argv):
        cur = argv[i]
        if cur in {"-m", "-S"}:
            i += 2
            continue
        if cur in script_flags:
            i += 2
            continue
        if (cur.startswith("./") or cur.startswith("../") or "/" in cur) and not os.path.isabs(cur):
            argv[i] = _repo_anchor_path(cur)
        break
    return cmd, argv


def _resolve_server_launcher(server_name: str, server_cfg: Dict[str, Any]) -> Tuple[bool, str]:
    name = str(server_name or server_cfg.get("name", "")).strip().lower()
    cmd, argv = _normalize_launcher_argv(server_cfg.get("command", ""), server_cfg.get("args", []))
    ok, resolved = _resolve_command(cmd)
    if ok:
        if name in {"pyghidra-mcp", "pyghidra_bridge"} and argv:
            bridge = argv[0]
            if (bridge.startswith("./") or bridge.startswith("../") or "/" in bridge) and not os.path.exists(bridge):
                return False, resolved
        return True, resolved
    if name == "gdb":
        fallback_ok, fallback = _resolve_command("gdb-mcp")
        if fallback_ok:
            return True, fallback
    if name in {"pyghidra-mcp", "pyghidra_bridge"}:
        fallback_ok, fallback = _resolve_command("pyghidra-mcp")
        if fallback_ok:
            return True, fallback
    return False, resolved or cmd


def _probe_tool_for_server(server_name: str) -> str:
    name = str(server_name or "").strip().lower()
    if not name:
        return ""
    if name in {"pyghidra-mcp", "pyghidra_bridge"}:
        return "list_project_binaries"
    if name == "gdb":
        return "gdb_list_sessions"
    return ""


def _probe_server_aliases(server_name: str) -> List[str]:
    name = str(server_name or "").strip().lower()
    if name in {"pyghidra-mcp", "pyghidra_bridge"}:
        return ["pyghidra-mcp", "pyghidra_bridge"]
    return [name] if name else []


def _find_server_cfg(servers: List[Dict[str, Any]], server_name: str) -> Dict[str, Any]:
    wanted = _probe_server_aliases(server_name)
    wanted_set = {x for x in wanted if x}
    for srv in servers:
        name = str(srv.get("name", "")).strip().lower()
        if name in wanted_set:
            return srv
    return {}


def _extract_arg_value(args: List[Any], key: str, default: str = "") -> str:
    if not isinstance(args, list):
        return default
    k = str(key or "").strip()
    if not k:
        return default
    for i, raw in enumerate(args):
        s = str(raw or "").strip()
        if not s:
            continue
        if s == k and (i + 1) < len(args):
            v = str(args[i + 1] or "").strip()
            if v:
                return v
        prefix = k + "="
        if s.startswith(prefix):
            v = s[len(prefix) :].strip()
            if v:
                return v
    return default


def _merge_java_tool_opts(raw: str, opt: str) -> str:
    base = str(raw or "").strip()
    want = str(opt or "").strip()
    if not want:
        return base
    if want in base:
        return base
    return (base + " " + want).strip() if base else want


def _has_live_pyghidra(project_path: str) -> bool:
    p = str(project_path or "").strip()
    if not p:
        return False
    try:
        ps = subprocess.run(
            ["ps", "-eo", "pid=,args="],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            check=False,
            timeout=1.5,
        )
    except Exception:
        return False
    if int(ps.returncode) != 0:
        return False
    for line in str(ps.stdout or "").splitlines():
        s = str(line).strip()
        if not s:
            continue
        low = s.lower()
        if ("pyghidra-mcp" not in low) and ("mcp_jsonline_bridge.py" not in low):
            continue
        if p in s:
            return True
    return False


def _remove_stale_project_locks(project_path: str, project_name: str) -> List[str]:
    removed: List[str] = []
    base = str(project_path or "").strip()
    name = str(project_name or "").strip()
    if (not base) or (not name):
        return removed
    if _has_live_pyghidra(base):
        return removed
    for fn in (f"{name}.lock", f"{name}.lock~"):
        p = os.path.join(base, fn)
        try:
            if os.path.exists(p):
                os.unlink(p)
                removed.append(os.path.relpath(p, ROOT_DIR))
        except Exception:
            continue
    return removed


def _discover_java_home() -> Dict[str, Any]:
    for cand in [os.environ.get("JAVA_HOME", ""), os.environ.get("JDK_HOME", ""), os.path.join(ROOT_DIR, ".tools", "jdk"), os.path.join(ROOT_DIR, ".tools", "java"), "/usr/lib/jvm"]:
        if not cand:
            continue
        if os.path.isdir(cand) and os.path.basename(cand) in {"jdk", "java"}:
            try:
                children = sorted(os.listdir(cand), reverse=True)
            except Exception:
                children = []
            for child in children:
                path = os.path.join(cand, child)
                if os.path.isfile(os.path.join(path, "bin", "java")):
                    return {"path": path, "meets_min": True}
        if os.path.isfile(os.path.join(cand, "bin", "java")):
            return {"path": cand, "meets_min": True}
    return {"path": "", "meets_min": False}


def _normalize_server_env(env_cfg: Dict[str, Any], cwd: str) -> Dict[str, str]:
    env = os.environ.copy()
    path_keys = {
        "CODEX_BIN", "CODEX_BIN_REAL", "CODEX_HOME", "CODEX_RUNTIME_HOME", "HOME",
        "PWN_LOADER", "PWN_LIBC_PATH", "PWN_LD_LIBRARY_PATH", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
        "XDG_DATA_HOME", "GHIDRA_MCP_HOME", "GHIDRA_MCP_XDG_CONFIG_HOME", "GHIDRA_MCP_XDG_CACHE_HOME",
        "GHIDRA_MCP_XDG_DATA_HOME", "GDB_LAUNCHER_SCRIPT", "PYGHIDRA_LAUNCHER_SCRIPT",
        "DIRGE_GDB_EXTRA_SITE", "DIRGE_PYGHIDRA_EXTRA_SITE", "GHIDRA_INSTALL_DIR",
        "GHIDRA_MCP_PROJECT_PATH", "PYTHON_BIN", "MCP_JSONLINE_BRIDGE", "MCP_JSONLINE_BRIDGE_LOG",
    }
    for k, v in (env_cfg or {}).items():
        key = str(k).strip()
        if not key:
            continue
        val = _normalize_repo_relative_env_value(key, str(v)) if key in path_keys else str(v)
        env[key] = val
    return env


def _run_gdb_cli_probe(server_cfg: Dict[str, Any], probe_timeout_sec: float, probe_label: str) -> Dict[str, Any]:
    cmd, argv = _normalize_launcher_argv(server_cfg.get("command", ""), server_cfg.get("args", []))
    ok, resolved = _resolve_server_launcher(probe_label, {**server_cfg, "command": cmd, "args": argv})
    result = {"server": probe_label, "tool": "tools/list", "ok": False, "error": "", "rc": 127, "cmd": "", "stdout_tail": "", "stderr_tail": ""}
    if not ok:
        result["error"] = f"launcher unavailable: {cmd}"
        return result
    full_cmd = [resolved, *argv]
    result["cmd"] = " ".join(full_cmd)
    cwd = _anchor_pathlike_value(str(server_cfg.get("cwd", "") or ROOT_DIR), ROOT_DIR) or ROOT_DIR
    env = _normalize_server_env(server_cfg.get("env", {}) if isinstance(server_cfg.get("env", {}), dict) else {}, cwd)
    try:
        p = subprocess.Popen(full_cmd, cwd=cwd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}) + "\n"
        tools = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
        stdout, stderr = p.communicate(init + tools, timeout=max(1.0, float(probe_timeout_sec)))
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        result["rc"] = 124
        result["error"] = "timeout"
        return result
    except Exception as e:
        result["error"] = str(e)
        return result
    result["rc"] = int(p.returncode or 0)
    result["stdout_tail"] = (stdout or "")[-1000:]
    result["stderr_tail"] = (stderr or "")[-1000:]
    if p.returncode != 0:
        result["error"] = f"mcp process exited unexpectedly: rc={p.returncode}"
        return result
    if '"id": 1' not in stdout or '"id": 2' not in stdout:
        result["error"] = "mcp initialize/tools handshake incomplete"
        return result
    result["ok"] = True
    return result


def _run_pyghidra_cli_probe(server_cfg: Dict[str, Any], probe_timeout_sec: float, probe_label: str) -> Dict[str, Any]:
    cmd, argv = _normalize_launcher_argv(server_cfg.get("command", ""), server_cfg.get("args", []))
    cmd_ok, cmd_resolved = _resolve_server_launcher(probe_label, {**server_cfg, "command": cmd, "args": argv})
    result: Dict[str, Any] = {
        "server": probe_label,
        "tool": "list_project_binaries",
        "ok": False,
        "error": "",
        "rc": 127,
        "cmd": "",
        "stdout_tail": "",
        "stderr_tail": "",
    }
    if not cmd_ok:
        result["error"] = f"launcher unavailable: {cmd}"
        return result

    probe_cmd_prefix: List[str] = [cmd_resolved or cmd]
    probe_arg_scan = list(argv)
    if "--" in probe_arg_scan:
        idx = probe_arg_scan.index("--")
        if idx > 0:
            bridge = probe_arg_scan[0]
            if (bridge.startswith("./") or bridge.startswith("../") or "/" in bridge) and not os.path.exists(bridge):
                result["error"] = f"bridge missing: {bridge}"
                return result
        if (idx + 1) < len(probe_arg_scan):
            inner_cmd_raw = str(probe_arg_scan[idx + 1] or "").strip()
            inner_ok, inner_resolved = _resolve_command(inner_cmd_raw)
            if inner_ok:
                probe_cmd_prefix = [inner_resolved or inner_cmd_raw]
                probe_arg_scan = probe_arg_scan[idx + 2 :]

    cwd = _anchor_pathlike_value(str(server_cfg.get("cwd", "") or ROOT_DIR), ROOT_DIR) or ROOT_DIR
    env_cfg = server_cfg.get("env", {}) if isinstance(server_cfg.get("env", {}), dict) else {}
    env = _normalize_server_env(env_cfg, cwd)

    project_path = _extract_arg_value(probe_arg_scan, "--project-path", str(env.get("GHIDRA_MCP_PROJECT_PATH", "")).strip())
    project_name = _extract_arg_value(probe_arg_scan, "--project-name", str(env.get("GHIDRA_MCP_PROJECT_NAME", "")).strip() or "my_project")
    env_project_path = str(os.environ.get("GHIDRA_MCP_PROJECT_PATH", "")).strip()
    env_project_name = str(os.environ.get("GHIDRA_MCP_PROJECT_NAME", "")).strip()
    if env_project_path:
        project_path = env_project_path
    if env_project_name:
        project_name = env_project_name
    project_path = _anchor_pathlike_value(project_path, ROOT_DIR)

    java = _discover_java_home()
    result["java"] = java
    if java.get("path"):
        env["JAVA_HOME"] = str(java["path"])
        env["JDK_HOME"] = str(java["path"])

    probe_cmd = list(probe_cmd_prefix)
    if len(probe_arg_scan) >= 2 and probe_arg_scan[0] == "-m":
        probe_cmd.extend(["-m", probe_arg_scan[1]])
    if project_path:
        probe_cmd.extend(["--project-path", project_path])
    if project_name:
        probe_cmd.extend(["--project-name", project_name])
    probe_cmd.append("--list-project-binaries")
    result["cmd"] = " ".join(probe_cmd)

    env["JAVA_TOOL_OPTIONS"] = _merge_java_tool_opts(env.get("JAVA_TOOL_OPTIONS", ""), "-Djava.awt.headless=true")
    env.setdefault("DISPLAY", "")

    removed_locks = _remove_stale_project_locks(project_path, project_name)
    if removed_locks:
        result["removed_locks"] = removed_locks

    timeout = max(3.0, float(probe_timeout_sec), float(server_cfg.get("startup_timeout_sec", 0) or 0))
    try:
        p = subprocess.run(probe_cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        result["rc"] = 124
        result["error"] = f"timeout: {e}"
        return result
    except Exception as e:
        result["rc"] = 127
        result["error"] = str(e)
        return result

    result["rc"] = int(p.returncode)
    result["stdout_tail"] = str(p.stdout or "")[-1000:]
    result["stderr_tail"] = str(p.stderr or "")[-1000:]
    if int(p.returncode) == 0:
        result["ok"] = True
    else:
        err = result["stderr_tail"].strip() or result["stdout_tail"].strip()
        result["error"] = err[-240:] if err else f"probe rc={int(p.returncode)}"
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="MCP health check for pwn-agent")
    ap.add_argument("--config", default=DEFAULT_CONFIG)
    ap.add_argument("--codex-bin", default=os.environ.get("CODEX_BIN", "codex"))
    ap.add_argument("--timeout-sec", type=float, default=8.0)
    ap.add_argument("--require", default="", help="comma-separated required server names")
    ap.add_argument(
        "--authority",
        choices=["project_config", "codex_registry"],
        default=os.environ.get("MCP_HEALTH_AUTHORITY", "project_config"),
        help="health authority source (default: project_config)",
    )
    ap.add_argument(
        "--functional-probe",
        action="store_true",
        help="run minimal functional probe via server launcher (pyghidra/gdb)",
    )
    ap.add_argument("--no-functional-probe", action="store_true")
    ap.add_argument("--probe-timeout-sec", type=float, default=12.0)
    ap.add_argument("--probe-servers", default="", help="comma-separated server names for functional probe")
    ap.add_argument(
        "--probe-nonfatal",
        action="store_true",
        help="functional probe failures only emit warnings",
    )
    ap.add_argument("--report", default="")
    ap.add_argument("--json", action="store_true", help="only print json result")
    args = ap.parse_args()

    args.config = _anchor_pathlike_value(args.config, ROOT_DIR) or DEFAULT_CONFIG
    args.codex_bin = _anchor_pathlike_value(args.codex_bin, ROOT_DIR) or args.codex_bin
    cfg = _load_toml(args.config)
    servers = _configured_servers(cfg)
    enabled_names = [s["name"] for s in servers if s.get("enabled")]
    runtime_servers: List[Dict[str, Any]] = []

    require_names = [x.strip() for x in str(args.require).split(",") if x.strip()]
    if not require_names:
        require_names = list(enabled_names)

    codex_ok, codex_resolved = _resolve_command(args.codex_bin)
    codex_exec = codex_resolved or args.codex_bin
    codex_detail: Dict[str, Any] = {
        "bin": args.codex_bin,
        "resolved": codex_resolved,
        "available": codex_ok,
    }

    listed_names: List[str] = []
    list_cmds: List[List[str]] = []
    list_errors: List[str] = []
    parse_from_json = False
    last_stdout = ""
    last_stderr = ""
    list_rc = 127

    if codex_ok:
        candidates = [
            [codex_exec, "mcp", "list", "--json"],
            [codex_exec, "mcp", "list"],
        ]
        for cmd in candidates:
            list_cmds.append(cmd)
            try:
                r = _run_cmd(cmd, timeout_sec=args.timeout_sec)
                list_rc = int(r["rc"])
                last_stdout = str(r["stdout"])
                last_stderr = str(r["stderr"])
                if list_rc == 0:
                    listed_names, parse_from_json = _parse_server_names(last_stdout)
                    if parse_from_json:
                        runtime_servers = _parse_server_entries(last_stdout)
                    if listed_names:
                        break
                else:
                    list_errors.append(f"rc={list_rc}: {' '.join(cmd)}")
            except subprocess.TimeoutExpired:
                list_errors.append(f"timeout: {' '.join(cmd)}")

    if runtime_servers:
        servers = _merge_server_cfg(servers, runtime_servers)

    codex_detail["list_cmds"] = [" ".join(x) for x in list_cmds]
    codex_detail["list_rc"] = list_rc
    codex_detail["list_parse_json"] = parse_from_json
    codex_detail["runtime_server_config_count"] = len(runtime_servers)
    if runtime_servers:
        codex_detail["runtime_server_names"] = [str(x.get("name", "")).strip() for x in runtime_servers]
    codex_detail["stderr_tail"] = last_stderr[-1000:]
    codex_detail["stdout_tail"] = last_stdout[-1000:]
    if list_errors:
        codex_detail["list_errors"] = list_errors

    authority = str(args.authority).strip() or "project_config"
    checks: List[Dict[str, Any]] = []
    listed_set = set(listed_names)
    required_set = set(require_names)
    listed_required_missing: List[str] = []
    for srv in servers:
        name = str(srv.get("name", "")).strip()
        cmd = str(srv.get("command", "")).strip()
        cmd_ok, cmd_resolved = _resolve_server_launcher(name, srv)
        enabled = bool(srv.get("enabled", True))
        required = name in required_set
        listed = name in listed_set if listed_names else False
        if required and enabled and not listed:
            listed_required_missing.append(name)
        if authority == "project_config":
            ok = enabled and cmd_ok
        else:
            ok = enabled and cmd_ok and (listed if codex_ok else False)
        if not enabled:
            ok = True
        checks.append(
            {
                "name": name,
                "enabled": enabled,
                "required": required,
                "launcher": cmd,
                "launcher_resolved": cmd_resolved,
                "launcher_exists": cmd_ok,
                "listed_by_codex": listed,
                "ok": ok,
            }
        )

    missing_required = [n for n in require_names if n not in listed_set]
    launcher_missing = [c["name"] for c in checks if c.get("required") and c.get("enabled") and (not c.get("launcher_exists"))]
    unhealthy_reasons: List[str] = []
    warnings: List[str] = []
    if not codex_ok:
        unhealthy_reasons.append("codex binary not found")
    if authority == "codex_registry":
        if codex_ok and not listed_names:
            unhealthy_reasons.append("cannot list mcp servers from codex")
        if missing_required:
            unhealthy_reasons.append(f"required servers not listed: {','.join(missing_required)}")
    else:
        if codex_ok and not listed_names:
            warnings.append("cannot list mcp servers from codex (ignored by authority=project_config)")
        if listed_required_missing:
            warnings.append(
                "required servers not listed in codex registry (ignored by authority=project_config): "
                + ",".join(sorted(set(listed_required_missing)))
            )
    if launcher_missing:
        unhealthy_reasons.append(f"required server launcher missing: {','.join(launcher_missing)}")

    probe_enabled = (not bool(args.no_functional_probe)) and (bool(args.functional_probe) or authority == "project_config")
    probe_timeout_sec = max(3.0, float(args.probe_timeout_sec or 12.0))
    probe_names = [x.strip() for x in str(args.probe_servers or "").split(",") if x.strip()]
    if not probe_names:
        probe_names = list(require_names)
    probe_results: List[Dict[str, Any]] = []
    probe_failures: List[str] = []
    if probe_enabled:
        for name in probe_names:
            tool_name = _probe_tool_for_server(name)
            if not tool_name:
                probe_results.append(
                    {
                        "server": name,
                        "tool": "",
                        "ok": False,
                        "skipped": True,
                        "error": "unsupported probe server",
                    }
                )
                continue
            if tool_name == "list_project_binaries":
                srv_cfg = _find_server_cfg(servers, name)
                if not srv_cfg:
                    item = {
                        "server": name,
                        "tool": tool_name,
                        "ok": False,
                        "error": "server config not found for pyghidra probe",
                    }
                else:
                    item = _run_pyghidra_cli_probe(
                        server_cfg=srv_cfg,
                        probe_timeout_sec=probe_timeout_sec,
                        probe_label=name,
                    )
                probe_results.append(item)
                if not bool(item.get("ok", False)):
                    probe_failures.append(f"{name}.{tool_name}: {item.get('error', 'probe failed')}")
                continue

            srv_cfg = _find_server_cfg(servers, name)
            if not srv_cfg:
                item = {"server": name, "tool": tool_name, "ok": False, "error": "server config not found for gdb probe"}
            else:
                item = _run_gdb_cli_probe(server_cfg=srv_cfg, probe_timeout_sec=probe_timeout_sec, probe_label=name)
            probe_results.append(item)
            if not bool(item.get("ok", False)):
                probe_failures.append(f"{name}.{tool_name}: {item.get('error', 'probe failed')}")

    if probe_failures:
        msg = "functional probe failed: " + "; ".join(probe_failures[:3])
        if bool(args.probe_nonfatal):
            warnings.append(msg)
        else:
            unhealthy_reasons.append(msg)

    healthy = len(unhealthy_reasons) == 0

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.report:
        report_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        report_abs = os.path.join(ROOT_DIR, "artifacts", "reports", f"health_mcp_{ts}.json")
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)

    report = {
        "generated_utc": utc_now(),
        "healthy": healthy,
        "reasons": unhealthy_reasons,
        "config_path": os.path.relpath(os.path.abspath(args.config), ROOT_DIR) if os.path.exists(args.config) else args.config,
        "authority": authority,
        "required_servers": require_names,
        "configured_enabled_servers": enabled_names,
        "listed_servers": listed_names,
        "codex": codex_detail,
        "servers": checks,
        "warnings": warnings,
        "functional_probe": {
            "enabled": probe_enabled,
            "nonfatal": bool(args.probe_nonfatal),
            "timeout_sec": probe_timeout_sec,
            "servers": probe_names,
            "results": probe_results,
            "failures": probe_failures,
        },
    }

    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    out = {
        "healthy": healthy,
        "report": os.path.relpath(report_abs, ROOT_DIR),
        "authority": authority,
        "required_servers": require_names,
        "listed_servers": listed_names,
        "reasons": unhealthy_reasons,
        "warnings": warnings,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
