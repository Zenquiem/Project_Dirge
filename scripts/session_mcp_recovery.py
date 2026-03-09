#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import sys
from typing import Any, Callable, Dict, List


def run_mcp_self_heal(
    *,
    root_dir: str,
    state_path: str,
    session_id: str,
    loop_idx: int,
    stage: str,
    reason: str,
    health_cfg: Dict[str, Any],
    codex_bin: str,
    notes: List[str] | None,
    load_json_fn: Callable[[str], Dict[str, Any]],
    save_json_fn: Callable[[str, Dict[str, Any]], None],
) -> str:
    if not bool(health_cfg.get("self_heal_enabled", True)):
        return ""
    include_gdb = bool(health_cfg.get("self_heal_include_gdb", False))
    warmup = bool(health_cfg.get("self_heal_warmup_health", True))
    warmup_timeout = float(health_cfg.get("self_heal_warmup_timeout_sec", 4.0) or 4.0)
    project_path = str(os.environ.get("GHIDRA_MCP_PROJECT_PATH", "")).strip()
    runtime_root = str(os.environ.get("GHIDRA_RUNTIME_ROOT", "")).strip()
    project_name = str(os.environ.get("GHIDRA_MCP_PROJECT_NAME", "my_project")).strip() or "my_project"
    report_rel = f"artifacts/reports/mcp_self_heal_{session_id}_{max(0, int(loop_idx)):02d}_{stage}.json"
    cmd = [
        sys.executable,
        os.path.join(root_dir, "scripts", "mcp_self_heal.py"),
        "--session-id",
        session_id,
        "--loop",
        str(max(0, int(loop_idx))),
        "--stage",
        stage,
        "--reason",
        reason,
        "--codex-bin",
        codex_bin,
        "--report",
        report_rel,
    ]
    if project_path:
        cmd.extend(["--project-path", project_path])
    if runtime_root:
        cmd.extend(["--runtime-root", runtime_root])
    if project_name:
        cmd.extend(["--project-name", project_name])
    if include_gdb:
        cmd.append("--include-gdb")
    if warmup:
        cmd.extend(["--warmup-health", "--warmup-timeout-sec", str(max(1.0, warmup_timeout))])

    p = subprocess.run(cmd, cwd=root_dir, capture_output=True, text=True, check=False)
    state = load_json_fn(state_path)
    latest = state.setdefault("artifacts_index", {}).setdefault("latest", {}).setdefault("paths", {})
    latest["mcp_self_heal_report"] = report_rel
    latest[f"mcp_self_heal_{stage}"] = report_rel
    save_json_fn(state_path, state)

    if notes is not None:
        if p.returncode == 0:
            notes.append(f"MCP self-heal executed ({stage})")
        else:
            notes.append(f"MCP self-heal failed ({stage})")
        if p.stderr and p.stderr.strip():
            notes.append(f"MCP self-heal stderr: {p.stderr.strip()[:180]}")
    return report_rel
