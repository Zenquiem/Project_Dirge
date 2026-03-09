#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
DEFAULT_SCHEMA = os.path.join(ROOT_DIR, "state", "schema.json")
DEFAULT_BUDGET = os.path.join(ROOT_DIR, "policy", "budget.yaml")
DEFAULT_ARTIFACT_SCAN_BYTES = 262144

sys.path.insert(0, ROOT_DIR)

from core.state_schema import load_json, validate_state_data  # noqa: E402

HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")
ABS_WIN_RE = re.compile(r"^[A-Za-z]:[\\/]")

FORBIDDEN_PATH_KEYS = {"gdb_cmds"}
FORBIDDEN_PATH_SUBSTRS = ("legacy/", "legacy\\", "gdb_cmds.used.txt")
LEGACY_MARKERS = [
    "fallback_objdump",
    "== gdb_cmds.used ==",
    "[pwn-recon]",
    "[pwn-ida-slice]",
    "[pwn-gdb-evidence]",
]


def try_load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml  # type: ignore
    except Exception:
        raise RuntimeError("PyYAML not installed. Please: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def get(d: Dict[str, Any], path: str, default=None):
    cur: Any = d
    for k in path.split("."):
        if isinstance(cur, dict) and k in cur:
            cur = cur[k]
        else:
            return default
    return cur


def is_hex(s: str) -> bool:
    return bool(HEX_RE.fullmatch((s or "").strip()))


def exists_file(path: str) -> bool:
    if not path:
        return False
    ap = path if os.path.isabs(path) else os.path.join(ROOT_DIR, path)
    return os.path.exists(ap)


def to_abs_repo_path(path: str) -> Optional[str]:
    if not path:
        return None
    ap = os.path.abspath(path if os.path.isabs(path) else os.path.join(ROOT_DIR, path))
    try:
        if os.path.commonpath([ROOT_DIR, ap]) != ROOT_DIR:
            return None
    except Exception:
        return None
    return ap


def iter_string_fields(obj: Any, path: str = "") -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            p = f"{path}.{k}" if path else str(k)
            out.extend(iter_string_fields(v, p))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            p = f"{path}[{i}]"
            out.extend(iter_string_fields(v, p))
    elif isinstance(obj, str):
        out.append((path, obj))
    return out


def is_path_like_field(field_path: str) -> bool:
    fp = field_path.lower()
    return (
        ".paths." in fp
        or fp.endswith(".path")
        or fp.endswith(".binary_path")
        or fp.endswith(".workdir")
        or fp.endswith(".summary_json")
        or fp.endswith(".raw_log")
        or fp.endswith(".gdb_raw")
        or fp.endswith(".gdb_summary")
        or fp.endswith(".ida_slice_json")
        or fp.endswith(".ida_slice_md")
        or fp.endswith(".recon_log")
        or fp.endswith(".recon_report")
        or fp.endswith(".conversation_log")
        or fp.endswith(".prompt_file")
    )


def compute_pc_offset(rip: str, pie_base: str) -> Optional[str]:
    if not (is_hex(rip) and is_hex(pie_base)):
        return None
    off = int(rip, 16) - int(pie_base, 16)
    if off >= 0:
        return f"0x{off:x}"
    return f"-0x{(-off):x}"


def fail(errs: List[str], msg: str):
    errs.append(msg)


def warn(warns: List[str], msg: str):
    warns.append(msg)


def verify_budget(state: Dict[str, Any], budget: Dict[str, Any], errs: List[str], warns: List[str]):
    per = get(budget, "per_challenge", None)
    if not isinstance(per, dict):
        warn(warns, "Budget schema: per_challenge not found (skipped budget checks)")
        return

    counters = get(state, "progress.counters", {}) or {}
    total_runs = int(counters.get("total_runs", 0) or 0)
    recon_runs = int(counters.get("recon_runs", 0) or 0)
    ida_calls = int(counters.get("ida_calls", 0) or 0)
    gdb_runs = int(counters.get("gdb_runs", 0) or 0)
    exploit_runs = int(counters.get("exploit_runs", 0) or 0)

    max_total = per.get("max_total_runs", None)
    if isinstance(max_total, int) and total_runs > max_total:
        fail(errs, f"Budget exceeded: total_runs={total_runs} > max_total_runs={max_total}")

    stage_limits = per.get("stage_limits", {}) if isinstance(per.get("stage_limits", {}), dict) else {}

    def check(key: str, used: int, label: str):
        lim = stage_limits.get(key)
        if isinstance(lim, int) and used > lim:
            fail(errs, f"Budget exceeded: {label}={used} > {key}={lim}")

    check("max_recon_runs", recon_runs, "recon_runs")
    check("max_ida_calls", ida_calls, "ida_calls")
    check("max_gdb_runs", gdb_runs, "gdb_runs")
    check("max_exploit_runs", exploit_runs, "exploit_runs")


def verify_pie_rules(state: Dict[str, Any], errs: List[str], warns: List[str], strict: bool):
    pie = get(state, "protections.pie", None)
    latest_pie_base = (get(state, "latest_bases.pie_base", "") or "").strip()

    evids = get(state, "dynamic_evidence.evidence", []) or []
    if not isinstance(evids, list):
        fail(errs, "dynamic_evidence.evidence is not a list")
        return

    if pie is True or pie is False:
        if not latest_pie_base:
            fail(errs, "latest_bases.pie_base is empty (must exist when protections.pie is true/false)")
        elif not is_hex(latest_pie_base):
            fail(errs, f"latest_bases.pie_base not hex: {latest_pie_base}")

    if not evids:
        return

    last = evids[-1] if isinstance(evids[-1], dict) else None
    if not last:
        return

    mappings = last.get("mappings") if isinstance(last.get("mappings"), dict) else {}
    gdb = last.get("gdb") if isinstance(last.get("gdb"), dict) else {}

    pie_base = (mappings.get("pie_base") or "").strip()
    rip = (gdb.get("rip") or gdb.get("pc") or "").strip()
    pc_offset = (gdb.get("pc_offset") or "").strip()

    if pie is True:
        if not (pie_base and is_hex(pie_base)):
            fail(errs, "PIE=true but last evidence mappings.pie_base missing/invalid")

        if not pc_offset:
            inferred = compute_pc_offset(rip, pie_base)
            if inferred:
                warn(warns, f"PIE=true: gdb.pc_offset missing; inferred pc_offset={inferred}")
            else:
                msg = "PIE=true: gdb.pc_offset missing and cannot infer (need hex rip + pie_base)"
                if strict:
                    fail(errs, msg)
                else:
                    warn(warns, msg)

    elif pie is False:
        if not (pie_base and is_hex(pie_base)):
            fail(errs, "PIE=false but last evidence mappings.pie_base missing/invalid")


def verify_artifacts(state: Dict[str, Any], errs: List[str], warns: List[str]):
    latest = get(state, "artifacts_index.latest.paths", {}) or {}
    if not isinstance(latest, dict):
        fail(errs, "artifacts_index.latest.paths is not a dict")
        return

    for k in [
        "recon_log",
        "recon_report",
        "ida_slice_json",
        "ida_slice_md",
        "ida_raw_log",
        "gdb_raw",
        "gdb_summary",
        "gdb_clusters",
        "gdb_mutation_manifest",
        "decision_report",
        "objective_report",
        "stage_receipt",
        "capabilities_report",
        "exp_plan_report",
        "exp_verify_report",
    ]:
        p = latest.get(k, "")
        if p and not exists_file(p):
            fail(errs, f"Missing artifact file for latest.paths.{k}: {p}")

    for k, p in latest.items():
        if isinstance(p, str) and p and (not exists_file(p)):
            fail(errs, f"Missing artifact file for latest.paths.{k}: {p}")

    evids = get(state, "dynamic_evidence.evidence", []) or []
    if not isinstance(evids, list):
        return

    start = max(0, len(evids) - 5)
    for i, ev in enumerate(evids[start:]):
        if not isinstance(ev, dict):
            continue
        paths = ev.get("paths", {}) if isinstance(ev.get("paths", {}), dict) else {}
        for kk in ["raw_log", "summary_json", "gdb_cmds"]:
            p = paths.get(kk, "")
            if p and not exists_file(p):
                fail(errs, f"Evidence[{start+i}] missing {kk}: {p}")


def collect_artifact_paths(state: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []

    latest = get(state, "artifacts_index.latest.paths", {}) or {}
    if isinstance(latest, dict):
        for k, v in latest.items():
            if isinstance(v, str) and v:
                out.append((f"artifacts_index.latest.paths.{k}", v))

    evids = get(state, "dynamic_evidence.evidence", []) or []
    if isinstance(evids, list):
        start = max(0, len(evids) - 5)
        for i, ev in enumerate(evids[start:]):
            if not isinstance(ev, dict):
                continue
            paths = ev.get("paths", {}) if isinstance(ev.get("paths", {}), dict) else {}
            for k, v in paths.items():
                if isinstance(v, str) and v:
                    out.append((f"dynamic_evidence.evidence[{start+i}].paths.{k}", v))

    return out


def verify_mcp_only(state: Dict[str, Any], errs: List[str], warns: List[str], artifact_scan_bytes: int):
    mode = (get(state, "project.mode", "") or "").strip().lower()
    if mode and mode != "mcp_only":
        fail(errs, f"project.mode must be 'mcp_only' (got: {mode})")
    elif not mode:
        warn(warns, "project.mode missing; run scripts/reset_state.sh to initialize MCP-only schema")

    for field_path, value in iter_string_fields(state):
        if not is_path_like_field(field_path):
            continue

        low = value.lower()
        for bad in FORBIDDEN_PATH_SUBSTRS:
            if bad in low:
                fail(errs, f"MCP-only violation: {field_path} contains forbidden segment '{bad}' -> {value}")
                break

        if value.startswith("/") or ABS_WIN_RE.match(value):
            ap = to_abs_repo_path(value)
            if ap is None:
                fail(errs, f"Path outside repository is not allowed for {field_path}: {value}")

    latest = get(state, "artifacts_index.latest.paths", {}) or {}
    if isinstance(latest, dict):
        for key in FORBIDDEN_PATH_KEYS:
            if key in latest and latest.get(key):
                fail(errs, f"MCP-only violation: artifacts_index.latest.paths.{key} is set ({latest.get(key)})")

    evids = get(state, "dynamic_evidence.evidence", []) or []
    if isinstance(evids, list):
        for i, ev in enumerate(evids):
            if not isinstance(ev, dict):
                continue
            paths = ev.get("paths", {}) if isinstance(ev.get("paths", {}), dict) else {}
            for key in FORBIDDEN_PATH_KEYS:
                if key in paths and paths.get(key):
                    fail(errs, f"MCP-only violation: dynamic_evidence.evidence[{i}].paths.{key} is set ({paths.get(key)})")

    scan_budget = max(4096, int(artifact_scan_bytes))
    for field_path, rel_path in collect_artifact_paths(state):
        ap = to_abs_repo_path(rel_path)
        if ap is None or not os.path.isfile(ap):
            continue
        try:
            with open(ap, "rb") as f:
                raw = f.read(scan_budget)
            text = raw.decode("utf-8", errors="ignore")
        except Exception as e:
            warn(warns, f"Artifact scan skipped for {field_path} ({rel_path}): {e}")
            continue

        for marker in LEGACY_MARKERS:
            if marker in text:
                fail(errs, f"MCP-only violation: legacy marker '{marker}' found in {field_path} ({rel_path})")
                break


def verify_state_init_tolerance(state: Dict[str, Any], errs: List[str], warns: List[str]):
    stage = (get(state, "progress.stage", "") or "").strip()
    bin_path = (get(state, "challenge.binary_path", "") or "").strip()
    if not bin_path and stage != "init":
        fail(errs, "challenge.binary_path missing")
    if not bin_path and stage == "init":
        warn(warns, "challenge.binary_path missing (allowed at init stage)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--budget", default=DEFAULT_BUDGET)
    ap.add_argument("--no-budget", action="store_true", help="skip budget checks")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    ap.add_argument("--allow-legacy", action="store_true", help="allow legacy non-MCP markers/paths")
    ap.add_argument("--artifact-scan-bytes", type=int, default=DEFAULT_ARTIFACT_SCAN_BYTES)
    args = ap.parse_args()

    errs: List[str] = []
    warns: List[str] = []

    if not os.path.exists(args.state):
        print(f"[verifier] state not found: {args.state}", file=sys.stderr)
        return 2

    if not os.path.exists(args.schema):
        print(f"[verifier] schema not found: {args.schema}", file=sys.stderr)
        return 2

    state = load_json(args.state)
    schema = load_json(args.schema)

    schema_errors = validate_state_data(schema, state)
    for e in schema_errors:
        fail(errs, f"schema: {e}")

    verify_state_init_tolerance(state, errs, warns)
    verify_artifacts(state, errs, warns)
    verify_pie_rules(state, errs, warns, strict=args.strict)

    if not args.allow_legacy:
        verify_mcp_only(state, errs, warns, artifact_scan_bytes=args.artifact_scan_bytes)
    else:
        warn(warns, "MCP-only checks disabled by --allow-legacy")

    if not args.no_budget and os.path.exists(args.budget):
        try:
            budget = try_load_yaml(args.budget)
            verify_budget(state, budget, errs, warns)
        except Exception as e:
            warn(warns, f"Budget check skipped: {e}")
    elif not args.no_budget:
        warn(warns, f"budget file not found: {args.budget} (skipped)")

    print("== verifier report ==")
    print(f"state: {args.state}")
    print(f"schema: {args.schema}")
    if not args.no_budget:
        print(f"budget: {args.budget}")
    print()

    if warns:
        print("Warnings:")
        for w in warns:
            print(f" - {w}")
        print()

    if errs:
        print("Errors:")
        for e in errs:
            print(f" - {e}")
        print("[verifier] FAIL")
        return 1

    if args.strict and warns:
        print("[verifier] FAIL (strict: warnings treated as errors)")
        return 1

    print("[verifier] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
