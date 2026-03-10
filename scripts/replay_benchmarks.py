#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import stat
import subprocess
import sys
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CASES_DIR = os.path.join(ROOT_DIR, "benchmarks", "cases")
DEFAULT_BASELINE = os.path.join(ROOT_DIR, "benchmarks", "baseline", "latest.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_case(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("case is not an object")
    return data


def load_json_or(path: str, default: Any) -> Any:
    if not path:
        return default
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _case_bool(case: Mapping[str, Any], key: str, default: bool) -> bool:
    raw = case.get(key, default)
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    low = str(raw).strip().lower()
    if low in {"1", "true", "yes", "on"}:
        return True
    if low in {"0", "false", "no", "off"}:
        return False
    return default


def _case_str_list(case: Mapping[str, Any], key: str) -> List[str]:
    raw = case.get(key, [])
    if not isinstance(raw, list):
        raise ValueError(f"{key} must be a list")
    out: List[str] = []
    for item in raw:
        s = str(item).strip()
        if not s:
            continue
        out.append(s)
    return out


def _case_env(case: Mapping[str, Any]) -> Dict[str, str]:
    raw = case.get("env", {})
    if raw in (None, ""):
        return {}
    if not isinstance(raw, dict):
        raise ValueError("env must be an object")
    env: Dict[str, str] = {}
    for k, v in raw.items():
        key = str(k).strip()
        if not key:
            continue
        env[key] = "" if v is None else str(v)
    return env


def _case_timeout_seconds(case: Mapping[str, Any], key: str) -> int | None:
    if key not in case:
        return None
    raw = case.get(key)
    if raw in (None, ""):
        return None
    try:
        value = int(raw)
    except Exception as e:
        raise ValueError(f"{key} must be an integer") from e
    if value <= 0:
        raise ValueError(f"{key} must be > 0")
    return value


def _case_expect(case: Mapping[str, Any]) -> Dict[str, Any]:
    raw = case.get("expect", {})
    if raw in (None, ""):
        return {}
    if not isinstance(raw, dict):
        raise ValueError("expect must be an object")

    out: Dict[str, Any] = {}

    for key in ("run_rc", "final_exit_code", "min_objective_score"):
        if key not in raw:
            continue
        try:
            out[key] = int(raw.get(key))
        except Exception as e:
            raise ValueError(f"expect.{key} must be an integer") from e

    if "acceptance_passed" in raw:
        val = raw.get("acceptance_passed")
        if not isinstance(val, bool):
            raise ValueError("expect.acceptance_passed must be a boolean")
        out["acceptance_passed"] = val

    if "forbid_stage_cache_hits" in raw:
        items = raw.get("forbid_stage_cache_hits")
        if not isinstance(items, list):
            raise ValueError("expect.forbid_stage_cache_hits must be a list")
        cleaned = []
        for item in items:
            s = str(item).strip()
            if s:
                cleaned.append(s)
        out["forbid_stage_cache_hits"] = cleaned

    for key in ("required_success_stages", "stage_sequence"):
        if key not in raw:
            continue
        items = raw.get(key)
        if not isinstance(items, list):
            raise ValueError(f"expect.{key} must be a list")
        cleaned = []
        for item in items:
            s = str(item).strip()
            if s:
                cleaned.append(s)
        out[key] = cleaned

    for key in ("metrics_min", "state_paths"):
        if key not in raw:
            continue
        items = raw.get(key)
        if not isinstance(items, dict):
            raise ValueError(f"expect.{key} must be an object")
        out[key] = dict(items)

    if "report_paths" in raw:
        items = raw.get("report_paths")
        if not isinstance(items, dict):
            raise ValueError("expect.report_paths must be an object")
        cleaned: Dict[str, str] = {}
        for key, value in items.items():
            dotted = str(key).strip()
            if not dotted:
                continue
            if not isinstance(value, str):
                raise ValueError(f"expect.report_paths.{dotted} must be a string")
            cleaned[dotted] = value
        out["report_paths"] = cleaned

    if "report_path_contains" in raw:
        items = raw.get("report_path_contains")
        if not isinstance(items, dict):
            raise ValueError("expect.report_path_contains must be an object")
        cleaned_contains: Dict[str, str] = {}
        for key, value in items.items():
            dotted = str(key).strip()
            if not dotted:
                continue
            needle = str(value).strip()
            if not needle:
                raise ValueError(f"expect.report_path_contains.{dotted} must be a non-empty string")
            cleaned_contains[dotted] = needle
        out["report_path_contains"] = cleaned_contains

    if "report_json_paths" in raw:
        items = raw.get("report_json_paths")
        if not isinstance(items, dict):
            raise ValueError("expect.report_json_paths must be an object")
        cleaned_json_paths: Dict[str, Dict[str, Any]] = {}
        for key, value in items.items():
            dotted = str(key).strip()
            if not dotted:
                continue
            if not isinstance(value, dict):
                raise ValueError(f"expect.report_json_paths.{dotted} must be an object")
            cleaned_json_paths[dotted] = dict(value)
        out["report_json_paths"] = cleaned_json_paths

    for key in ("notes_contains", "notes_absent"):
        if key not in raw:
            continue
        items = raw.get(key)
        if not isinstance(items, list):
            raise ValueError(f"expect.{key} must be a list")
        cleaned = []
        for item in items:
            needle = str(item).strip()
            if not needle:
                raise ValueError(f"expect.{key} entries must be non-empty strings")
            cleaned.append(needle)
        out[key] = cleaned

    return out


def _resolve_case_binary_path(challenge_dir: str, binary: str) -> str:
    raw_dir = str(challenge_dir or "").strip()
    raw_bin = str(binary or "").strip()
    if not raw_dir or not raw_bin:
        return ""
    challenge_abs = raw_dir if os.path.isabs(raw_dir) else os.path.join(ROOT_DIR, raw_dir)
    if os.path.isabs(raw_bin):
        return os.path.abspath(raw_bin)
    return os.path.abspath(os.path.join(challenge_abs, raw_bin))


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _json_sha256(doc: Any) -> str:
    payload = json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def summarize_case_contract(case_exec: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "challenge_dir": str(case_exec.get("challenge_dir", "")).strip(),
        "binary": str(case_exec.get("binary", "")).strip(),
        "max_loops": int(case_exec.get("max_loops", 1) or 1),
        "allow_codex_missing": bool(case_exec.get("allow_codex_missing", False)),
        "start_no_codex": bool(case_exec.get("start_no_codex", True)),
        "start_session_args": list(case_exec.get("start_session_args") or []),
        "run_session_args": list(case_exec.get("run_session_args") or []),
        "env": dict(case_exec.get("env") or {}),
        "expect": dict(case_exec.get("expect") or {}),
        "ensure_binary_executable": bool(case_exec.get("ensure_binary_executable", False)),
        "clear_cached_artifacts": bool(case_exec.get("clear_cached_artifacts", False)),
        "start_timeout_seconds": case_exec.get("start_timeout_seconds"),
        "run_timeout_seconds": case_exec.get("run_timeout_seconds"),
    }


def clear_case_cached_artifacts(challenge_dir: str, binary: str, *, enabled: bool) -> Dict[str, Any]:
    path = _resolve_case_binary_path(challenge_dir, binary)
    info: Dict[str, Any] = {
        "enabled": bool(enabled),
        "path": os.path.relpath(path, ROOT_DIR) if path and path.startswith(ROOT_DIR) else path,
        "exists": bool(path and os.path.isfile(path)),
        "binary_sha256": "",
        "removed": [],
        "error": "",
    }
    if not enabled:
        return info
    if not path:
        info["error"] = "binary path unavailable"
        return info
    if not os.path.isfile(path):
        info["error"] = "binary not found"
        return info
    try:
        binary_sha = _file_sha256(path)
        info["binary_sha256"] = binary_sha
    except Exception as e:
        info["error"] = f"sha256 failed: {e}"
        return info

    cache_dir = os.path.join(ROOT_DIR, "artifacts", "cache")
    patterns = [
        os.path.join(cache_dir, f"{binary_sha}_*.json"),
        os.path.join(cache_dir, f"{binary_sha}_*.md"),
        os.path.join(cache_dir, f"{binary_sha}_*.txt"),
    ]
    removed: List[str] = []
    errors: List[str] = []
    seen = set()
    for pattern in patterns:
        for candidate in sorted(glob.glob(pattern)):
            if candidate in seen or (not os.path.isfile(candidate)):
                continue
            seen.add(candidate)
            try:
                os.remove(candidate)
                removed.append(os.path.relpath(candidate, ROOT_DIR))
            except Exception as e:
                errors.append(f"{os.path.relpath(candidate, ROOT_DIR)}: {e}")
    info["removed"] = removed
    if errors:
        info["error"] = "; ".join(errors)
    return info


def ensure_case_binary_executable(challenge_dir: str, binary: str, *, enabled: bool) -> Dict[str, Any]:
    path = _resolve_case_binary_path(challenge_dir, binary)
    info: Dict[str, Any] = {
        "enabled": bool(enabled),
        "path": os.path.relpath(path, ROOT_DIR) if path and path.startswith(ROOT_DIR) else path,
        "exists": bool(path and os.path.isfile(path)),
        "before_user_executable": False,
        "changed": False,
        "after_user_executable": False,
        "error": "",
    }
    if not path:
        info["error"] = "binary path unavailable"
        return info
    if not os.path.isfile(path):
        info["error"] = "binary not found"
        return info
    try:
        mode = os.stat(path).st_mode
    except Exception as e:
        info["error"] = str(e)
        return info

    before_exec = bool(mode & stat.S_IXUSR)
    info["before_user_executable"] = before_exec
    if enabled and (not before_exec):
        try:
            os.chmod(path, mode | stat.S_IXUSR)
            info["changed"] = True
            mode = os.stat(path).st_mode
        except Exception as e:
            info["error"] = str(e)
    info["after_user_executable"] = bool(mode & stat.S_IXUSR)
    return info


def run_cmd(
    cmd: List[str], *, env: Dict[str, str] | None = None, timeout_seconds: int | None = None
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(k): str(v) for k, v in env.items()})
    try:
        proc = subprocess.run(
            cmd,
            cwd=ROOT_DIR,
            env=merged_env,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout if isinstance(e.stdout, str) else ((e.stdout or b"").decode("utf-8", errors="replace") if e.stdout is not None else "")
        stderr = e.stderr if isinstance(e.stderr, str) else ((e.stderr or b"").decode("utf-8", errors="replace") if e.stderr is not None else "")
        proc = subprocess.CompletedProcess(cmd, 124, stdout=stdout, stderr=stderr)
        setattr(proc, "timed_out", True)
        setattr(proc, "timeout_seconds", timeout_seconds)
        return proc
    setattr(proc, "timed_out", False)
    setattr(proc, "timeout_seconds", timeout_seconds)
    return proc


def build_case_commands(
    case: Mapping[str, Any],
    *,
    case_id: str,
    session_id: str,
    allow_codex_missing_default: bool,
) -> Dict[str, Any]:
    challenge_dir = str(case.get("challenge_dir", "")).strip()
    binary = str(case.get("binary", "")).strip()
    max_loops = int(case.get("max_loops", 1) or 1)
    allow_missing = _case_bool(case, "allow_codex_missing", allow_codex_missing_default)
    start_no_codex = _case_bool(case, "start_no_codex", True)
    start_session_args = _case_str_list(case, "start_session_args")
    run_session_args = _case_str_list(case, "run_session_args")
    env = _case_env(case)
    expect = _case_expect(case)
    ensure_binary_executable = _case_bool(case, "ensure_binary_executable", False)
    clear_cached_artifacts = _case_bool(case, "clear_cached_artifacts", False)
    start_timeout_seconds = _case_timeout_seconds(case, "start_timeout_seconds")
    run_timeout_seconds = _case_timeout_seconds(case, "run_timeout_seconds")

    cmd_start = [
        "bash",
        os.path.join(ROOT_DIR, "scripts", "start_session.sh"),
        "--challenge-dir",
        challenge_dir,
        "--session-id",
        session_id,
    ]
    if start_no_codex:
        cmd_start.append("--no-codex")
    if binary:
        cmd_start.extend(["--binary", binary])
    if start_session_args:
        cmd_start.extend(start_session_args)

    cmd_run = [
        sys.executable,
        os.path.join(ROOT_DIR, "scripts", "run_session.py"),
        "--session-id",
        session_id,
        "--max-loops",
        str(max_loops),
    ]
    if allow_missing:
        cmd_run.append("--allow-codex-missing")
    if run_session_args:
        cmd_run.extend(run_session_args)

    return {
        "challenge_dir": challenge_dir,
        "binary": binary,
        "max_loops": max_loops,
        "allow_codex_missing": allow_missing,
        "start_no_codex": start_no_codex,
        "start_session_args": start_session_args,
        "run_session_args": run_session_args,
        "env": env,
        "expect": expect,
        "ensure_binary_executable": ensure_binary_executable,
        "clear_cached_artifacts": clear_cached_artifacts,
        "start_timeout_seconds": start_timeout_seconds,
        "run_timeout_seconds": run_timeout_seconds,
        "cmd_start": cmd_start,
        "cmd_run": cmd_run,
    }


def _metrics_from_case_result(item: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "runs_total": 0,
        "loops_total": 0,
        "codex_errors": 0,
        "stage_retries": 0,
        "recoverable_failures": 0,
        "capability_updates": 0,
        "objective_score_latest": 0,
        "exploit_success": 0,
    }
    run_output = item.get("run_output")
    if not isinstance(run_output, dict):
        return out
    metrics_rel = str(run_output.get("metrics", "")).strip()
    if not metrics_rel:
        return out
    metrics_abs = metrics_rel if os.path.isabs(metrics_rel) else os.path.join(ROOT_DIR, metrics_rel)
    m = load_json_or(metrics_abs, {})
    if not isinstance(m, dict):
        return out
    for k in out.keys():
        try:
            out[k] = int(m.get(k, out[k]) or 0)
        except Exception:
            pass
    return out


def _iter_path_tokens(dotted_path: str) -> List[Any]:
    tokens: List[Any] = []
    for raw_part in str(dotted_path or "").split("."):
        part = raw_part.strip()
        if not part:
            continue
        m = re.match(r"^([^\[]+)", part)
        if m:
            tokens.append(m.group(1))
        idx_parts = re.findall(r"\[(-?\d+)\]", part)
        if (not m) and (not idx_parts):
            tokens.append(part)
        for idx_text in idx_parts:
            try:
                tokens.append(int(idx_text))
            except Exception:
                tokens.append(idx_text)
    return tokens


def _get_path_value(doc: Mapping[str, Any], dotted_path: str) -> Any:
    cur: Any = doc
    for token in _iter_path_tokens(dotted_path):
        if isinstance(token, int):
            if not isinstance(cur, list):
                return None
            try:
                cur = cur[token]
            except Exception:
                return None
            continue
        key = str(token).strip()
        if not isinstance(cur, Mapping) or key not in cur:
            return None
        cur = cur.get(key)
    return cur


def _resolve_existing_path(raw_path: Any) -> str:
    path = str(raw_path or "").strip()
    if not path:
        return ""
    if not os.path.isabs(path):
        path = os.path.join(ROOT_DIR, path)
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return ""
    return path


def _expand_expect_placeholder(value: str, *, item: Mapping[str, Any]) -> str:
    text = str(value or "")
    session_id = str(item.get("session_id", "") or "").strip()
    if session_id:
        text = text.replace("{{SESSION_ID}}", session_id)
    return text


def _expand_expected_value(value: Any, *, item: Mapping[str, Any]) -> Any:
    if isinstance(value, str):
        return _expand_expect_placeholder(value, item=item)
    return value



def evaluate_case_expectations(item: Dict[str, Any], expect: Mapping[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    checks: Dict[str, Any] = {}

    run_rc = int(item.get("run_rc", 0) or 0)
    run_output = item.get("run_output") if isinstance(item.get("run_output"), dict) else {}
    metrics = item.get("metrics") if isinstance(item.get("metrics"), dict) else {}

    state_doc: Dict[str, Any] = {}
    state_rel = str(run_output.get("state", "")).strip()
    if state_rel:
        state_abs = state_rel if os.path.isabs(state_rel) else os.path.join(ROOT_DIR, state_rel)
        loaded = load_json_or(state_abs, {})
        if isinstance(loaded, dict):
            state_doc = loaded

    if "run_rc" in expect:
        expected = int(expect.get("run_rc", 0) or 0)
        actual = run_rc
        ok = actual == expected
        checks["run_rc"] = {"ok": ok, "actual": actual, "expected": expected}
        if not ok:
            errors.append(f"run_rc mismatch: actual={actual} expected={expected}")

    if "final_exit_code" in expect:
        expected = int(expect.get("final_exit_code", 0) or 0)
        actual = int(run_output.get("exit_code", 0) or 0)
        ok = actual == expected
        checks["final_exit_code"] = {"ok": ok, "actual": actual, "expected": expected}
        if not ok:
            errors.append(f"final_exit_code mismatch: actual={actual} expected={expected}")

    if "acceptance_passed" in expect:
        expected = bool(expect.get("acceptance_passed"))
        actual = bool(run_output.get("acceptance_passed", False))
        ok = actual == expected
        checks["acceptance_passed"] = {"ok": ok, "actual": actual, "expected": expected}
        if not ok:
            errors.append(f"acceptance_passed mismatch: actual={actual} expected={expected}")

    if "min_objective_score" in expect:
        expected = int(expect.get("min_objective_score", 0) or 0)
        actual = int(metrics.get("objective_score_latest", 0) or 0)
        ok = actual >= expected
        checks["min_objective_score"] = {"ok": ok, "actual": actual, "expected_min": expected}
        if not ok:
            errors.append(f"objective_score_latest too low: actual={actual} expected_min={expected}")

    stage_results = run_output.get("stage_results") if isinstance(run_output.get("stage_results"), list) else []

    executed_stage_sequence = [
        str(row.get("stage", "")).strip()
        for row in stage_results
        if isinstance(row, dict) and str(row.get("stage", "")).strip()
    ]
    success_stages = {
        str(row.get("stage", "")).strip()
        for row in stage_results
        if isinstance(row, dict) and bool(row.get("ok", False)) and str(row.get("stage", "")).strip()
    }

    required_success_stages = expect.get("required_success_stages", [])
    if isinstance(required_success_stages, list) and required_success_stages:
        missing = [stage for stage in required_success_stages if stage not in success_stages]
        ok = not missing
        checks["required_success_stages"] = {
            "ok": ok,
            "required": list(required_success_stages),
            "missing": missing,
        }
        if not ok:
            errors.append(f"required_success_stages missing successful runs: {', '.join(missing)}")

    expected_stage_sequence = expect.get("stage_sequence", [])
    if isinstance(expected_stage_sequence, list) and expected_stage_sequence:
        ok = executed_stage_sequence == list(expected_stage_sequence)
        checks["stage_sequence"] = {
            "ok": ok,
            "actual": executed_stage_sequence,
            "expected": list(expected_stage_sequence),
        }
        if not ok:
            errors.append(
                "stage_sequence mismatch: "
                f"actual={executed_stage_sequence!r} expected={list(expected_stage_sequence)!r}"
            )

    forbid_stage_cache_hits = expect.get("forbid_stage_cache_hits", [])
    if isinstance(forbid_stage_cache_hits, list) and forbid_stage_cache_hits:
        stage_cache_hits = sorted(
            {
                str(row.get("stage", "")).strip()
                for row in stage_results
                if isinstance(row, dict) and bool(row.get("stage_cache_hit", False)) and str(row.get("stage", "")).strip()
            }
        )
        offending = [stage for stage in forbid_stage_cache_hits if stage in stage_cache_hits]
        ok = not offending
        checks["forbid_stage_cache_hits"] = {
            "ok": ok,
            "forbidden": list(forbid_stage_cache_hits),
            "actual_cache_hit_stages": stage_cache_hits,
            "offending": offending,
        }
        if not ok:
            errors.append(f"forbidden stage cache hits present: {', '.join(offending)}")

    metrics_min = expect.get("metrics_min", {})
    if isinstance(metrics_min, dict):
        metric_checks: Dict[str, Any] = {}
        for key, value in metrics_min.items():
            try:
                expected = int(value)
            except Exception as e:
                raise ValueError(f"expect.metrics_min.{key} must be an integer") from e
            actual = int(metrics.get(str(key), 0) or 0)
            ok = actual >= expected
            metric_checks[str(key)] = {"ok": ok, "actual": actual, "expected_min": expected}
            if not ok:
                errors.append(f"metrics.{key} too low: actual={actual} expected_min={expected}")
        if metric_checks:
            checks["metrics_min"] = metric_checks

    state_paths = expect.get("state_paths", {})
    if isinstance(state_paths, dict):
        state_checks: Dict[str, Any] = {}
        for dotted_path, expected in state_paths.items():
            actual = _get_path_value(state_doc, str(dotted_path))
            ok = actual == expected
            state_checks[str(dotted_path)] = {"ok": ok, "actual": actual, "expected": expected}
            if not ok:
                errors.append(f"state_paths.{dotted_path} mismatch: actual={actual!r} expected={expected!r}")
        if state_checks:
            checks["state_paths"] = state_checks

    report_paths = expect.get("report_paths", {})
    if isinstance(report_paths, dict):
        report_checks: Dict[str, Any] = {}
        for dotted_path, kind in report_paths.items():
            path_value = _get_path_value(run_output, str(dotted_path))
            existing_abs = _resolve_existing_path(path_value)
            actual_kind = ""
            if existing_abs:
                if os.path.isdir(existing_abs):
                    actual_kind = "dir"
                elif os.path.isfile(existing_abs):
                    actual_kind = "file"
                else:
                    actual_kind = "exists"
            expected_kind = str(kind).strip().lower() or "exists"
            ok = bool(existing_abs) and (expected_kind in {"exists", actual_kind})
            report_checks[str(dotted_path)] = {
                "ok": ok,
                "actual": os.path.relpath(existing_abs, ROOT_DIR) if existing_abs.startswith(ROOT_DIR) else existing_abs,
                "actual_kind": actual_kind,
                "expected_kind": expected_kind,
                "raw": path_value,
            }
            if not ok:
                errors.append(
                    f"report_paths.{dotted_path} missing/invalid: actual={path_value!r} actual_kind={actual_kind or 'missing'} expected={expected_kind}"
                )
        if report_checks:
            checks["report_paths"] = report_checks

    report_path_contains = expect.get("report_path_contains", {})
    if isinstance(report_path_contains, dict):
        contains_checks: Dict[str, Any] = {}
        for dotted_path, needle in report_path_contains.items():
            path_value = _get_path_value(run_output, str(dotted_path))
            path_text = str(path_value or "").strip()
            expanded_needle = _expand_expect_placeholder(str(needle), item=item)
            ok = bool(path_text) and expanded_needle in path_text
            contains_checks[str(dotted_path)] = {
                "ok": ok,
                "actual": path_text,
                "expected_contains": expanded_needle,
                "raw_expected": needle,
            }
            if not ok:
                errors.append(
                    f"report_path_contains.{dotted_path} mismatch: actual={path_text!r} expected_contains={expanded_needle!r}"
                )
        if contains_checks:
            checks["report_path_contains"] = contains_checks

    report_json_paths = expect.get("report_json_paths", {})
    if isinstance(report_json_paths, dict):
        json_report_checks: Dict[str, Any] = {}
        for dotted_path, json_expect in report_json_paths.items():
            if not isinstance(json_expect, dict):
                raise ValueError(f"expect.report_json_paths.{dotted_path} must be an object")
            path_value = _get_path_value(run_output, str(dotted_path))
            existing_abs = _resolve_existing_path(path_value)
            entry: Dict[str, Any] = {
                "ok": False,
                "path": path_value,
                "resolved": os.path.relpath(existing_abs, ROOT_DIR) if existing_abs and existing_abs.startswith(ROOT_DIR) else existing_abs,
                "checks": {},
            }
            if not existing_abs or (not os.path.isfile(existing_abs)):
                errors.append(f"report_json_paths.{dotted_path} missing json file: actual={path_value!r}")
                json_report_checks[str(dotted_path)] = entry
                continue
            report_doc = load_json_or(existing_abs, None)
            if not isinstance(report_doc, dict):
                errors.append(f"report_json_paths.{dotted_path} invalid json object: actual={path_value!r}")
                json_report_checks[str(dotted_path)] = entry
                continue
            entry["ok"] = True
            nested_checks: Dict[str, Any] = {}
            for json_path, expected in json_expect.items():
                actual = _get_path_value(report_doc, str(json_path))
                expanded_expected = _expand_expected_value(expected, item=item)
                ok = actual == expanded_expected
                nested_checks[str(json_path)] = {
                    "ok": ok,
                    "actual": actual,
                    "expected": expanded_expected,
                    "raw_expected": expected,
                }
                if not ok:
                    entry["ok"] = False
                    errors.append(
                        f"report_json_paths.{dotted_path}.{json_path} mismatch: actual={actual!r} expected={expanded_expected!r}"
                    )
            entry["checks"] = nested_checks
            json_report_checks[str(dotted_path)] = entry
        if json_report_checks:
            checks["report_json_paths"] = json_report_checks

    notes = [str(x).strip() for x in (run_output.get("notes") or []) if str(x).strip()]

    notes_contains = expect.get("notes_contains", [])
    if isinstance(notes_contains, list) and notes_contains:
        contains_checks: List[Dict[str, Any]] = []
        for needle in notes_contains:
            expanded_needle = _expand_expect_placeholder(str(needle), item=item)
            matched_note = next((note for note in notes if expanded_needle in note), "")
            ok = bool(matched_note)
            contains_checks.append(
                {
                    "ok": ok,
                    "expected_contains": expanded_needle,
                    "raw_expected": needle,
                    "matched_note": matched_note,
                }
            )
            if not ok:
                errors.append(f"notes_contains missing substring: expected_contains={expanded_needle!r}")
        if contains_checks:
            checks["notes_contains"] = contains_checks

    notes_absent = expect.get("notes_absent", [])
    if isinstance(notes_absent, list) and notes_absent:
        absent_checks: List[Dict[str, Any]] = []
        for needle in notes_absent:
            expanded_needle = _expand_expect_placeholder(str(needle), item=item)
            matched_note = next((note for note in notes if expanded_needle in note), "")
            ok = not matched_note
            absent_checks.append(
                {
                    "ok": ok,
                    "expected_absent": expanded_needle,
                    "raw_expected": needle,
                    "matched_note": matched_note,
                }
            )
            if not ok:
                errors.append(f"notes_absent matched forbidden substring: expected_absent={expanded_needle!r}")
        if absent_checks:
            checks["notes_absent"] = absent_checks

    return {"ok": len(errors) == 0, "errors": errors, "checks": checks}


def compute_scoreboard(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    executed = [x for x in results if not x.get("skipped")]
    ok_cases = [x for x in executed if x.get("ok")]
    failed_cases = [x for x in executed if not x.get("ok")]
    metric_rows = [_metrics_from_case_result(x) for x in executed]
    metric_count = len(metric_rows) if metric_rows else 1

    def total(key: str) -> int:
        return sum(int(x.get(key, 0) or 0) for x in metric_rows)

    return {
        "cases_total": len(results),
        "cases_executed": len(executed),
        "cases_skipped": sum(1 for x in results if x.get("skipped")),
        "cases_ok": len(ok_cases),
        "cases_failed": len(failed_cases),
        "success_rate": (len(ok_cases) / len(executed)) if executed else 0.0,
        "codex_errors_total": total("codex_errors"),
        "stage_retries_total": total("stage_retries"),
        "recoverable_failures_total": total("recoverable_failures"),
        "capability_updates_total": total("capability_updates"),
        "exploit_success_total": total("exploit_success"),
        "objective_score_avg": (total("objective_score_latest") / metric_count) if metric_rows else 0.0,
    }


def summarize_case_for_baseline(item: Mapping[str, Any]) -> Dict[str, Any]:
    run_output = item.get("run_output") if isinstance(item.get("run_output"), dict) else {}
    stage_results = run_output.get("stage_results") if isinstance(run_output.get("stage_results"), list) else []
    stage_sequence = [
        str(row.get("stage", "")).strip()
        for row in stage_results
        if isinstance(row, dict) and str(row.get("stage", "")).strip()
    ]
    success_stages = sorted(
        {
            str(row.get("stage", "")).strip()
            for row in stage_results
            if isinstance(row, dict) and row.get("ok")
        }
    )
    summary: Dict[str, Any] = {
        "case_id": str(item.get("case_id", "")).strip(),
        "ok": bool(item.get("ok")),
        "run_rc": int(item.get("run_rc", 0) or 0),
    }
    case_contract = item.get("case_contract") if isinstance(item.get("case_contract"), dict) else {}
    if case_contract:
        summary["case_contract"] = case_contract
        summary["case_contract_hash"] = _json_sha256(case_contract)
    if "exit_code" in run_output:
        summary["final_exit_code"] = int(run_output.get("exit_code", 0) or 0)
    if "acceptance_passed" in run_output:
        summary["acceptance_passed"] = bool(run_output.get("acceptance_passed", False))
    if success_stages:
        summary["success_stages"] = success_stages
    if stage_sequence:
        summary["stage_sequence"] = stage_sequence
    return summary


def compare_with_baseline(
    *,
    current: Dict[str, Any],
    baseline: Dict[str, Any],
    max_success_drop: float,
    max_codex_error_increase: int,
    max_stage_retry_increase: int,
    current_results: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    base_score = baseline.get("scoreboard", baseline)
    if not isinstance(base_score, dict):
        return {"ok": False, "errors": ["baseline scoreboard invalid"]}

    errors: List[str] = []
    cur_success = float(current.get("success_rate", 0.0) or 0.0)
    base_success = float(base_score.get("success_rate", 0.0) or 0.0)
    if cur_success < (base_success - float(max_success_drop)):
        errors.append(
            f"success_rate dropped too much: current={cur_success:.4f} baseline={base_success:.4f} allowed_drop={max_success_drop:.4f}"
        )

    cur_codex = int(current.get("codex_errors_total", 0) or 0)
    base_codex = int(base_score.get("codex_errors_total", 0) or 0)
    if cur_codex > (base_codex + int(max_codex_error_increase)):
        errors.append(
            f"codex_errors_total increased too much: current={cur_codex} baseline={base_codex} allowed_inc={max_codex_error_increase}"
        )

    cur_retry = int(current.get("stage_retries_total", 0) or 0)
    base_retry = int(base_score.get("stage_retries_total", 0) or 0)
    if cur_retry > (base_retry + int(max_stage_retry_increase)):
        errors.append(
            f"stage_retries_total increased too much: current={cur_retry} baseline={base_retry} allowed_inc={max_stage_retry_increase}"
        )

    baseline_cases_raw = baseline.get("cases", [])
    baseline_cases = baseline_cases_raw if isinstance(baseline_cases_raw, list) else []
    current_case_map: Dict[str, Dict[str, Any]] = {}
    for item in current_results or []:
        if not isinstance(item, dict) or item.get("skipped"):
            continue
        case_id = str(item.get("case_id", "")).strip()
        if case_id:
            current_case_map[case_id] = item

    case_checks: Dict[str, Any] = {}
    for row in baseline_cases:
        if not isinstance(row, dict):
            continue
        case_id = str(row.get("case_id", "")).strip()
        if not case_id:
            continue
        expected_ok = bool(row.get("ok", False))
        expected_run_rc = int(row.get("run_rc", 0) or 0)
        expected_exit_code = row.get("final_exit_code")
        expected_acceptance = row.get("acceptance_passed")
        expected_success_stages = [
            str(x).strip() for x in (row.get("success_stages") or []) if str(x).strip()
        ] if isinstance(row.get("success_stages"), list) else []
        expected_stage_sequence = [
            str(x).strip() for x in (row.get("stage_sequence") or []) if str(x).strip()
        ] if isinstance(row.get("stage_sequence"), list) else []
        expected_case_contract_hash = str(row.get("case_contract_hash", "") or "").strip()
        current_row = current_case_map.get(case_id)
        if not current_row:
            case_checks[case_id] = {
                "ok": False,
                "error": "case missing from current run",
                "expected_ok": expected_ok,
                "expected_run_rc": expected_run_rc,
                "expected_final_exit_code": expected_exit_code,
                "expected_acceptance_passed": expected_acceptance,
                "expected_success_stages": expected_success_stages,
                "expected_stage_sequence": expected_stage_sequence,
                "expected_case_contract_hash": expected_case_contract_hash,
            }
            errors.append(f"baseline case missing from current run: {case_id}")
            continue
        actual_summary = summarize_case_for_baseline(current_row)
        actual_ok = bool(actual_summary.get("ok", False))
        actual_run_rc = int(actual_summary.get("run_rc", 0) or 0)
        actual_exit_code = actual_summary.get("final_exit_code")
        actual_acceptance = actual_summary.get("acceptance_passed")
        actual_success_stages = [
            str(x).strip() for x in (actual_summary.get("success_stages") or []) if str(x).strip()
        ]
        actual_stage_sequence = [
            str(x).strip() for x in (actual_summary.get("stage_sequence") or []) if str(x).strip()
        ]
        actual_case_contract_hash = str(actual_summary.get("case_contract_hash", "") or "").strip()
        row_ok = True
        row_errors: List[str] = []
        if expected_ok and (not actual_ok):
            row_ok = False
            row_errors.append(f"ok regressed: baseline=true current={actual_ok}")
        if actual_run_rc != expected_run_rc:
            row_ok = False
            row_errors.append(f"run_rc mismatch: baseline={expected_run_rc} current={actual_run_rc}")
        if expected_exit_code is not None and actual_exit_code != int(expected_exit_code):
            row_ok = False
            row_errors.append(
                f"final_exit_code mismatch: baseline={int(expected_exit_code)} current={actual_exit_code}"
            )
        if expected_acceptance is not None and actual_acceptance != bool(expected_acceptance):
            row_ok = False
            row_errors.append(
                f"acceptance_passed mismatch: baseline={bool(expected_acceptance)} current={actual_acceptance}"
            )
        if expected_success_stages:
            missing_stages = [stage for stage in expected_success_stages if stage not in actual_success_stages]
            if missing_stages:
                row_ok = False
                row_errors.append(
                    "success_stages regressed: missing=" + ",".join(missing_stages)
                )
        if expected_stage_sequence and actual_stage_sequence != expected_stage_sequence:
            row_ok = False
            row_errors.append(
                f"stage_sequence mismatch: baseline={expected_stage_sequence!r} current={actual_stage_sequence!r}"
            )
        if expected_case_contract_hash and actual_case_contract_hash != expected_case_contract_hash:
            row_ok = False
            row_errors.append(
                "case_contract_hash mismatch: "
                f"baseline={expected_case_contract_hash} current={actual_case_contract_hash or '<missing>'}"
            )
        case_checks[case_id] = {
            "ok": row_ok,
            "expected_ok": expected_ok,
            "actual_ok": actual_ok,
            "expected_run_rc": expected_run_rc,
            "actual_run_rc": actual_run_rc,
            "expected_final_exit_code": expected_exit_code,
            "actual_final_exit_code": actual_exit_code,
            "expected_acceptance_passed": expected_acceptance,
            "actual_acceptance_passed": actual_acceptance,
            "expected_success_stages": expected_success_stages,
            "actual_success_stages": actual_success_stages,
            "expected_stage_sequence": expected_stage_sequence,
            "actual_stage_sequence": actual_stage_sequence,
            "expected_case_contract_hash": expected_case_contract_hash,
            "actual_case_contract_hash": actual_case_contract_hash,
            "errors": row_errors,
        }
        if row_errors:
            errors.append(f"baseline case regressed: {case_id} ({'; '.join(row_errors)})")

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "baseline_scoreboard": base_score,
        "case_checks": case_checks,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay benchmark cases for run_session workflow")
    ap.add_argument("--cases-dir", default=DEFAULT_CASES_DIR)
    ap.add_argument("--only", default="", help="run only case_id contains this keyword")
    ap.add_argument("--allow-codex-missing", action="store_true")
    ap.add_argument("--baseline", default="")
    ap.add_argument("--gate", action="store_true", help="enable regression gate against baseline")
    ap.add_argument("--max-success-rate-drop", type=float, default=0.05)
    ap.add_argument("--max-codex-errors-increase", type=int, default=2)
    ap.add_argument("--max-stage-retries-increase", type=int, default=4)
    ap.add_argument("--write-baseline", default="", help="write current scoreboard as baseline json")
    ap.add_argument("--fail-on-case-error", action="store_true")
    args = ap.parse_args()

    case_files = sorted(glob.glob(os.path.join(args.cases_dir, "*.json")))
    if not case_files:
        print(f"[replay_benchmarks] no case files under: {args.cases_dir}", file=sys.stderr)
        return 2

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: List[Dict[str, Any]] = []

    for path in case_files:
        case_id = os.path.splitext(os.path.basename(path))[0]
        if args.only and args.only not in case_id:
            continue

        try:
            case = load_case(path)
        except Exception as e:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "error": f"invalid case json: {e}",
                }
            )
            continue

        if case.get("enabled", True) is False:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": True,
                    "skipped": True,
                    "reason": "enabled=false",
                }
            )
            continue

        session_id = f"bench_{case_id}_{ts}"
        try:
            case_exec = build_case_commands(
                case,
                case_id=case_id,
                session_id=session_id,
                allow_codex_missing_default=args.allow_codex_missing,
            )
        except Exception as e:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "session_id": session_id,
                    "error": f"invalid case config: {e}",
                }
            )
            continue

        if not str(case_exec.get("challenge_dir", "")).strip():
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "error": "challenge_dir is required",
                }
            )
            continue

        binary_preflight = ensure_case_binary_executable(
            str(case_exec.get("challenge_dir", "")).strip(),
            str(case_exec.get("binary", "")).strip(),
            enabled=bool(case_exec.get("ensure_binary_executable", False)),
        )
        cache_preflight = clear_case_cached_artifacts(
            str(case_exec.get("challenge_dir", "")).strip(),
            str(case_exec.get("binary", "")).strip(),
            enabled=bool(case_exec.get("clear_cached_artifacts", False)),
        )

        p_start = run_cmd(
            case_exec["cmd_start"],
            env=case_exec["env"],
            timeout_seconds=case_exec.get("start_timeout_seconds"),
        )
        if p_start.returncode != 0:
            results.append(
                {
                    "case_id": case_id,
                    "path": os.path.relpath(path, ROOT_DIR),
                    "ok": False,
                    "session_id": session_id,
                    "start_rc": p_start.returncode,
                    "start_stderr": p_start.stderr[-2000:],
                    "start_stdout": p_start.stdout[-2000:],
                    "start_timed_out": bool(getattr(p_start, "timed_out", False)),
                    "start_timeout_seconds": getattr(p_start, "timeout_seconds", None),
                    "start_cmd": case_exec["cmd_start"],
                    "env_keys": sorted(case_exec["env"].keys()),
                    "binary_preflight": binary_preflight,
                    "cache_preflight": cache_preflight,
                }
            )
            continue

        p_run = run_cmd(
            case_exec["cmd_run"],
            env=case_exec["env"],
            timeout_seconds=case_exec.get("run_timeout_seconds"),
        )
        item: Dict[str, Any] = {
            "case_id": case_id,
            "path": os.path.relpath(path, ROOT_DIR),
            "session_id": session_id,
            "case_contract": summarize_case_contract(case_exec),
            "ok": p_run.returncode == 0,
            "run_rc": p_run.returncode,
            "run_timed_out": bool(getattr(p_run, "timed_out", False)),
            "run_timeout_seconds": getattr(p_run, "timeout_seconds", None),
            "start_cmd": case_exec["cmd_start"],
            "run_cmd": case_exec["cmd_run"],
            "env_keys": sorted(case_exec["env"].keys()),
            "binary_preflight": binary_preflight,
            "cache_preflight": cache_preflight,
            "case_config": {
                "challenge_dir": case_exec["challenge_dir"],
                "binary": case_exec["binary"],
                "max_loops": case_exec["max_loops"],
                "allow_codex_missing": case_exec["allow_codex_missing"],
                "start_no_codex": case_exec["start_no_codex"],
                "start_session_args": case_exec["start_session_args"],
                "run_session_args": case_exec["run_session_args"],
                "expect": case_exec["expect"],
                "ensure_binary_executable": case_exec["ensure_binary_executable"],
                "clear_cached_artifacts": case_exec["clear_cached_artifacts"],
                "start_timeout_seconds": case_exec["start_timeout_seconds"],
                "run_timeout_seconds": case_exec["run_timeout_seconds"],
            },
        }

        if p_run.stdout.strip():
            try:
                item["run_output"] = json.loads(p_run.stdout)
            except Exception:
                item["run_stdout_tail"] = p_run.stdout[-2000:]
        if p_run.stderr.strip():
            item["run_stderr_tail"] = p_run.stderr[-2000:]

        item["metrics"] = _metrics_from_case_result(item)

        expect = case_exec.get("expect", {})
        if expect:
            expectation_result = evaluate_case_expectations(item, expect)
            item["expectation_result"] = expectation_result
            item["ok"] = bool(expectation_result.get("ok", False))
        results.append(item)

    scoreboard = compute_scoreboard(results)
    summary = {
        "generated_utc": utc_now(),
        "scoreboard": scoreboard,
        "results": results,
    }

    baseline_path = args.baseline.strip() or (args.write_baseline.strip() or DEFAULT_BASELINE)
    gate_result: Dict[str, Any] = {"enabled": bool(args.gate), "ok": True, "errors": []}
    if args.gate:
        baseline = load_json_or(baseline_path, {})
        if not isinstance(baseline, dict) or not baseline:
            gate_result = {
                "enabled": True,
                "ok": False,
                "errors": [f"baseline not found or invalid: {os.path.relpath(baseline_path, ROOT_DIR)}"],
            }
        else:
            cmp_res = compare_with_baseline(
                current=scoreboard,
                baseline=baseline,
                max_success_drop=float(args.max_success_rate_drop),
                max_codex_error_increase=int(args.max_codex_errors_increase),
                max_stage_retry_increase=int(args.max_stage_retries_increase),
                current_results=results,
            )
            gate_result = {
                "enabled": True,
                "ok": bool(cmp_res.get("ok", False)),
                "errors": list(cmp_res.get("errors", [])),
                "baseline_path": os.path.relpath(os.path.abspath(baseline_path), ROOT_DIR),
                "baseline_scoreboard": cmp_res.get("baseline_scoreboard", {}),
                "case_checks": cmp_res.get("case_checks", {}),
            }
    summary["gate"] = gate_result

    out_rel = f"artifacts/reports/benchmark_replay_{ts}.json"
    out_abs = os.path.join(ROOT_DIR, out_rel)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    baseline_write_target = args.write_baseline.strip()
    if baseline_write_target:
        target_abs = baseline_write_target if os.path.isabs(baseline_write_target) else os.path.join(ROOT_DIR, baseline_write_target)
        os.makedirs(os.path.dirname(target_abs), exist_ok=True)
        baseline_doc = {
            "generated_utc": utc_now(),
            "source_report": out_rel,
            "scoreboard": scoreboard,
            "cases": [
                summarize_case_for_baseline(x)
                for x in results
                if not x.get("skipped")
            ],
        }
        with open(target_abs, "w", encoding="utf-8") as f:
            json.dump(baseline_doc, f, ensure_ascii=False, indent=2)
        summary["baseline_written"] = os.path.relpath(os.path.abspath(target_abs), ROOT_DIR)

    print(json.dumps({"report": out_rel, "summary": summary}, ensure_ascii=False, indent=2))

    if args.gate and (not gate_result.get("ok", True)):
        return 3
    if args.fail_on_case_error and int(scoreboard.get("cases_failed", 0) or 0) > 0:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
