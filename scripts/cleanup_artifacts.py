#!/usr/bin/env python3
from __future__ import annotations

import argparse
import glob
import json
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Set, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_ARTIFACTS = os.path.join(ROOT_DIR, "artifacts")
DEFAULT_BUDGET = os.path.join(ROOT_DIR, "policy", "budget.yaml")
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _try_load_yaml(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data if isinstance(data, dict) else {}


def _repo_rel(path: str) -> str:
    return os.path.relpath(os.path.abspath(path), ROOT_DIR)


def _inside_repo(path: str) -> bool:
    try:
        return os.path.commonpath([ROOT_DIR, os.path.abspath(path)]) == ROOT_DIR
    except Exception:
        return False


def _norm_rel_path(path: str) -> str:
    return _repo_rel(path).replace("\\", "/")


def _safe_load_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _collect_session_keep_paths(
    *,
    state_path: str,
    session_id: str,
) -> Set[str]:
    keep: Set[str] = set()
    state = _safe_load_json(state_path)
    latest = state.get("artifacts_index", {}).get("latest", {}).get("paths", {})
    if isinstance(latest, dict):
        for v in latest.values():
            p = str(v or "").strip().replace("\\", "/")
            if (not p) or (not p.startswith("artifacts/")) or (session_id not in p):
                continue
            keep.add(p)

    sess = state.get("session", {}) if isinstance(state.get("session", {}), dict) else {}
    exp = sess.get("exp", {}) if isinstance(sess.get("exp", {}), dict) else {}
    remote = sess.get("remote", {}) if isinstance(sess.get("remote", {}), dict) else {}
    for d in [exp, remote]:
        for key in ["plan_report", "verify_report", "last_preflight_report", "last_remote_report"]:
            p = str(d.get(key, "")).strip().replace("\\", "/")
            if (not p) or (not p.startswith("artifacts/")) or (session_id not in p):
                continue
            keep.add(p)

    meta_path = os.path.join(ROOT_DIR, "sessions", session_id, "meta.json")
    meta = _safe_load_json(meta_path)
    latest_art = meta.get("latest_artifacts", {}) if isinstance(meta.get("latest_artifacts", {}), dict) else {}
    for v in latest_art.values():
        p = str(v or "").strip().replace("\\", "/")
        if (not p) or (not p.startswith("artifacts/")) or (session_id not in p):
            continue
        keep.add(p)
    return keep


def _collect_prune_failed_candidates(art_root: str, session_id: str) -> List[str]:
    pattern = os.path.join(art_root, "**", f"*{session_id}*")
    out: List[str] = []
    for p in glob.glob(pattern, recursive=True):
        ap = os.path.abspath(p)
        if not _inside_repo(ap):
            continue
        if ap == os.path.abspath(art_root):
            continue
        out.append(ap)
    dedup = sorted(set(out), key=lambda x: (len(x), x), reverse=True)
    return dedup


def _prune_failed_session_artifacts(
    *,
    art_root: str,
    session_id: str,
    keep_paths: Set[str],
    dry_run: bool,
) -> Tuple[int, List[str]]:
    victims = _collect_prune_failed_candidates(art_root, session_id)
    removed: List[str] = []
    for p in victims:
        rel = _norm_rel_path(p)
        if rel in keep_paths:
            continue
        if os.path.isdir(p):
            prefix = rel.rstrip("/") + "/"
            if any(k.startswith(prefix) for k in keep_paths):
                continue
        _delete_path(p, dry_run=dry_run)
        removed.append(rel)
    return len(removed), removed


def _list_children(path: str) -> List[str]:
    if not os.path.isdir(path):
        return []
    out: List[str] = []
    for name in os.listdir(path):
        if name in {".", ".."}:
            continue
        out.append(os.path.join(path, name))
    out.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return out


def _delete_path(path: str, dry_run: bool) -> None:
    if dry_run:
        return
    if os.path.isdir(path) and (not os.path.islink(path)):
        shutil.rmtree(path, ignore_errors=True)
    else:
        try:
            os.remove(path)
        except FileNotFoundError:
            pass


def _prune_keep_recent(path: str, keep: int, dry_run: bool) -> Tuple[int, List[str]]:
    children = _list_children(path)
    if keep < 0:
        keep = 0
    victims = children[keep:]
    removed: List[str] = []
    for p in victims:
        _delete_path(p, dry_run=dry_run)
        removed.append(_repo_rel(p))
    return len(victims), removed


def _remove_empty_dirs(root: str, dry_run: bool) -> int:
    removed = 0
    for cur, dirs, files in os.walk(root, topdown=False):
        if files:
            continue
        if dirs:
            continue
        if os.path.abspath(cur) == os.path.abspath(root):
            continue
        if dry_run:
            removed += 1
            continue
        try:
            os.rmdir(cur)
            removed += 1
        except OSError:
            continue
    return removed


def main() -> int:
    ap = argparse.ArgumentParser(description="Cleanup artifacts with keep-last policy")
    ap.add_argument("--artifacts-dir", default=DEFAULT_ARTIFACTS)
    ap.add_argument("--budget", default=DEFAULT_BUDGET)
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--keep-reports", type=int, default=-1)
    ap.add_argument("--keep-logs", type=int, default=-1)
    ap.add_argument("--keep-gdb", type=int, default=-1)
    ap.add_argument("--keep-ida", type=int, default=-1)
    ap.add_argument("--keep-inputs", type=int, default=-1)
    ap.add_argument("--keep-cores", type=int, default=-1)
    ap.add_argument("--purge-tmp", action="store_true")
    ap.add_argument("--session-id", default="", help="session id for targeted pruning")
    ap.add_argument(
        "--prune-failed",
        action="store_true",
        help="remove stale artifacts matching --session-id but not referenced by state/meta latest index",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--report", default="")
    ap.add_argument("--max-paths", type=int, default=200)
    args = ap.parse_args()

    art_root = os.path.abspath(args.artifacts_dir if os.path.isabs(args.artifacts_dir) else os.path.join(ROOT_DIR, args.artifacts_dir))
    if not _inside_repo(art_root):
        print(json.dumps({"ok": False, "error": f"artifacts dir outside repo: {art_root}"}, ensure_ascii=False, indent=2))
        return 2
    if bool(args.prune_failed) and (not str(args.session_id).strip()):
        print(json.dumps({"ok": False, "error": "--prune-failed requires --session-id"}, ensure_ascii=False, indent=2))
        return 2

    budget = _try_load_yaml(args.budget)
    keep_default = 20
    if isinstance(budget.get("artifacts"), dict):
        try:
            keep_default = int(budget["artifacts"].get("keep_last_n_runs", keep_default) or keep_default)
        except Exception:
            keep_default = 20

    keep_cfg = {
        "reports": keep_default if args.keep_reports < 0 else args.keep_reports,
        "logs": keep_default if args.keep_logs < 0 else args.keep_logs,
        "gdb": keep_default if args.keep_gdb < 0 else args.keep_gdb,
        "ida": keep_default if args.keep_ida < 0 else args.keep_ida,
        "inputs": keep_default if args.keep_inputs < 0 else args.keep_inputs,
        "cores": keep_default if args.keep_cores < 0 else args.keep_cores,
        "tmp": 0,
    }

    plan: List[Tuple[str, int]] = []
    for key in ["reports", "logs", "gdb", "ida", "inputs", "cores"]:
        plan.append((key, int(keep_cfg[key])))
    if args.purge_tmp:
        plan.append(("tmp", 0))

    stats: Dict[str, Any] = {
        "generated_utc": utc_now(),
        "artifacts_dir": _repo_rel(art_root),
        "dry_run": bool(args.dry_run),
        "keep": keep_cfg,
        "purge_tmp": bool(args.purge_tmp),
        "pruned": {},
        "removed_paths": [],
        "removed_count": 0,
        "removed_failed_count": 0,
        "empty_dirs_removed": 0,
    }

    removed_paths: List[str] = []
    for key, keep in plan:
        cur = os.path.join(art_root, key)
        removed_count, removed = _prune_keep_recent(cur, keep, dry_run=args.dry_run)
        stats["pruned"][key] = {"keep": keep, "removed": removed_count}
        stats["removed_count"] += removed_count
        if len(removed_paths) < max(0, int(args.max_paths)):
            left = max(0, int(args.max_paths)) - len(removed_paths)
            removed_paths.extend(removed[:left])

    if bool(args.prune_failed):
        sid = str(args.session_id).strip()
        keep_paths = _collect_session_keep_paths(state_path=args.state, session_id=sid)
        removed_failed_count, removed_failed = _prune_failed_session_artifacts(
            art_root=art_root,
            session_id=sid,
            keep_paths=keep_paths,
            dry_run=args.dry_run,
        )
        stats["pruned_failed"] = {
            "session_id": sid,
            "state": _repo_rel(args.state if os.path.isabs(args.state) else os.path.join(ROOT_DIR, args.state)),
            "keep_count": len(keep_paths),
            "removed": removed_failed_count,
        }
        stats["removed_count"] += removed_failed_count
        stats["removed_failed_count"] = removed_failed_count
        if len(removed_paths) < max(0, int(args.max_paths)):
            left = max(0, int(args.max_paths)) - len(removed_paths)
            removed_paths.extend(removed_failed[:left])

    stats["empty_dirs_removed"] = _remove_empty_dirs(art_root, dry_run=args.dry_run)
    stats["removed_paths"] = removed_paths
    stats["ok"] = True

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.report:
        report_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        report_abs = os.path.join(art_root, "reports", f"cleanup_{ts}.json")
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)

    out = {
        "ok": True,
        "report": _repo_rel(report_abs),
        "removed_count": stats["removed_count"],
        "removed_failed_count": stats.get("removed_failed_count", 0),
        "empty_dirs_removed": stats["empty_dirs_removed"],
        "dry_run": bool(args.dry_run),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
