#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_STATE = os.path.join(ROOT_DIR, "state", "state.json")
DEFAULT_TEMPLATE = os.path.join(ROOT_DIR, "state", "state.template.jsonc")
DEFAULT_SCHEMA = os.path.join(ROOT_DIR, "state", "schema.json")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _repo_rel(path: str) -> str:
    return os.path.relpath(os.path.abspath(path), ROOT_DIR)


def _load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _load_jsonc(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r"^\s*//.*$", "", text, flags=re.MULTILINE)
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("template root is not object")
    return data


def _save_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def _type_ok_like(template_v: Any, cur_v: Any) -> bool:
    if isinstance(template_v, dict):
        return isinstance(cur_v, dict)
    if isinstance(template_v, list):
        return isinstance(cur_v, list)
    if isinstance(template_v, bool):
        return isinstance(cur_v, bool)
    if isinstance(template_v, int) and not isinstance(template_v, bool):
        return isinstance(cur_v, int) and not isinstance(cur_v, bool)
    if isinstance(template_v, float):
        return isinstance(cur_v, (int, float)) and not isinstance(cur_v, bool)
    if isinstance(template_v, str):
        return isinstance(cur_v, str)
    if template_v is None:
        return True
    return True


def _repair_node(cur: Any, tpl: Any, path: str, changes: List[Dict[str, Any]]) -> Any:
    if isinstance(tpl, dict):
        if not isinstance(cur, dict):
            changes.append({"path": path, "action": "replace_type", "expected": "object"})
            cur = {}
        for k, tv in tpl.items():
            p = f"{path}.{k}" if path else k
            if k not in cur:
                cur[k] = copy.deepcopy(tv)
                changes.append({"path": p, "action": "add_missing"})
            else:
                cur[k] = _repair_node(cur[k], tv, p, changes)
        return cur

    if isinstance(tpl, list):
        if not isinstance(cur, list):
            changes.append({"path": path, "action": "replace_type", "expected": "array"})
            return copy.deepcopy(tpl)
        return cur

    if not _type_ok_like(tpl, cur):
        expected = type(tpl).__name__ if tpl is not None else "any"
        changes.append({"path": path, "action": "replace_type", "expected": expected})
        return copy.deepcopy(tpl)
    return cur


def _validate_with_schema(schema_path: str, state: Dict[str, Any]) -> List[str]:
    if not os.path.exists(schema_path):
        return []
    try:
        from core.state_schema import load_json as load_schema_json, validate_state_data  # type: ignore
    except Exception:
        return []
    schema = load_schema_json(schema_path)
    if not isinstance(schema, dict):
        return ["schema root is not object"]
    return validate_state_data(schema, state)


def main() -> int:
    ap = argparse.ArgumentParser(description="Repair state/state.json structure from template")
    ap.add_argument("--state", default=DEFAULT_STATE)
    ap.add_argument("--template", default=DEFAULT_TEMPLATE)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--from-template", action="store_true", help="rebuild from template then merge challenge/session from old state")
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--no-backup", action="store_true")
    ap.add_argument("--keep-challenge", action="store_true")
    ap.add_argument("--keep-session", action="store_true")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    state_abs = os.path.abspath(args.state if os.path.isabs(args.state) else os.path.join(ROOT_DIR, args.state))
    tpl_abs = os.path.abspath(args.template if os.path.isabs(args.template) else os.path.join(ROOT_DIR, args.template))
    schema_abs = os.path.abspath(args.schema if os.path.isabs(args.schema) else os.path.join(ROOT_DIR, args.schema))

    if not os.path.exists(tpl_abs):
        print(json.dumps({"ok": False, "error": f"template not found: {tpl_abs}"}, ensure_ascii=False, indent=2))
        return 2

    raw_state: Any = {}
    state_parse_error = ""
    if os.path.exists(state_abs):
        try:
            with open(state_abs, "r", encoding="utf-8") as f:
                raw_state = json.load(f)
        except Exception as e:
            state_parse_error = str(e)
            raw_state = {}

    template = _load_jsonc(tpl_abs)
    current = raw_state if isinstance(raw_state, dict) else {}

    if args.from_template or (not isinstance(raw_state, dict)):
        repaired = copy.deepcopy(template)
        if args.keep_challenge and isinstance(current.get("challenge"), dict):
            repaired["challenge"] = copy.deepcopy(current["challenge"])
        if args.keep_session and isinstance(current.get("session"), dict):
            repaired["session"] = copy.deepcopy(current["session"])
    else:
        repaired = copy.deepcopy(current)

    changes: List[Dict[str, Any]] = []
    repaired = _repair_node(repaired, template, "", changes)

    schema_errors = _validate_with_schema(schema_abs, repaired)
    ok = len(schema_errors) == 0

    backup_rel = ""
    if (not args.check_only) and (not args.no_backup) and os.path.exists(state_abs):
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        bak = f"{state_abs}.bak.{ts}"
        shutil.copy2(state_abs, bak)
        backup_rel = _repo_rel(bak)

    if not args.check_only:
        _save_json(state_abs, repaired)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if args.report:
        report_abs = os.path.abspath(args.report if os.path.isabs(args.report) else os.path.join(ROOT_DIR, args.report))
    else:
        report_abs = os.path.join(ROOT_DIR, "artifacts", "reports", f"state_repair_{ts}.json")
    os.makedirs(os.path.dirname(report_abs), exist_ok=True)

    report = {
        "generated_utc": utc_now(),
        "ok": ok,
        "check_only": bool(args.check_only),
        "state_path": _repo_rel(state_abs),
        "template_path": _repo_rel(tpl_abs),
        "schema_path": _repo_rel(schema_abs) if os.path.exists(schema_abs) else args.schema,
        "state_parse_error": state_parse_error,
        "changes_count": len(changes),
        "changes": changes,
        "schema_errors": schema_errors,
        "backup": backup_rel,
    }
    with open(report_abs, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    out = {
        "ok": ok,
        "report": _repo_rel(report_abs),
        "changes_count": len(changes),
        "schema_errors": len(schema_errors),
        "backup": backup_rel,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

    if not ok:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
